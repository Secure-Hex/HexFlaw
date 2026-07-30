"""Tests del scoping por target en M4 (acota el análisis a la funcionalidad)."""

from __future__ import annotations

from pathlib import Path

from hexflaw.core.models import (
    CodeChunk,
    CodeGraph,
    IngestionResult,
    TargetDefinition,
)
from hexflaw.modules import m1_ingestion, m2_target, m3_graph
from hexflaw.modules.m4_static import _prefilter, _scope_filter, _semantic_rescue
from hexflaw.services.embedding import LocalCPUEmbedding
from hexflaw.services.embedding.base import EmbeddingService
from hexflaw.services.language_service import LanguageService


def _chunk(i: int, code: str) -> CodeChunk:
    return CodeChunk(
        id=f"c{i}",
        file=f"f{i}.go",
        language="go",
        name=f"fn{i}",
        code=code,
        line_start=1,
        line_end=2,
        hash=f"h{i}",
    )


def test_scope_passthrough_when_under_limit() -> None:
    emb = LocalCPUEmbedding(dim=64)
    emb._model = None
    chunks = [_chunk(0, "a"), _chunk(1, "b")]
    assert _scope_filter(chunks, "anything", emb, max_chunks=10) == chunks


def test_path_boost_prioritizes_but_keeps_system_picks() -> None:
    emb = LocalCPUEmbedding(dim=128)
    emb._model = None
    # Chunks irrelevantes al target pero en el path apuntado.
    in_path = [
        CodeChunk(id=f"p{i}", file="modules/git/grep.go", language="go",
                  name=f"g{i}", code="func g(){ unrelated arithmetic }",
                  line_start=1, line_end=2, hash=f"p{i}")
        for i in range(2)
    ]
    # Chunk muy relevante al target pero fuera del path.
    relevant_out = CodeChunk(
        id="r", file="web_src/js/search.ts", language="typescript", name="search",
        code="git grep code search keyword user controlled query",
        line_start=1, line_end=2, hash="r",
    )
    chunks = in_path + [relevant_out]

    kept = _scope_filter(
        chunks, "git grep code search keyword", emb, max_chunks=3,
        boost_paths=["modules/git"],
    )
    # Caben los 3: los del path (boost) + el relevante del sistema (no se pierde).
    assert {c.id for c in kept} == {"p0", "p1", "r"}
    # Con capacidad reducida, el path tiene prioridad sobre el resto.
    kept2 = _scope_filter(
        chunks, "git grep code search keyword", emb, max_chunks=2,
        boost_paths=["modules/git"],
    )
    assert all("modules/git" in c.file for c in kept2)


def test_scope_keeps_most_similar_to_target() -> None:
    emb = LocalCPUEmbedding(dim=128)
    emb._model = None  # fallback determinístico por hashing de tokens
    # Mezcla de chunks: unos sobre "git grep search", otros irrelevantes.
    relevant = [_chunk(i, "func gitGrep(keyword) { runGitGrep search keyword }") for i in range(3)]
    noise = [_chunk(100 + i, "func addNumbers(a, b) { return a plus b }") for i in range(5)]
    chunks = noise + relevant

    kept = _scope_filter(chunks, "git grep code search keyword", emb, max_chunks=3)
    assert len(kept) == 3
    # Los 3 más similares deben ser los de git grep, no el ruido aritmético.
    assert all("gitGrep" in c.code for c in kept)


# --------------------------------------------------------------------------- #
# Rescate por grafo en el prefiltro (capa 1)
# --------------------------------------------------------------------------- #
def _wrapper_project(tmp_path: Path) -> tuple[IngestionResult, TargetDefinition, CodeGraph, LanguageService]:
    """Proyecto donde el sink está envuelto en un helper propio.

    Es el patrón que más falsos negativos produce: la función que recibe el input
    del usuario —donde vive el bug— no menciona ninguna keyword conocida.
    """
    (tmp_path / "utils.py").write_text(
        "import subprocess\n\ndef run_cmd(c):\n    subprocess.run(c, shell=True)\n",
        encoding="utf-8",
    )
    (tmp_path / "api.py").write_text(
        'from utils import run_cmd\n\n'
        'def handler(user_input):\n    """Punto de entrada HTTP."""\n    run_cmd(user_input)\n',
        encoding="utf-8",
    )
    langs = LanguageService()
    ingestion = m1_ingestion.ingest(tmp_path, "p", langs)
    target = m2_target.define_target_directed("command execution", ingestion, langs)
    return ingestion, target, m3_graph.build_graph(ingestion, langs), langs


def test_prefilter_drops_the_caller_without_the_graph(tmp_path: Path) -> None:
    """Sin grafo, el chunk donde vive el bug no llega nunca al LLM."""
    ingestion, target, _, langs = _wrapper_project(tmp_path)

    kept = {c.name for c in _prefilter(ingestion, target, langs)}

    assert "run_cmd" in kept, "el helper sí tiene la keyword"
    assert "handler" not in kept, "y el caller se pierde: es el falso negativo"


def test_prefilter_rescues_chunks_that_reach_a_sink(tmp_path: Path) -> None:
    """Con el grafo, el caller se rescata aunque no tenga ninguna keyword."""
    ingestion, target, graph, langs = _wrapper_project(tmp_path)

    kept = {c.name for c in _prefilter(ingestion, target, langs, graph, 2)}

    assert {"handler", "run_cmd"} <= kept


def test_sink_rescue_can_be_disabled(tmp_path: Path) -> None:
    """``sink_rescue_hops=0`` vuelve al comportamiento anterior."""
    ingestion, target, graph, langs = _wrapper_project(tmp_path)

    kept = {c.name for c in _prefilter(ingestion, target, langs, graph, 0)}

    assert "handler" not in kept


def test_sink_rescue_respects_the_hop_budget(tmp_path: Path) -> None:
    """Un caller a 2 saltos entra con hops=2 y queda afuera con hops=1."""
    (tmp_path / "utils.py").write_text(
        "import subprocess\n\ndef run_cmd(c):\n    subprocess.run(c, shell=True)\n",
        encoding="utf-8",
    )
    (tmp_path / "mid.py").write_text(
        "from utils import run_cmd\n\ndef middle(v):\n    run_cmd(v)\n", encoding="utf-8"
    )
    (tmp_path / "api.py").write_text(
        'from mid import middle\n\ndef handler(user_input):\n    """HTTP."""\n    middle(user_input)\n',
        encoding="utf-8",
    )
    langs = LanguageService()
    ingestion = m1_ingestion.ingest(tmp_path, "p", langs)
    target = m2_target.define_target_directed("command execution", ingestion, langs)
    graph = m3_graph.build_graph(ingestion, langs)

    near = {c.name for c in _prefilter(ingestion, target, langs, graph, 1)}
    far = {c.name for c in _prefilter(ingestion, target, langs, graph, 2)}

    assert "middle" in near and "handler" not in near
    assert "handler" in far


def test_sink_rescue_is_bounded_and_does_not_keep_everything(tmp_path: Path) -> None:
    """El rescate agrega solo lo que alcanza un sink, no abre el filtro entero.

    Es la propiedad que hace que esto siga siendo un filtro: código inerte que no
    llama a nada peligroso tiene que seguir afuera, o el ahorro de tokens se pierde.
    """
    (tmp_path / "utils.py").write_text(
        "import subprocess\n\ndef run_cmd(c):\n    subprocess.run(c, shell=True)\n",
        encoding="utf-8",
    )
    (tmp_path / "api.py").write_text(
        "from utils import run_cmd\n\ndef handler(u):\n    run_cmd(u)\n", encoding="utf-8"
    )
    (tmp_path / "inert.py").write_text(
        "def add(a, b):\n    return a + b\n\n\ndef greet(name):\n    return f'hola {name}'\n",
        encoding="utf-8",
    )
    langs = LanguageService()
    ingestion = m1_ingestion.ingest(tmp_path, "p", langs)
    target = m2_target.define_target_directed("command execution", ingestion, langs)
    graph = m3_graph.build_graph(ingestion, langs)

    kept = {c.name for c in _prefilter(ingestion, target, langs, graph, 5)}

    assert "handler" in kept, "el caller del sink entra"
    assert "add" not in kept and "greet" not in kept, "el código inerte sigue afuera"


# --------------------------------------------------------------------------- #
# Rescate semántico (última red del prefiltro)
# --------------------------------------------------------------------------- #
class _ScriptedEmbedding(EmbeddingService):
    """Embedding determinístico: vector fijo por substring presente en el texto.

    Evita depender de descargar un modelo real en los tests; lo que se verifica es
    la lógica de umbral, orden y tope, no la calidad del modelo.
    """

    def __init__(self, table: dict[str, list[float]]) -> None:
        self._table = table

    def embed(self, code: str) -> list[float]:
        for key, vector in self._table.items():
            if key in code:
                return vector
        return [0.0, 0.0, 1.0]

    def embed_batch(self, chunks: list[str]) -> list[list[float]]:
        return [self.embed(c) for c in chunks]


def _rescue_setup() -> tuple[list[CodeChunk], TargetDefinition, _ScriptedEmbedding]:
    peligroso = _chunk(1, "def traer(h, p):\n    PELIGRO conectar y enviar\n")
    inerte = _chunk(2, "def sumar(a, b):\n    INERTE return a + b\n")
    embedding = _ScriptedEmbedding(
        {
            "subprocess.run": [1.0, 0.0, 0.0],  # la consulta de command_injection
            "PELIGRO": [0.95, 0.31, 0.0],  # ~0.95 de similitud con la consulta
            "INERTE": [0.0, 1.0, 0.0],  # ortogonal
        }
    )
    target = TargetDefinition(target_confirmed="t", vuln_profile=["command_injection"])
    return [peligroso, inerte], target, embedding


def test_semantic_rescue_recovers_a_lookalike_chunk() -> None:
    """Rescata lo que se PARECE a un sink aunque no tenga ninguna keyword."""
    chunks, target, embedding = _rescue_setup()

    rescued = _semantic_rescue(chunks, target, embedding, threshold=0.22, max_rescued=25)

    assert [c.name for c in rescued] == ["fn1"]


def test_semantic_rescue_leaves_inert_code_out() -> None:
    """El código ortogonal a toda consulta no entra: si no, el filtro deja de filtrar."""
    chunks, target, embedding = _rescue_setup()

    rescued = _semantic_rescue(chunks, target, embedding, threshold=0.22, max_rescued=25)

    assert all(c.name != "fn2" for c in rescued)


def test_semantic_rescue_respects_the_hard_cap() -> None:
    """El tope acota el costo: se ordenan por score y solo entran los mejores."""
    chunks, target, embedding = _rescue_setup()
    muchos = chunks + [_chunk(i, "PELIGRO otra cosa") for i in range(3, 12)]

    rescued = _semantic_rescue(muchos, target, embedding, threshold=0.22, max_rescued=3)

    assert len(rescued) == 3


def test_semantic_rescue_is_disabled_without_embeddings() -> None:
    """Sin backend de embeddings no se rescata nada, y no explota."""
    chunks, target, _ = _rescue_setup()

    assert _semantic_rescue(chunks, target, None, threshold=0.22, max_rescued=25) == []


def test_semantic_rescue_needs_a_known_vuln_class() -> None:
    """Un perfil sin clases mapeadas no produce consulta: no se inventa uno."""
    chunks, _, embedding = _rescue_setup()
    target = TargetDefinition(target_confirmed="t", vuln_profile=["clase_inventada"])

    assert _semantic_rescue(chunks, target, embedding, threshold=0.22, max_rescued=25) == []


def test_rescue_budget_scales_with_the_accepted_set() -> None:
    """Un tope absoluto queda mal en los dos extremos.

    Medido contra el OWASP Benchmark (13.691 chunks): un tope fijo de 25 aportaba
    +0,3 puntos de recall — el rescate funcionaba pero el tope lo anulaba.
    """
    from hexflaw.modules.m4_static import _rescue_budget

    assert _rescue_budget(50, floor=25, fraction=0.10) == 25  # proyecto chico: piso
    assert _rescue_budget(6610, floor=25, fraction=0.10) == 661  # grande: proporción


def test_rescue_budget_never_goes_below_the_floor() -> None:
    """En un proyecto muy chico la capa 3 tiene que seguir existiendo."""
    from hexflaw.modules.m4_static import _rescue_budget

    assert _rescue_budget(1, floor=25, fraction=0.10) == 25
    assert _rescue_budget(0, floor=25, fraction=0.10) == 25

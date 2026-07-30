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
from hexflaw.modules.m4_static import _prefilter, _scope_filter
from hexflaw.services.embedding import LocalCPUEmbedding
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

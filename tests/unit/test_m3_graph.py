"""Tests de M3 — Code Graph Builder y de la integridad del GraphService."""

from __future__ import annotations

from pathlib import Path

import pytest

from hexflaw.core.models import (
    GRAPH_SCHEMA_VERSION,
    ChunkKind,
    CodeGraph,
    EdgeType,
    GraphEdge,
    IngestionResult,
    NodeType,
)
from hexflaw.modules import chunking, m1_ingestion, m3_graph
from hexflaw.services.graph_service import GraphService
from hexflaw.services.language_service import LanguageService

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _graph() -> tuple[IngestionResult, CodeGraph]:
    langs = LanguageService()
    ingestion = m1_ingestion.ingest(FIXTURES / "sample_c", "proj-1", langs)
    return ingestion, m3_graph.build_graph(ingestion, langs)


def _py_graph(
    root: Path | None = None,
) -> tuple[IngestionResult, CodeGraph, set[tuple[str, str]]]:
    """Grafo del fixture Python AST (o de ``root``), con índices por conveniencia."""
    langs = LanguageService()
    ingestion = m1_ingestion.ingest(root or FIXTURES / "ast_python", "proj-py", langs)
    graph = m3_graph.build_graph(ingestion, langs)
    by_id = {n.id: n for n in graph.nodes}
    edges = {
        (f"{by_id[e.from_].file}::{by_id[e.from_].name}", f"{by_id[e.to].file}::{by_id[e.to].name}")
        for e in graph.edges
    }
    return ingestion, graph, edges


def test_graph_nodes_entry_and_sink() -> None:
    _, graph = _graph()
    by_name = {n.name: n for n in graph.nodes}

    assert "main" in by_name and "handle_ping_input" in by_name
    # main contiene 'int main'/'argv' → entry point.
    assert by_name["main"].is_entry_point
    # handle_ping_input contiene system()/sprintf → sink.
    assert by_name["handle_ping_input"].is_sink
    assert any(s.sink_type == "command_execution" for s in graph.sinks)


def test_graph_call_edge_main_to_handler() -> None:
    _, graph = _graph()
    by_name = {n.name: n.id for n in graph.nodes}
    edge_pairs = {(e.from_, e.to) for e in graph.edges}
    assert (by_name["main"], by_name["handle_ping_input"]) in edge_pairs


# --------------------------------------------------------------------------- #
# Ruta Python por AST
# --------------------------------------------------------------------------- #
def test_python_ast_edge_between_module_functions() -> None:
    """handler() → run_command() del mismo archivo."""
    _, _, edges = _py_graph()
    assert ("app.py::handler", "app.py::run_command") in edges


def test_python_ast_resolves_import_alias_as_sink() -> None:
    """'import subprocess as sp' + 'sp.run(...)' → sink, aunque el texto diga 'sp.run'."""
    _, graph, _ = _py_graph()
    run_command = next(n for n in graph.nodes if n.name == "run_command" and n.file == "app.py")

    assert run_command.is_sink
    functions = {s.function for s in graph.sinks if s.node_id == run_command.id}
    assert "subprocess" in functions
    # El substring crudo no lo habría visto: el chunk nunca dice "subprocess".
    assert "subprocess" not in run_command.signature


def test_python_ast_resolves_from_import_alias_as_sink() -> None:
    """'from os import system as syscmd' + 'syscmd(...)' → sink os.system."""
    _, graph, _ = _py_graph()
    run_command = next(n for n in graph.nodes if n.name == "run_command" and n.file == "app.py")

    functions = {s.function for s in graph.sinks if s.node_id == run_command.id}
    assert "os.system" in functions


def test_python_ast_method_to_method_edge() -> None:
    """Controller.handle() → self.execute() genera arista método → método."""
    _, graph, edges = _py_graph()
    handle = next(n for n in graph.nodes if n.name == "handle")
    execute = next(n for n in graph.nodes if n.name == "execute")

    assert handle.type == NodeType.METHOD and execute.type == NodeType.METHOD
    assert ("app.py::handle", "app.py::execute") in edges


def test_python_ast_qualified_cross_file_call() -> None:
    """'from pkg import helpers' + 'helpers.write(...)' liga al archivo correcto."""
    _, _, edges = _py_graph()
    assert ("app.py::run_command", "pkg/helpers.py::write") in edges


def test_python_ast_does_not_mix_homonyms_across_files() -> None:
    """Dos run_command en archivos distintos: cada llamada queda en su archivo."""
    _, _, edges = _py_graph()

    assert ("other.py::caller", "other.py::run_command") in edges
    # Sin resolución clara, NO se liga al homónimo del otro archivo.
    assert ("other.py::caller", "app.py::run_command") not in edges
    assert ("app.py::handler", "other.py::run_command") not in edges


def test_python_ast_unqualified_call_is_not_bound_to_method() -> None:
    """inert() llama a execute() sin self: no debe ligarse a Controller.execute."""
    _, _, edges = _py_graph()
    assert ("app.py::inert", "app.py::execute") not in edges


def test_python_ast_node_types_and_qualnames() -> None:
    """El grafo distingue función, método, clase y módulo."""
    ingestion, graph, _ = _py_graph()
    by_name = {(n.file, n.name): n for n in graph.nodes}

    assert by_name[("app.py", "handler")].type == NodeType.FUNCTION
    assert by_name[("app.py", "Controller")].type == NodeType.CLASS
    assert by_name[("app.py", "handle")].type == NodeType.METHOD
    assert by_name[("app.py", "<module>")].type == NodeType.MODULE

    quals = {c.qualname for c in ingestion.chunks if c.kind == ChunkKind.METHOD}
    assert {"Controller.handle", "Controller.execute"} <= quals


def test_python_ast_import_alone_is_not_a_sink() -> None:
    """'import subprocess' en el preludio no convierte al módulo en sink."""
    _, graph, _ = _py_graph()
    module = next(n for n in graph.nodes if n.file == "app.py" and n.name == "<module>")
    assert not module.is_sink


def test_python_ast_prunes_substring_false_positives() -> None:
    """'exec' no matchea self.execute(), 'open(' no matchea sp.Popen()."""
    _, graph, _ = _py_graph()
    handle = next(n for n in graph.nodes if n.name == "handle")
    execute = next(n for n in graph.nodes if n.name == "execute")

    # handle solo llama a self.execute → ningún sink.
    assert not handle.is_sink
    # execute llama a sp.Popen → subprocess sí, file_op (open() no.
    kinds = {s.sink_type for s in graph.sinks if s.node_id == execute.id}
    assert kinds == {"command_execution"}


def test_module_node_does_not_shadow_functions_for_m5(tmp_path: Path) -> None:
    """Un finding dentro de una función resuelve a la función, no al <module>.

    El nodo ``<module>`` abarca el archivo entero, y ``_locate_node`` de M5 cae al
    match por rango cuando no hay match por nombre. Los nodos MODULE van últimos
    justamente para no tapar a sus propias funciones.
    """
    from hexflaw.core.models import Finding
    from hexflaw.modules.m5_taint import _locate_node

    _, graph, _ = _py_graph()
    target = next(n for n in graph.nodes if n.file == "app.py" and n.name == "run_command")
    finding = Finding(
        id="F001",
        type="command_injection",
        file="app.py",
        line=target.line_start + 1,
        function=None,  # fuerza el fallback por rango
    )

    located = _locate_node(finding, graph)
    assert located is not None and located.name == "run_command"


def test_falls_back_to_regex_when_no_ast_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sin ``ast`` ni tree-sitter, M3 mantiene el comportamiento regex de siempre.

    Se fuerzan los dos caminos AST a fallar: sintaxis inválida corta ``ast.parse`` y
    el monkeypatch simula que la grammar no está instalada. Queda el chunker regex,
    cuyos chunks no traen ``kind`` — y esa ausencia es lo que hace que M3 use
    ``_build_call_edges`` en vez de la resolución por AST.
    """
    monkeypatch.setattr(chunking, "ts_parse", lambda code, lang: None)
    broken = tmp_path / "broken.py"
    broken.write_text(
        "def handler(cmd):\n"
        "    run_command(cmd  # paréntesis sin cerrar → SyntaxError\n"
        "\n"
        "def run_command(cmd):\n"
        "    os.system(cmd)\n",
        encoding="utf-8",
    )

    ingestion, graph, edges = _py_graph(tmp_path)

    assert all(chunk.kind is None for chunk in ingestion.chunks)
    # El grafo se construye igual, con las aristas heurísticas por nombre.
    assert ("broken.py::handler", "broken.py::run_command") in edges
    assert any(n.is_sink for n in graph.nodes)
    # El fallback no produce flujo: data/control flow solo salen del camino AST.
    assert all(e.type == EdgeType.CALLS for e in graph.edges)


# --------------------------------------------------------------------------- #
# Data flow y control flow
# --------------------------------------------------------------------------- #
def _flow_graph(tmp_path: Path, source: str) -> CodeGraph:
    """Construye el grafo de un único archivo Python dado como texto."""
    (tmp_path / "flow.py").write_text(source, encoding="utf-8")
    langs = LanguageService()
    ingestion = m1_ingestion.ingest(tmp_path, "proj-flow", langs)
    return m3_graph.build_graph(ingestion, langs)


def _edge(graph: CodeGraph, src: str, dst: str, kind: EdgeType) -> GraphEdge | None:
    """Busca la arista ``src → dst`` del tipo dado, por nombre de nodo."""
    by_id = {n.id: n.name for n in graph.nodes}
    return next(
        (
            e
            for e in graph.edges
            if e.type == kind and by_id[e.from_] == src and by_id[e.to] == dst
        ),
        None,
    )


_FLOW_SOURCE = '''import shlex
import subprocess as sp


def handle_request(user_input, mode):
    if mode == "admin":
        payload = build(user_input)
        run(payload)
    run_safe(shlex.quote(user_input))


def build(raw):
    return raw.strip()


def run(cmd):
    sp.run(cmd, shell=True)


def run_safe(cmd):
    sp.run(cmd, shell=True)
'''


def test_data_flow_edge_carries_variable_names(tmp_path: Path) -> None:
    """El parámetro tainted que se pasa como argumento genera una arista data_flow."""
    graph = _flow_graph(tmp_path, _FLOW_SOURCE)
    edge = _edge(graph, "handle_request", "build", EdgeType.DATA_FLOW)

    assert edge is not None
    assert edge.data_vars == ["user_input"]
    assert not edge.sanitized


def test_data_flow_propagates_through_return_value(tmp_path: Path) -> None:
    """El taint viaja por el retorno: build() devuelve a payload y payload va a run()."""
    graph = _flow_graph(tmp_path, _FLOW_SOURCE)

    back = _edge(graph, "build", "handle_request", EdgeType.DATA_FLOW)
    assert back is not None and back.data_vars == ["payload"]

    onward = _edge(graph, "handle_request", "run", EdgeType.DATA_FLOW)
    assert onward is not None and onward.data_vars == ["payload"]


def test_control_flow_edge_records_the_guard(tmp_path: Path) -> None:
    """Una llamada dentro de un if produce arista control_flow con la condición."""
    graph = _flow_graph(tmp_path, _FLOW_SOURCE)
    edge = _edge(graph, "handle_request", "run", EdgeType.CONTROL_FLOW)

    assert edge is not None
    assert edge.condition == "if mode == 'admin'"
    # La llamada fuera del if no queda guardada.
    assert _edge(graph, "handle_request", "run_safe", EdgeType.CONTROL_FLOW) is None


def test_sanitizer_marks_the_data_flow_edge(tmp_path: Path) -> None:
    """Pasar por shlex.quote no borra la arista: la marca ``sanitized``."""
    graph = _flow_graph(tmp_path, _FLOW_SOURCE)
    edge = _edge(graph, "handle_request", "run_safe", EdgeType.DATA_FLOW)

    assert edge is not None
    assert edge.sanitized, "el dato pasó por shlex.quote y debe quedar marcado"


def test_data_flow_merges_vars_from_several_call_sites(tmp_path: Path) -> None:
    """Dos llamadas al mismo callee fusionan sus variables en una sola arista."""
    graph = _flow_graph(
        tmp_path,
        "def entry(a, b):\n    sink(a)\n    sink(b)\n\n\ndef sink(x):\n    print(x)\n",
    )
    edge = _edge(graph, "entry", "sink", EdgeType.DATA_FLOW)

    assert edge is not None
    assert edge.data_vars == ["a", "b"]


def test_adjacency_ignores_flow_edges_by_default(tmp_path: Path) -> None:
    """``build_adjacency`` solo sigue ``calls``: las de retorno van callee→caller.

    Si mezclara ``data_flow``, la arista de retorno ``build → handle_request`` le
    haría creer a M5 que existe una llamada que no existe.
    """
    from hexflaw.modules.m5_taint import build_adjacency

    graph = _flow_graph(tmp_path, _FLOW_SOURCE)
    by_id = {n.id: n.name for n in graph.nodes}
    build_id = next(i for i, name in by_id.items() if name == "build")

    call_adjacency = build_adjacency(graph)
    assert "handle_request" not in [by_id[t] for t in call_adjacency.get(build_id, [])]

    # Pedidas explícitamente, sí aparecen.
    flow_adjacency = build_adjacency(graph, (EdgeType.DATA_FLOW,))
    assert "handle_request" in [by_id[t] for t in flow_adjacency.get(build_id, [])]


def test_m5_finds_data_flow_path_to_sink(tmp_path: Path) -> None:
    """M5 encuentra el camino de data flow entry point → sink, no solo el call path."""
    from hexflaw.modules.m5_taint import find_data_flow_path

    graph = _flow_graph(tmp_path, _FLOW_SOURCE)
    by_id = {n.id: n.name for n in graph.nodes}
    sink_id = next(i for i, name in by_id.items() if name == "run")

    path = find_data_flow_path(sink_id, graph)
    names = [by_id[node_id] for node_id in path]

    assert names[0] == "handle_request", "el camino arranca en el entry point"
    assert names[-1] == "run", "y termina en el sink"


def test_m5_data_flow_path_empty_on_calls_only_graph(tmp_path: Path) -> None:
    """En un grafo viejo (solo ``calls``) no hay camino de data flow: M5 sigue igual."""
    from hexflaw.modules.m5_taint import find_data_flow_path

    graph = _flow_graph(tmp_path, _FLOW_SOURCE)
    # Se simula un artefacto pre-feature: se descartan las aristas de flujo.
    graph.edges = [e for e in graph.edges if e.type == EdgeType.CALLS]
    sink = next(n for n in graph.nodes if n.name == "run")

    assert find_data_flow_path(sink.id, graph) == []


# --------------------------------------------------------------------------- #
# Multi-lenguaje vía tree-sitter
# --------------------------------------------------------------------------- #
_TS_CASES = [
    ("c", "svc.c", '#include <stdlib.h>\nvoid run(char* c){ system(c); }\nvoid handler(char* c){ run(c); }\n'),
    ("go", "svc.go", 'package main\nimport "os/exec"\nfunc run(c string) { exec.Command("sh", "-c", c) }\nfunc handler(c string) { run(c) }\n'),
    ("java", "Svc.java", 'class Svc {\n  void run(String c){ Runtime.getRuntime().exec(c); }\n  void handler(String c){ run(c); }\n}\n'),
    ("php", "svc.php", '<?php\nfunction run($c){ shell_exec($c); }\nfunction handler($c){ run($c); }\n'),
    ("ruby", "svc.rb", 'def run(c)\n  system(c)\nend\n\ndef handler(c)\n  run(c)\nend\n'),
    ("javascript", "svc.js", 'const cp = require("child_process");\nfunction run(c){ cp.exec(c); }\nfunction handler(c){ run(c); }\n'),
]


@pytest.mark.parametrize(("language", "filename", "source"), _TS_CASES)
def test_treesitter_builds_call_edge(
    tmp_path: Path, language: str, filename: str, source: str
) -> None:
    """En cada lenguaje con grammar, handler() → run() genera arista por AST."""
    if chunking.ts_parse(source, chunking.ts_language_for(language) or "") is None:
        pytest.skip(f"grammar de tree-sitter no disponible para {language}")

    (tmp_path / filename).write_text(source, encoding="utf-8")
    langs = LanguageService()
    ingestion = m1_ingestion.ingest(tmp_path, f"proj-{language}", langs)
    graph = m3_graph.build_graph(ingestion, langs)
    by_id = {n.id: n.name for n in graph.nodes}
    pairs = {(by_id[e.from_], by_id[e.to]) for e in graph.edges if e.type == EdgeType.CALLS}

    assert any(c.kind is not None for c in ingestion.chunks), "tree-sitter no chunkeó"
    assert ("handler", "run") in pairs
    # La arista viene del camino AST, no del cruce de nombres por regex: el
    # fallback nunca emite data_flow, así que su presencia lo distingue.
    flow = {
        (by_id[e.from_], by_id[e.to])
        for e in graph.edges
        if e.type == EdgeType.DATA_FLOW
    }
    assert ("handler", "run") in flow, "el parámetro debe viajar como data flow"


def test_treesitter_sets_kind_for_non_python(tmp_path: Path) -> None:
    """El chunker tree-sitter distingue clase y método, no solo función."""
    source = 'class Svc {\n  void run(String c){}\n  void handler(String c){ run(c); }\n}\n'
    if chunking.ts_parse(source, "java") is None:
        pytest.skip("grammar de Java no disponible")

    (tmp_path / "Svc.java").write_text(source, encoding="utf-8")
    langs = LanguageService()
    ingestion = m1_ingestion.ingest(tmp_path, "proj-java", langs)
    kinds = {(c.name, c.kind) for c in ingestion.chunks}

    assert ("Svc", ChunkKind.CLASS) in kinds
    assert ("handler", ChunkKind.METHOD) in kinds
    quals = {c.qualname for c in ingestion.chunks if c.kind == ChunkKind.METHOD}
    assert "Svc.handler" in quals


def test_graph_builds_from_pre_feature_chunks() -> None:
    """Un chunks.json viejo (sin kind/qualname) sigue construyendo grafo."""
    from hexflaw.core.models import IngestionResult

    legacy = {
        "project_id": "p",
        "languages": ["python"],
        "app_type": "web",
        "file_map": [],
        "chunks": [
            {
                "id": "a.py::0",
                "file": "a.py",
                "language": "python",
                "name": "handler",
                "code": "def handler(c):\n    run_command(c)",
                "line_start": 1,
                "line_end": 2,
                "hash": "x",
            }
        ],
    }
    ingestion = IngestionResult.model_validate(legacy)
    assert ingestion.chunks[0].kind is None  # el artefacto viejo no los trae

    graph = m3_graph.build_graph(ingestion, LanguageService())
    assert [n.name for n in graph.nodes] == ["handler"]
    assert graph.nodes[0].type == NodeType.FUNCTION


def test_graph_service_integrity_roundtrip(tmp_path: Path) -> None:
    ingestion, graph = _graph()
    service = GraphService(tmp_path)
    digest = m3_graph.source_hash(ingestion)

    service.save(graph, digest)
    loaded = service.load_if_valid(digest)
    assert loaded is not None
    assert len(loaded.nodes) == len(graph.nodes)

    # Distinto source hash → no se usa la caché.
    assert service.load_if_valid("otro-hash") is None


def test_graph_service_rejects_older_schema_version(tmp_path: Path) -> None:
    """Un grafo de una versión anterior se descarta aunque el código no cambió.

    Es el caso real de este cambio: M3 pasó de regex a AST con aristas de flujo. Sin
    este chequeo, un proyecto ya analizado reutilizaba el grafo viejo para siempre y
    M5 razonaba sin data flow, sin que nada lo indicara.
    """
    from hexflaw.infrastructure import storage

    ingestion, graph = _graph()
    service = GraphService(tmp_path)
    digest = m3_graph.source_hash(ingestion)
    service.save(graph, digest)

    assert service.load_if_valid(digest) is not None  # recién guardado: válido

    # Se simula un sidecar escrito por una versión anterior del builder.
    payload = storage.read_json(service.integrity_path)
    payload["schema_version"] = GRAPH_SCHEMA_VERSION - 1
    storage.write_json(service.integrity_path, payload)

    assert service.load_if_valid(digest) is None, "un grafo viejo debe regenerarse"


def test_graph_service_rejects_sidecar_without_version(tmp_path: Path) -> None:
    """Un sidecar pre-feature (sin ``schema_version``) cuenta como versión 1."""
    from hexflaw.infrastructure import storage

    ingestion, graph = _graph()
    service = GraphService(tmp_path)
    digest = m3_graph.source_hash(ingestion)
    service.save(graph, digest)

    payload = storage.read_json(service.integrity_path)
    del payload["schema_version"]
    storage.write_json(service.integrity_path, payload)

    assert service.load_if_valid(digest) is None


def test_graph_service_detects_tampering(tmp_path: Path) -> None:
    ingestion, graph = _graph()
    service = GraphService(tmp_path)
    digest = m3_graph.source_hash(ingestion)
    service.save(graph, digest)

    # Manipulación externa del code_graph.json (T-M3-2).
    from hexflaw.infrastructure import storage

    payload = storage.read_json(service.graph_path)
    payload["nodes"] = []
    storage.write_json(service.graph_path, payload)

    assert service.load_if_valid(digest) is None  # integridad rota → regenerar


# --------------------------------------------------------------------------- #
# Catálogo de sinks calificados (import de CodeQL)
# --------------------------------------------------------------------------- #
def _java_graph(tmp_path: Path, source: str) -> CodeGraph:
    """Grafo de un único archivo Java."""
    (tmp_path / "Svc.java").write_text(source, encoding="utf-8")
    langs = LanguageService()
    return m3_graph.build_graph(m1_ingestion.ingest(tmp_path, "p", langs), langs)


def test_qualified_callee_keeps_the_receiver_type(tmp_path: Path) -> None:
    """Java expone receptor y método por separado; sin recomponer se pierde el tipo.

    Quedarse con ``exec`` a secas hace indistinguible el de ``Runtime`` de
    cualquier otro, que es lo que vuelve inservible un catálogo de miles de
    nombres de método.
    """
    graph = _java_graph(
        tmp_path, "class Svc {\n  void m(String c){ Runtime.getRuntime().exec(c); }\n}"
    )
    facts = m3_graph._ts_flow_facts(
        [c for c in m1_ingestion.ingest(tmp_path, "p", LanguageService()).chunks]
    )
    names = {call.name for f in facts.values() for call in f.calls}

    assert "Runtime.exec" in names, f"se perdió el receptor: {names}"
    assert graph is not None


def test_sink_catalog_resolves_the_vulnerability_class(tmp_path: Path) -> None:
    """El catálogo trae el sink_type ya mapeado, no un 'unknown'."""
    graph = _java_graph(
        tmp_path, "class Svc {\n  void m(String c){ Runtime.getRuntime().exec(c); }\n}"
    )
    tipos = {s.sink_type for s in graph.sinks}

    assert "command_execution" in tipos, f"tipos detectados: {tipos}"


def test_sink_catalog_does_not_flag_inert_code(tmp_path: Path) -> None:
    """1000+ patrones importados no pueden convertir código inocente en sink.

    Es la condición que hace viable el import: los nombres genéricos se filtran
    en la importación y el match exige el tipo receptor, no el método suelto.
    """
    graph = _java_graph(
        tmp_path,
        "class Svc {\n"
        "  void a(String x, String y){ System.out.println(x.length() + y.length()); }\n"
        "  void b(java.util.List<String> l){ l.add(\"x\"); l.get(0); }\n"
        "}",
    )
    por_nodo = {n.name: n.is_sink for n in graph.nodes}

    assert por_nodo.get("a") is False
    assert por_nodo.get("b") is False


def test_sink_models_are_optional_and_backward_compatible() -> None:
    """Una definición sin ``sink_models`` sigue siendo válida."""
    from hexflaw.services.language_service import LanguageDefinition

    definition = LanguageDefinition.from_dict(
        {"id": "x", "name": "X", "extensions": [".x"], "sink_patterns": ["system"]}
    )
    assert definition.sink_models == []


# --------------------------------------------------------------------------- #
# Inferencia de tipos locales
# --------------------------------------------------------------------------- #
def test_type_inference_resolves_a_parameter_receiver(tmp_path: Path) -> None:
    """``st.executeQuery`` con ``st`` de tipo Statement → ``Statement.executeQuery``.

    Es lo que hace utilizable el catálogo de sinks: casi todos los sinks de
    métodos de instancia están catalogados por tipo, no por nombre de método.
    """
    graph = _java_graph(
        tmp_path,
        "import java.sql.*;\nclass Svc {\n"
        '  void m(Statement st, String u){ st.executeQuery("SELECT " + u); }\n}',
    )
    tipos = {s.sink_type for s in graph.sinks}

    assert "sql_query" in tipos, f"tipos detectados: {tipos}"


def test_type_inference_resolves_a_local_declaration(tmp_path: Path) -> None:
    """``Statement st = c.createStatement();`` declara el tipo explícitamente."""
    graph = _java_graph(
        tmp_path,
        "import java.sql.*;\nclass Svc {\n"
        "  void m(Connection c, String u) throws Exception {\n"
        "    Statement st = c.createStatement();\n"
        "    st.executeQuery(u);\n  }\n}",
    )

    assert any(s.sink_type == "sql_query" for s in graph.sinks)


def test_type_inference_handles_implicit_var(tmp_path: Path) -> None:
    """``var pb = new ProcessBuilder(...)`` saca el tipo del valor construido."""
    from hexflaw.modules.chunking import ts_parse

    source = "void m(String u){ var pb = new ProcessBuilder(u); pb.start(); }"
    root = ts_parse(source, "java")
    assert root is not None

    types = m3_graph._ts_local_types(root, source.encode("utf-8"))

    assert types.get("pb") == "ProcessBuilder"


def test_type_inference_ignores_unresolvable_returns(tmp_path: Path) -> None:
    """Un tipo que vendría del retorno de otra llamada NO se inventa.

    ``var st = c.createStatement()`` necesitaría la firma de ``createStatement``.
    Adivinarlo produciría sinks falsos, que es peor que no resolverlo.
    """
    from hexflaw.modules.chunking import ts_parse

    source = "void m(Connection c){ var st = c.createStatement(); st.executeQuery(q); }"
    root = ts_parse(source, "java")
    assert root is not None

    types = m3_graph._ts_local_types(root, source.encode("utf-8"))

    assert "st" not in types


def test_type_inference_applies_to_dotted_call_fields(tmp_path: Path) -> None:
    """C#/Go/JS entregan la llamada como un path entero, no receptor + método.

    Sin sustituir también ahí, la inferencia de tipos solo serviría para Java.
    """
    (tmp_path / "A.cs").write_text(
        "class A {\n  void M(SqlHelper h, string q){ h.ExecuteReader(q); }\n}",
        encoding="utf-8",
    )
    langs = LanguageService()
    ingestion = m1_ingestion.ingest(tmp_path, "p", langs)
    facts = m3_graph._ts_flow_facts(ingestion.chunks)
    nombres = {call.name for f in facts.values() for call in f.calls}

    assert "SqlHelper.ExecuteReader" in nombres, nombres

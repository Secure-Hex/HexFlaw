"""Tests del render del code graph (``hexflaw graph`` y ``services.graph_render``)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from hexflaw.cli.main import app
from hexflaw.core.models import (
    CodeGraph,
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
    SinkRef,
)
from hexflaw.services import graph_render


def _graph() -> CodeGraph:
    """Grafo mínimo con un camino tainted y otro sanitizado."""
    nodes = [
        GraphNode(
            id="a",
            name="handler",
            file="src/api.py",
            line_start=1,
            line_end=5,
            type=NodeType.FUNCTION,
            is_entry_point=True,
        ),
        GraphNode(
            id="b", name="run", file="src/api.py", line_start=7, line_end=9, is_sink=True
        ),
        GraphNode(
            id="c",
            name="run_safe",
            file="src/api.py",
            line_start=11,
            line_end=13,
            is_sink=True,
        ),
        GraphNode(
            id="m",
            name="<module>",
            file="src/api.py",
            line_start=1,
            line_end=1,
            type=NodeType.MODULE,
        ),
    ]
    edges = [
        GraphEdge(from_="a", to="b", type=EdgeType.CALLS),
        GraphEdge(from_="a", to="b", type=EdgeType.DATA_FLOW, data_vars=["cmd"]),
        GraphEdge(
            from_="a", to="b", type=EdgeType.CONTROL_FLOW, condition="if mode == 'x'"
        ),
        GraphEdge(from_="a", to="c", type=EdgeType.CALLS),
        GraphEdge(
            from_="a",
            to="c",
            type=EdgeType.DATA_FLOW,
            data_vars=["safe"],
            sanitized=True,
        ),
    ]
    return CodeGraph(
        project_id="p",
        nodes=nodes,
        edges=edges,
        entry_points=["a"],
        sinks=[
            SinkRef(node_id="b", sink_type="command_execution", function="os.system"),
            SinkRef(node_id="c", sink_type="command_execution", function="subprocess"),
        ],
    )


# --------------------------------------------------------------------------- #
# select()
# --------------------------------------------------------------------------- #
def test_select_returns_everything_by_default() -> None:
    graph = _graph()
    view = graph_render.select(graph)
    assert len(view.nodes) == 4
    assert len(view.edges) == 5


def test_select_filters_by_edge_type() -> None:
    view = graph_render.select(_graph(), edge_types=(EdgeType.DATA_FLOW,))
    assert {e.type for e in view.edges} == {EdgeType.DATA_FLOW}


def test_select_focus_limits_to_neighbourhood() -> None:
    """Con foco y depth=1 solo entran el nodo y sus vecinos directos."""
    view = graph_render.select(_graph(), focus="run", depth=1)
    names = {n.name for n in view.nodes}
    assert names == {"run", "handler"}
    assert "<module>" not in names


def test_select_focus_accepts_file_qualified_name() -> None:
    view = graph_render.select(_graph(), focus="src/api.py::run", depth=0)
    assert [n.name for n in view.nodes] == ["run"]


def test_select_unknown_focus_is_empty() -> None:
    view = graph_render.select(_graph(), focus="no_existe_este_nodo")
    assert view.nodes == [] and view.edges == []


def test_select_only_flows_drops_isolated_nodes() -> None:
    """El nodo módulo no participa de ningún camino entry→sink y queda afuera."""
    view = graph_render.select(_graph(), only_flows=True)
    assert "<module>" not in {n.name for n in view.nodes}
    assert "handler" in {n.name for n in view.nodes}


# --------------------------------------------------------------------------- #
# flow_paths() / to_paths()
# --------------------------------------------------------------------------- #
def test_flow_paths_prefers_unsanitized_first() -> None:
    paths = graph_render.flow_paths(_graph())
    assert paths, "debe hallar caminos entry point → sink"
    assert paths[0].tainted, "el camino sin sanitizar va primero"
    assert paths[0].labels[0].endswith("::handler")


def test_flow_paths_hop_reports_variables_and_guard() -> None:
    paths = graph_render.flow_paths(_graph())
    tainted = next(p for p in paths if p.tainted)
    assert "cmd" in tainted.hops[0]
    assert "sin sanitizar" in tainted.hops[0]


def test_to_paths_marks_sanitized_path() -> None:
    rendered = graph_render.to_paths(_graph())
    assert "SIN SANITIZAR" in rendered
    assert "sanitizado" in rendered


def test_to_paths_without_sinks_explains_instead_of_crashing() -> None:
    graph = _graph()
    graph.sinks = []
    assert "No se encontraron caminos" in graph_render.to_paths(graph)


# --------------------------------------------------------------------------- #
# to_dot() / to_mermaid() / to_tree()
# --------------------------------------------------------------------------- #
def test_to_dot_is_well_formed_and_styles_roles() -> None:
    dot = graph_render.to_dot(graph_render.select(_graph()))

    assert dot.startswith("digraph ") and dot.rstrip().endswith("}")
    assert dot.count("{") == dot.count("}"), "llaves balanceadas"
    # entry point en verde, sink en rojo.
    assert "darkgreen" in dot and "firebrick" in dot
    # las variables del data flow van como etiqueta de la arista.
    assert 'label="cmd"' in dot


def test_to_dot_distinguishes_sanitized_flow_visually() -> None:
    """El flujo sanitizado NO se pinta como el explotable.

    En una herramienta de seguridad la vista se va al rojo: si un flujo que pasó
    por ``shlex.quote`` sale igual de rojo y grueso que uno sin sanitizar, el
    pentester mira lo que no importa.
    """
    dot = graph_render.to_dot(graph_render.select(_graph()))
    lines = dot.splitlines()

    tainted = next(ln for ln in lines if 'label="cmd"' in ln)
    sanitized = next(ln for ln in lines if "safe" in ln and "->" in ln)

    assert "firebrick" in tainted and "bold" in tainted
    assert "darkgreen" in sanitized and "bold" not in sanitized


def test_to_dot_escapes_hostile_content() -> None:
    """Nombres del código analizado no pueden romper el DOT (§15 T-M6b-1)."""
    graph = _graph()
    graph.nodes[0].file = 'evil".py\nmalicious [shape=box];'
    dot = graph_render.to_dot(graph_render.select(graph))

    assert dot.count("{") == dot.count("}")
    assert "\\" in dot, "la comilla del nombre debe quedar escapada"
    # El salto de línea no sobrevive: no puede inyectar una sentencia nueva.
    for line in dot.splitlines():
        assert not line.strip().startswith("malicious")


def test_to_mermaid_uses_distinct_arrows_per_edge_type() -> None:
    mermaid = graph_render.to_mermaid(graph_render.select(_graph()))

    assert mermaid.startswith("flowchart LR")
    assert "-->" in mermaid  # calls
    assert "==>" in mermaid  # data flow
    assert "-.->" in mermaid  # control flow


def test_to_mermaid_escapes_delimiters() -> None:
    """Los corchetes rompen el parser de Mermaid; el módulo debe seguir legible."""
    mermaid = graph_render.to_mermaid(graph_render.select(_graph()))
    body = [line for line in mermaid.splitlines() if "module" in line]

    assert body, "el nodo <module> debe aparecer"
    assert "(module)" in body[0], "los angulares se mapean a paréntesis"


def test_to_tree_groups_edges_by_target() -> None:
    """Las tres aristas hacia el mismo callee salen en una línea, no en tres."""
    graph = _graph()
    tree = graph_render.to_tree(graph_render.select(graph), graph)
    run_lines = [ln for ln in tree.splitlines() if "::run " in ln or ln.endswith("::run")]
    matching = [ln for ln in tree.splitlines() if "api.py::run " in ln]

    assert "calls,control_flow,data_flow" in tree
    assert len(matching) <= 1, f"el nodo run se repite: {run_lines}"
    assert "aristas: calls=" in tree


def test_to_tree_marks_sinks_and_reports_counts() -> None:
    graph = _graph()
    tree = graph_render.to_tree(graph_render.select(graph), graph)
    assert "(!)" in tree, "los sinks se marcan"
    assert "4 nodos" in tree and "5 aristas" in tree


def test_to_tree_breaks_cycles() -> None:
    """Un ciclo se reporta y no cuelga el render."""
    graph = _graph()
    graph.edges.append(GraphEdge(from_="b", to="a", type=EdgeType.CALLS))
    tree = graph_render.to_tree(graph_render.select(graph), graph)
    assert "(ciclo)" in tree


def test_render_handles_empty_graph() -> None:
    empty = CodeGraph(project_id="p")
    view = graph_render.select(empty)
    assert graph_render.to_dot(view).count("{") == 1
    assert graph_render.to_mermaid(view).strip() == "flowchart LR"
    assert "0 nodos" in graph_render.to_tree(view, empty)


# --------------------------------------------------------------------------- #
# Comando CLI
# --------------------------------------------------------------------------- #
def _project_with_graph(tmp_path: Path) -> Path:
    """Crea un proyecto mínimo con ``code_graph.json`` persistido."""
    from hexflaw.core.models import ProjectMetadata
    from hexflaw.infrastructure import storage

    hexflaw_dir = tmp_path / ".hexflaw"
    storage.ensure_dir(hexflaw_dir)
    storage.write_json(
        hexflaw_dir / "metadata.json",
        ProjectMetadata(project_id="p", name="test").model_dump(mode="json"),
    )
    storage.write_json(
        hexflaw_dir / "code_graph.json", _graph().model_dump(mode="json", by_alias=True)
    )
    return hexflaw_dir


def test_graph_command_writes_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``hexflaw graph -f dot -o archivo`` persiste el render con permisos 600."""
    _project_with_graph(tmp_path)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(app, ["graph", "-f", "dot", "-o", "out.dot"])

    assert result.exit_code == 0, result.output
    destination = tmp_path / "out.dot"
    assert destination.read_text(encoding="utf-8").startswith("digraph ")
    if os.name == "posix":
        assert oct(destination.stat().st_mode)[-3:] == "600"


def test_graph_command_prints_paths_to_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """La vista de caminos sale por stdout, lista para pipear."""
    _project_with_graph(tmp_path)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(app, ["graph", "-f", "paths"])

    assert result.exit_code == 0, result.output
    assert "SIN SANITIZAR" in result.output


def test_graph_command_rejects_unknown_format(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _project_with_graph(tmp_path)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(app, ["graph", "-f", "nope"])

    assert result.exit_code == 1


def test_graph_command_errors_without_graph_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sin code_graph.json el comando explica qué correr, no explota."""
    from hexflaw.core.models import ProjectMetadata
    from hexflaw.infrastructure import storage

    storage.ensure_dir(tmp_path / ".hexflaw")
    storage.write_json(
        tmp_path / ".hexflaw" / "metadata.json",
        ProjectMetadata(project_id="p", name="test").model_dump(mode="json"),
    )
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(app, ["graph"])

    assert result.exit_code == 1

"""Comando ``hexflaw graph`` — inspección y export del code graph (CLAUDE.md §6 M3)."""

from __future__ import annotations

from pathlib import Path

import typer

from hexflaw.cli import console
from hexflaw.cli.helpers import handle_project_errors
from hexflaw.core import project as project_mod
from hexflaw.core.models import CodeGraph, EdgeType
from hexflaw.infrastructure import storage
from hexflaw.services import graph_render

_EDGE_CHOICES = {
    "all": None,
    "calls": (EdgeType.CALLS,),
    "data": (EdgeType.DATA_FLOW,),
    "control": (EdgeType.CONTROL_FLOW,),
    "flow": (EdgeType.DATA_FLOW, EdgeType.CONTROL_FLOW),
}


def graph_command(
    output_format: str = typer.Option(
        "tree",
        "--format",
        "-f",
        help="tree (terminal) | paths (entry→sink) | dot (Graphviz) | mermaid | json.",
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Escribe a un archivo en vez de stdout."
    ),
    node: str | None = typer.Option(
        None,
        "--node",
        "-n",
        help="Centra la vista en un nodo ('handler' o 'src/api.py::handler').",
    ),
    depth: int = typer.Option(2, "--depth", "-d", help="Saltos alrededor del nodo."),
    edges: str = typer.Option(
        "all", "--edges", "-e", help="all | calls | data | control | flow."
    ),
    only_flows: bool = typer.Option(
        False,
        "--only-flows",
        help="Solo los nodos que participan de un camino entry point → sink.",
    ),
) -> None:
    """Muestra o exporta el code graph generado por M3.

    Ejemplos:
        hexflaw graph                        # árbol en la terminal
        hexflaw graph -f paths               # caminos entry point → sink
        hexflaw graph -f dot -o g.dot        # y después: dot -Tsvg g.dot > g.svg
        hexflaw graph -f mermaid             # pegable en Markdown
        hexflaw graph -n handle_ping -d 3    # vecindario de un nodo
    """
    with handle_project_errors():
        project = project_mod.load_project()

    graph_path = project.hexflaw_dir / "code_graph.json"
    if not graph_path.exists():
        console.error(
            "No hay code_graph.json todavía. Corré 'hexflaw analyze' (genera M3)."
        )
        raise typer.Exit(code=1)

    try:
        graph = CodeGraph.model_validate(storage.read_json(graph_path))
    except (ValueError, OSError) as exc:
        console.error(f"No se pudo leer el code graph: {exc}")
        raise typer.Exit(code=1) from exc

    if edges not in _EDGE_CHOICES:
        console.error(f"--edges inválido: {edges}. Opciones: {', '.join(_EDGE_CHOICES)}")
        raise typer.Exit(code=1)

    rendered = _render(graph, output_format, node, depth, edges, only_flows)
    if rendered is None:
        console.error(
            f"--format inválido: {output_format}. "
            "Opciones: tree, paths, dot, mermaid, json."
        )
        raise typer.Exit(code=1)

    if output is not None:
        storage.write_text(output, rendered)
        console.success(f"Escrito en {output} ({len(rendered)} bytes)")
        if output_format == "dot":
            console.info(f"Para verlo: dot -Tsvg {output} > {output.with_suffix('.svg')}")
        return
    # print() y no la consola de rich: dot/mermaid/json se pipean a otras
    # herramientas y el markup o el wrapping de rich los corrompería.
    print(rendered)


def _render(
    graph: CodeGraph,
    output_format: str,
    node: str | None,
    depth: int,
    edges: str,
    only_flows: bool,
) -> str | None:
    """Produce el texto del formato pedido, o ``None`` si el formato no existe."""
    if output_format == "paths":
        return graph_render.to_paths(graph)

    view = graph_render.select(
        graph,
        focus=node,
        depth=depth,
        edge_types=_EDGE_CHOICES[edges],
        only_flows=only_flows,
    )
    if node is not None and not view.nodes:
        return f"Ningún nodo coincide con '{node}'."

    if output_format == "tree":
        return graph_render.to_tree(view, graph)
    if output_format == "dot":
        return graph_render.to_dot(view)
    if output_format == "mermaid":
        return graph_render.to_mermaid(view)
    if output_format == "json":
        subset = graph.model_copy(update={"nodes": view.nodes, "edges": view.edges})
        return storage.dumps_json(subset.model_dump(mode="json", by_alias=True))
    return None

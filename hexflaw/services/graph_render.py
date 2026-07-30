"""Render del code graph a formatos visualizables (CLAUDE.md §14).

El code graph es el artefacto más crítico del pipeline y hasta ahora solo se podía
inspeccionar leyendo JSON a mano. Este servicio lo traduce a formatos que se ven:

- ``dot``     — Graphviz. ``hexflaw graph --format dot | dot -Tsvg > g.svg``.
- ``mermaid`` — pegable en GitHub, Notion o cualquier Markdown que lo renderice.
- ``tree``    — árbol de texto para la terminal, sin dependencias.
- ``paths``   — solo los caminos entry point → sink, que es lo que importa en SAST.

Es capa de servicio: recibe un :class:`CodeGraph` ya cargado y devuelve texto.
No lee disco, no imprime y no sabe nada de la CLI.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from hexflaw.core.models import CodeGraph, EdgeType, GraphEdge, GraphNode, NodeType

#: Estilo por tipo de arista: (color Graphviz, estilo de línea, flecha Mermaid).
_EDGE_STYLE: dict[EdgeType, tuple[str, str, str]] = {
    EdgeType.CALLS: ("gray40", "solid", "-->"),
    EdgeType.DATA_FLOW: ("firebrick", "bold", "==>"),
    EdgeType.CONTROL_FLOW: ("goldenrod3", "dashed", "-.->"),
}

#: Estilo del data flow YA SANITIZADO. Va aparte a propósito: en una herramienta de
#: seguridad la vista se va al rojo, y pintar un flujo sanitizado igual que uno
#: explotable manda al pentester a mirar lo que no importa.
_SANITIZED_STYLE = ("darkgreen", "solid", "-->")

#: Forma del nodo en Graphviz según su naturaleza.
_NODE_SHAPE: dict[NodeType, str] = {
    NodeType.FUNCTION: "box",
    NodeType.METHOD: "box",
    NodeType.CLASS: "folder",
    NodeType.MODULE: "component",
}

_MAX_LABEL = 48


@dataclass
class GraphView:
    """Subconjunto del grafo listo para renderizar."""

    nodes: list[GraphNode]
    edges: list[GraphEdge]

    @property
    def node_ids(self) -> set[str]:
        """Ids de los nodos incluidos en la vista."""
        return {node.id for node in self.nodes}


def select(
    graph: CodeGraph,
    *,
    focus: str | None = None,
    depth: int = 2,
    edge_types: tuple[EdgeType, ...] | None = None,
    only_flows: bool = False,
) -> GraphView:
    """Recorta el grafo a lo que se quiere ver.

    Un grafo completo de un codebase real es ilegible en cualquier formato, así que
    el recorte no es un lujo: es lo que hace útil la visualización.

    Args:
        graph: Code graph completo.
        focus: Nombre (o ``archivo::nombre``) del nodo desde el que expandir. Si es
            ``None``, se incluye todo el grafo.
        depth: Saltos a incluir alrededor del foco, en ambas direcciones.
        edge_types: Tipos de arista a incluir. ``None`` = todos.
        only_flows: Si ``True``, se queda solo con los nodos que participan de algún
            camino entry point → sink.

    Returns:
        La :class:`GraphView` recortada.
    """
    edges = [
        edge
        for edge in graph.edges
        if edge_types is None or edge.type in edge_types
    ]
    keep: set[str] | None = None

    if focus is not None:
        matches = _match_nodes(graph, focus)
        if not matches:
            return GraphView(nodes=[], edges=[])
        keep = _neighbourhood({n.id for n in matches}, edges, depth)

    if only_flows:
        flow_nodes = _flow_participants(graph, edges)
        keep = flow_nodes if keep is None else keep & flow_nodes

    if keep is None:
        return GraphView(nodes=list(graph.nodes), edges=edges)

    return GraphView(
        nodes=[node for node in graph.nodes if node.id in keep],
        edges=[e for e in edges if e.from_ in keep and e.to in keep],
    )


def _match_nodes(graph: CodeGraph, focus: str) -> list[GraphNode]:
    """Nodos que coinciden con el foco pedido, por nombre o ``archivo::nombre``."""
    if "::" in focus:
        wanted_file, _, wanted_name = focus.rpartition("::")
        return [
            n for n in graph.nodes if n.name == wanted_name and wanted_file in n.file
        ]
    exact = [n for n in graph.nodes if n.name == focus]
    return exact or [n for n in graph.nodes if focus.lower() in n.name.lower()]


def _neighbourhood(
    seeds: set[str], edges: list[GraphEdge], depth: int
) -> set[str]:
    """Ids alcanzables desde ``seeds`` en hasta ``depth`` saltos, en ambos sentidos."""
    outgoing: dict[str, list[str]] = {}
    incoming: dict[str, list[str]] = {}
    for edge in edges:
        outgoing.setdefault(edge.from_, []).append(edge.to)
        incoming.setdefault(edge.to, []).append(edge.from_)

    seen = set(seeds)
    frontier = deque((node_id, 0) for node_id in seeds)
    while frontier:
        node_id, distance = frontier.popleft()
        if distance >= depth:
            continue
        for neighbour in (*outgoing.get(node_id, []), *incoming.get(node_id, [])):
            if neighbour not in seen:
                seen.add(neighbour)
                frontier.append((neighbour, distance + 1))
    return seen


def _flow_participants(graph: CodeGraph, edges: list[GraphEdge]) -> set[str]:
    """Ids que participan de algún camino entry point → sink."""
    participants: set[str] = set()
    for path in flow_paths(graph, edges=edges):
        participants.update(path.node_ids)
    return participants


@dataclass
class FlowPath:
    """Un camino concreto entry point → sink, con lo que pasa en cada salto."""

    node_ids: list[str]
    labels: list[str]
    hops: list[str]
    tainted: bool

    @property
    def sanitized(self) -> bool:
        """``True`` si todos los saltos con datos están sanitizados."""
        return not self.tainted


def flow_paths(
    graph: CodeGraph, *, edges: list[GraphEdge] | None = None, limit: int = 40
) -> list[FlowPath]:
    """Caminos entry point → sink, priorizando los que llevan datos sin sanitizar.

    Prefiere aristas ``data_flow`` (probar que el dato llega) y cae a ``calls``
    cuando no hay flujo modelado, igual que M5. Es la vista que responde la única
    pregunta que importa: *¿por dónde entra el input y cómo llega al sink?*

    Args:
        graph: Code graph completo.
        edges: Aristas a considerar (por defecto, las del grafo).
        limit: Tope de caminos devueltos, para no explotar en grafos grandes.

    Returns:
        Lista de :class:`FlowPath`, primero los no sanitizados.
    """
    pool = list(graph.edges) if edges is None else edges
    by_id = {node.id: node for node in graph.nodes}
    sink_ids = [s.node_id for s in graph.sinks if s.node_id in by_id]
    entry_ids = {e for e in graph.entry_points if e in by_id}
    if not sink_ids or not entry_ids:
        return []

    index: dict[tuple[str, str], list[GraphEdge]] = {}
    for edge in pool:
        index.setdefault((edge.from_, edge.to), []).append(edge)

    results: list[FlowPath] = []
    seen_paths: set[tuple[str, ...]] = set()
    for preferred in (EdgeType.DATA_FLOW, EdgeType.CALLS):
        adjacency: dict[str, list[str]] = {}
        for edge in pool:
            if edge.type == preferred:
                adjacency.setdefault(edge.from_, []).append(edge.to)
        for sink_id in sink_ids:
            path = _shortest_path(entry_ids, sink_id, adjacency)
            if path is None or tuple(path) in seen_paths:
                continue
            seen_paths.add(tuple(path))
            hops = [
                _hop_label(index.get((path[i], path[i + 1]), []))
                for i in range(len(path) - 1)
            ]
            results.append(
                FlowPath(
                    node_ids=path,
                    labels=[_node_label(by_id[i]) for i in path],
                    hops=hops,
                    tainted=any("sin sanitizar" in hop for hop in hops)
                    or all(not hop for hop in hops),
                )
            )
            if len(results) >= limit:
                break
        if len(results) >= limit:
            break

    results.sort(key=lambda p: not p.tainted)  # los no sanitizados primero
    return results


def _shortest_path(
    sources: set[str], target: str, adjacency: dict[str, list[str]]
) -> list[str] | None:
    """BFS multi-source; ``None`` si el target no es alcanzable."""
    if target in sources:
        return [target]
    parent: dict[str, str | None] = {s: None for s in sources}
    queue = deque(sources)
    while queue:
        node = queue.popleft()
        for nxt in adjacency.get(node, []):
            if nxt in parent:
                continue
            parent[nxt] = node
            if nxt == target:
                path: list[str] = []
                cursor: str | None = nxt
                while cursor is not None:
                    path.append(cursor)
                    cursor = parent[cursor]
                return list(reversed(path))
            queue.append(nxt)
    return None


def _hop_label(edges: list[GraphEdge]) -> str:
    """Resumen de un salto: variables que viajan, sanitización y guardas."""
    parts: list[str] = []
    for edge in edges:
        if edge.type == EdgeType.DATA_FLOW and edge.data_vars:
            state = "sanitizado" if edge.sanitized else "sin sanitizar"
            parts.append(f"{', '.join(edge.data_vars)} ({state})")
        elif edge.type == EdgeType.CONTROL_FLOW and edge.condition:
            # La condición ya viene con su keyword ('if x', 'while y').
            parts.append(f"solo {edge.condition}")
    return " · ".join(parts)


def _node_label(node: GraphNode) -> str:
    """Etiqueta legible de un nodo: ``archivo::nombre``."""
    return f"{node.file}::{node.name}"


def _truncate(text: str, limit: int = _MAX_LABEL) -> str:
    """Acorta un texto para que quepa en una etiqueta de grafo."""
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def to_dot(view: GraphView, *, title: str = "HexFlaw code graph") -> str:
    """Renderiza la vista a Graphviz DOT.

    Los entry points salen en verde, los sinks en rojo, y el tipo de arista se
    distingue por color y estilo de línea. Las aristas ``data_flow`` llevan las
    variables como etiqueta, y las ``control_flow`` la condición.
    """
    lines = [
        f'digraph "{_escape_dot(title)}" {{',
        "  rankdir=LR;",
        '  graph [fontname="Helvetica", labelloc="t", '
        f'label="{_escape_dot(title)}"];',
        '  node [fontname="Helvetica", fontsize=10, style="filled", fillcolor="white"];',
        '  edge [fontname="Helvetica", fontsize=8];',
    ]
    for node in view.nodes:
        attributes = [
            f'label="{_escape_dot(_node_label(node))}"',
            f'shape="{_NODE_SHAPE.get(node.type, "box")}"',
        ]
        if node.is_sink:
            attributes += ['fillcolor="#ffdddd"', 'color="firebrick"', "penwidth=2"]
        elif node.is_entry_point:
            attributes += ['fillcolor="#ddffdd"', 'color="darkgreen"', "penwidth=2"]
        lines.append(f'  "{node.id}" [{", ".join(attributes)}];')

    for edge in view.edges:
        color, style, _ = _edge_style(edge)
        attributes = [f'color="{color}"', f'style="{style}"']
        label = _edge_label(edge)
        if label:
            attributes.append(f'label="{_escape_dot(label)}"')
        lines.append(f'  "{edge.from_}" -> "{edge.to}" [{", ".join(attributes)}];')

    lines.append("}")
    return "\n".join(lines)


def to_mermaid(view: GraphView) -> str:
    """Renderiza la vista a Mermaid (``flowchart LR``), pegable en Markdown."""
    lines = ["flowchart LR"]
    aliases = {node.id: f"n{i}" for i, node in enumerate(view.nodes)}
    for node in view.nodes:
        label = _escape_mermaid(_node_label(node))
        shape = f"[/{label}/]" if node.type == NodeType.MODULE else f"[{label}]"
        lines.append(f"  {aliases[node.id]}{shape}")

    for edge in view.edges:
        if edge.from_ not in aliases or edge.to not in aliases:
            continue
        _, _, arrow = _edge_style(edge)
        label = _edge_label(edge)
        marker = f"|{_escape_mermaid(label)}|" if label else ""
        lines.append(f"  {aliases[edge.from_]} {arrow}{marker} {aliases[edge.to]}")

    for node in view.nodes:
        if node.is_sink:
            lines.append(f"  style {aliases[node.id]} fill:#ffdddd,stroke:#b22222")
        elif node.is_entry_point:
            lines.append(f"  style {aliases[node.id]} fill:#ddffdd,stroke:#006400")
    return "\n".join(lines)


def to_tree(view: GraphView, graph: CodeGraph) -> str:
    """Árbol de texto para la terminal: entry points, sinks y aristas por nodo."""
    by_id = {node.id: node for node in view.nodes}
    outgoing: dict[str, list[GraphEdge]] = {}
    for edge in view.edges:
        outgoing.setdefault(edge.from_, []).append(edge)

    lines: list[str] = []
    entries = [by_id[i] for i in graph.entry_points if i in by_id]
    sinks = [by_id[s.node_id] for s in graph.sinks if s.node_id in by_id]
    lines.append(
        f"{len(view.nodes)} nodos · {len(view.edges)} aristas · "
        f"{len(entries)} entry points · {len(sinks)} sinks"
    )

    counts: dict[str, int] = {}
    for edge in view.edges:
        counts[edge.type.value] = counts.get(edge.type.value, 0) + 1
    if counts:
        lines.append(
            "aristas: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        )

    roots = entries or sorted(by_id.values(), key=_node_label)[:20]
    for root in roots:
        lines.append("")
        lines.append(f"* {_node_label(root)}  [{root.type.value}]")
        _tree_branch(root.id, outgoing, by_id, lines, prefix="  ", seen={root.id})
    return "\n".join(lines)


def _tree_branch(
    node_id: str,
    outgoing: dict[str, list[GraphEdge]],
    by_id: dict[str, GraphNode],
    lines: list[str],
    *,
    prefix: str,
    seen: set[str],
    depth: int = 0,
) -> None:
    """Escribe recursivamente las aristas salientes de un nodo."""
    if depth >= 6:
        lines.append(f"{prefix}... (profundidad máxima)")
        return
    # Se agrupa por nodo destino: las tres aristas hacia el mismo callee son una
    # sola relación vista de tres formas, y listarlas por separado triplica el
    # árbol sin agregar información.
    grouped: dict[str, list[GraphEdge]] = {}
    for edge in outgoing.get(node_id, []):
        if edge.to in by_id:
            grouped.setdefault(edge.to, []).append(edge)

    targets = list(grouped)
    for i, target_id in enumerate(targets):
        target = by_id[target_id]
        group = grouped[target_id]
        last = i == len(targets) - 1
        kinds = ",".join(sorted({e.type.value for e in group}))
        details = " · ".join(filter(None, (_edge_label(e) for e in group)))
        suffix = f"  [{details}]" if details else ""
        mark = " (!)" if target.is_sink else ""
        lines.append(
            f"{prefix}{'`-' if last else '|-'} {kinds}: "
            f"{_node_label(target)}{mark}{suffix}"
        )
        child_prefix = prefix + ("   " if last else "|  ")
        if target_id in seen:
            lines.append(f"{child_prefix}(ciclo)")
            continue
        _tree_branch(
            target_id,
            outgoing,
            by_id,
            lines,
            prefix=child_prefix,
            seen=seen | {target_id},
            depth=depth + 1,
        )


def to_paths(graph: CodeGraph, *, limit: int = 40) -> str:
    """Vista de caminos entry point → sink, con el estado del dato en cada salto."""
    paths = flow_paths(graph, limit=limit)
    if not paths:
        return (
            "No se encontraron caminos entry point → sink.\n"
            "Puede que no haya entry points detectados, que no haya sinks, o que el "
            "grafo no tenga aristas que los conecten."
        )
    lines: list[str] = []
    for i, path in enumerate(paths, start=1):
        flag = "SIN SANITIZAR" if path.tainted else "sanitizado"
        lines.append(f"[{i}] {flag}")
        for step, label in enumerate(path.labels):
            lines.append(f"    {step + 1}. {label}")
            if step < len(path.hops) and path.hops[step]:
                lines.append(f"       |  {path.hops[step]}")
        lines.append("")
    return "\n".join(lines).rstrip()


def _edge_style(edge: GraphEdge) -> tuple[str, str, str]:
    """Estilo de la arista, distinguiendo el data flow sanitizado del que no lo está."""
    if edge.type == EdgeType.DATA_FLOW and edge.sanitized:
        return _SANITIZED_STYLE
    return _EDGE_STYLE.get(edge.type, ("black", "solid", "-->"))


def _edge_label(edge: GraphEdge) -> str:
    """Etiqueta de una arista según su tipo."""
    if edge.type == EdgeType.DATA_FLOW and edge.data_vars:
        suffix = " ✓" if edge.sanitized else ""
        return _truncate(", ".join(edge.data_vars)) + suffix
    if edge.type == EdgeType.CONTROL_FLOW and edge.condition:
        return _truncate(edge.condition)
    return ""


def _escape_dot(text: str) -> str:
    """Escapa un texto para usarlo como literal en DOT.

    El contenido viene del código analizado (nombres de archivo, condiciones), que
    es entrada no confiable: nunca se interpola crudo (CLAUDE.md §15 T-M6b-1).
    """
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def _escape_mermaid(text: str) -> str:
    """Escapa un texto para usarlo como etiqueta en Mermaid.

    Los delimitadores rompen el parser de Mermaid. Los angulares se mapean a
    paréntesis en vez de borrarse, para que ``<module>`` siga leyéndose.
    """
    cleaned = text.replace('"', "'").replace("\n", " ")
    cleaned = cleaned.replace("<", "(").replace(">", ")")
    for char in "[]{}|":
        cleaned = cleaned.replace(char, " ")
    return cleaned

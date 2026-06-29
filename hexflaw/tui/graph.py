"""HexFlaw TUI — Fase 3: visor interactivo del code graph (Textual).

En una terminal no se puede "dibujar" un grafo con líneas de forma legible para
codebases reales, así que el grafo se explora como un árbol navegable (entry
points, sinks, y por archivo) + un panel de detalle que muestra, para el nodo
bajo el cursor/mouse, sus aristas: a quién llama y quién lo llama (el "grafo
alrededor" del nodo). El hover del mouse mueve el cursor del árbol y dispara la
actualización del detalle.
"""

from __future__ import annotations

from rich.panel import Panel
from rich.table import Table
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import Footer, Header, Static, Tree

from hexflaw.core.models import CodeGraph
from hexflaw.infrastructure import storage


def _etype(e) -> str:
    return getattr(e.type, "value", str(e.type))


class GraphScreen(Screen):
    """Pantalla del code graph: árbol de nodos + detalle de aristas con hover."""

    CSS = """
    #gtree { width: 45%; border: round $accent; }
    #gdetail { width: 1fr; border: round $primary; padding: 0 1; }
    """
    BINDINGS = [
        ("escape", "app.pop_screen", "Volver"),
        ("q", "app.pop_screen", "Volver"),
    ]

    def __init__(self, project) -> None:
        super().__init__()
        self.project = project
        self.graph: CodeGraph | None = None
        self._nmap: dict = {}
        self._out: dict = {}
        self._in: dict = {}

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            yield Tree("code graph", id="gtree")
            yield Static("Pasá por un nodo (mouse o flechas) para ver su detalle.", id="gdetail")
        yield Footer()

    def on_mount(self) -> None:
        path = self.project.hexflaw_dir / "code_graph.json"
        detail = self.query_one("#gdetail", Static)
        if not path.exists():
            detail.update("[yellow]No hay code_graph todavía. Corré 'analyze' (genera M3).[/]")
            return
        try:
            self.graph = CodeGraph.model_validate(storage.read_json(path))
        except Exception as exc:  # artefacto corrupto
            detail.update(f"[red]Error cargando el code graph: {exc}[/]")
            return
        self._nmap = {n.id: n for n in self.graph.nodes}
        for e in self.graph.edges:
            self._out.setdefault(e.from_, []).append(e)
            self._in.setdefault(e.to, []).append(e)
        self._build_tree()

    def _build_tree(self) -> None:
        assert self.graph is not None
        tree = self.query_one("#gtree", Tree)
        tree.root.expand()

        eps = [self._nmap[i] for i in self.graph.entry_points if i in self._nmap]
        ep_branch = tree.root.add(f"ENTRY POINTS ({len(eps)})", expand=True)
        for n in eps:
            ep_branch.add_leaf(f">> {n.name}  ({n.file})", data=n.id)

        sink_branch = tree.root.add(f"SINKS ({len(self.graph.sinks)})", expand=True)
        for s in self.graph.sinks:
            sink_branch.add_leaf(f"!! {s.function}  ({s.sink_type})", data=s.node_id)

        by_file: dict[str, list] = {}
        for n in self.graph.nodes:
            by_file.setdefault(n.file, []).append(n)
        files_branch = tree.root.add(f"ARCHIVOS ({len(by_file)}) - {len(self.graph.nodes)} nodos")
        for fname in sorted(by_file):
            fb = files_branch.add(f"{fname} ({len(by_file[fname])})")
            for n in sorted(by_file[fname], key=lambda x: x.line_start):
                mark = "*" if n.is_entry_point else ("!" if n.is_sink else " ")
                fb.add_leaf(f"{mark} {n.name}  L{n.line_start}", data=n.id)

    def on_tree_node_highlighted(self, event: Tree.NodeHighlighted) -> None:
        """Hover/navegación: actualiza el panel de detalle del nodo apuntado."""
        node_id = event.node.data
        if not node_id or node_id not in self._nmap:
            return
        self.query_one("#gdetail", Static).update(self._detail(node_id))

    def _detail(self, node_id: str):
        n = self._nmap[node_id]
        t = Table(show_header=False, box=None, expand=True)
        t.add_row("[b]nombre[/]", n.name)
        t.add_row("archivo", f"{n.file}:{n.line_start}-{n.line_end}")
        t.add_row("tipo", getattr(n.type, "value", str(n.type)))
        if n.signature:
            t.add_row("firma", n.signature)
        flags = []
        if n.is_entry_point:
            flags.append("[green]entry point[/]")
        if n.is_sink:
            flags.append("[red]sink[/]")
        if flags:
            t.add_row("flags", " ".join(flags))
        if n.tags:
            t.add_row("tags", ", ".join(n.tags))

        outs = self._out.get(node_id, [])
        ins = self._in.get(node_id, [])
        t.add_row("", "")
        t.add_row(f"[b cyan]-> llama a ({len(outs)})[/]", "")
        for e in outs[:15]:
            dst = self._nmap.get(e.to)
            label = dst.name if dst else e.to
            t.add_row("", f"[dim]{_etype(e)}[/] -> {label}")
        t.add_row(f"[b magenta]<- llamado por ({len(ins)})[/]", "")
        for e in ins[:15]:
            src = self._nmap.get(e.from_)
            label = src.name if src else e.from_
            t.add_row("", f"[dim]{_etype(e)}[/] <- {label}")

        border = "red" if n.is_sink else ("green" if n.is_entry_point else "cyan")
        return Panel(t, title=f"{n.name}", border_style=border)

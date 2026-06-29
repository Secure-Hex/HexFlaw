"""Capa de presentación visual con rich (CLAUDE.md §13/§14).

Centraliza todo el render bonito de la CLI: paneles, tablas, spinners y estilos
de severidad/estado. Es presentación pura — no contiene lógica de negocio y el
Core nunca la importa.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from typing import Any, Callable, Iterator

from rich.console import Console, Group
from rich.live import Live
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


def esc(value: object) -> str:
    """Escapa markup de rich en contenido dinámico (del código analizado).

    Evita que nombres de archivo/función o notas con corchetes rompan el render
    o inyecten estilos en la terminal (análogo al escaping de Markdown en M6b).

    Args:
        value: Valor a escapar (se convierte a str).

    Returns:
        Texto seguro para interpolar en strings con markup.
    """
    return escape(str(value))

#: Consola principal (stdout). Los logs van por su propio handler a stderr.
console = Console()
err_console = Console(stderr=True)

BRAND = "[bold magenta]HexFlaw[/] [dim]· SecureHex[/]"

#: Estilos por severidad de hallazgo (M6b).
SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

#: Estilos por estado de hallazgo (M5).
STATUS_STYLE = {
    "confirmed": "bold red",
    "conditional": "yellow",
    "false_positive": "dim",
    "preliminary": "blue",
    "needs_review": "bold magenta",
}


def banner(subtitle: str = "") -> None:
    """Imprime el encabezado de marca de HexFlaw.

    Args:
        subtitle: Texto secundario opcional bajo el título.
    """
    body = Text.from_markup(
        "[bold magenta]HexFlaw[/]  [dim]AI-powered source code vulnerability analyzer[/]"
    )
    if subtitle:
        body.append("\n")
        body.append(Text.from_markup(f"[dim]{subtitle}[/]"))
    console.print(Panel(body, border_style="magenta", expand=False))


def success(message: str) -> None:
    """Mensaje de éxito (verde)."""
    console.print(f"[bold green]✓[/] {message}")


def warn(message: str) -> None:
    """Mensaje de advertencia (amarillo)."""
    console.print(f"[bold yellow]![/] {message}")


def error(message: str) -> None:
    """Mensaje de error (rojo, a stderr)."""
    err_console.print(f"[bold red]✗[/] {message}")


def info(message: str) -> None:
    """Mensaje informativo neutro."""
    console.print(message)


def kv_panel(title: str, rows: list[tuple[str, str]], *, border: str = "cyan") -> None:
    """Imprime un panel con pares clave/valor alineados.

    Args:
        title: Título del panel.
        rows: Lista de tuplas ``(clave, valor)``.
        border: Color del borde.
    """
    table = Table.grid(padding=(0, 2))
    table.add_column(style="dim", justify="right")
    table.add_column()
    for key, value in rows:
        table.add_row(key, value)
    console.print(Panel(table, title=title, border_style=border, expand=False))


def table(title: str, columns: list[str]) -> Table:
    """Crea una tabla rich con encabezados estilizados.

    Args:
        title: Título de la tabla.
        columns: Nombres de columna.

    Returns:
        La :class:`~rich.table.Table` lista para ``add_row``.
    """
    tbl = Table(title=title, header_style="bold magenta", title_style="bold")
    for col in columns:
        tbl.add_column(col)
    return tbl


def print_table(tbl: Table) -> None:
    """Imprime una tabla ya construida."""
    console.print(tbl)


def _quiet_hexflaw_logs(level: int) -> dict[str, int]:
    """Baja el nivel de todos los loggers ``hexflaw.*`` y devuelve los previos."""
    previous: dict[str, int] = {}
    for name, lg in logging.root.manager.loggerDict.items():
        if name.startswith("hexflaw") and isinstance(lg, logging.Logger):
            previous[name] = lg.level
            lg.setLevel(level)
    return previous


def _restore_logs(previous: dict[str, int]) -> None:
    for name, lvl in previous.items():
        logging.getLogger(name).setLevel(lvl)


def _fmt_dur(seconds: float) -> str:
    """Formatea una duración en segundos de forma compacta (``1.2s`` / ``2m05s``)."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, secs = divmod(int(seconds), 60)
    return f"{minutes}m{secs:02d}s"


def _render_pipeline(orchestrator: Any, title: str) -> Panel:
    """Construye el panel en vivo: timeline con tiempos, fase actual, tokens."""
    llm = getattr(orchestrator, "llm", None)

    # Timeline de fases: completadas (con duración) + la actual (elapsed en vivo).
    phases = Table.grid(padding=(0, 2))
    phases.add_column()
    phases.add_column(justify="right")
    try:
        done = orchestrator.timeline()
    except Exception:
        done = []
    for name, dur in done:
        phases.add_row(f"[green]✓[/] {esc(name)}", f"[dim]{_fmt_dur(dur)}[/]")
    current = getattr(orchestrator, "current_phase", "")
    if current and current != "done":
        elapsed = _fmt_dur(getattr(orchestrator, "current_elapsed", 0.0))
        phases.add_row(f"[bold cyan]▶ {esc(current)}[/]", f"[bold cyan]{elapsed}[/]")
        detail = getattr(orchestrator, "detail", "")
        if detail:
            phases.add_row(f"  [dim]└ {esc(detail)}[/]", "")

    usage = getattr(llm, "model_usage", {}) or {}
    tbl = Table(box=None, pad_edge=False, header_style="bold magenta")
    tbl.add_column("Modelo")
    tbl.add_column("Llamadas", justify="right")
    tbl.add_column("In tok", justify="right")
    tbl.add_column("Out tok", justify="right")
    try:  # el worker thread puede mutar model_usage mientras renderizamos
        items = sorted(usage.items())
    except RuntimeError:
        items = []
    for model, row in items:
        marker = "[green]●[/] " if model == getattr(llm, "last_model", "") else "  "
        tbl.add_row(
            f"{marker}{esc(model)}",
            str(row.get("calls", 0)),
            f"{row.get('input', 0):,}",
            f"{row.get('output', 0):,}",
        )
    if not items:
        tbl.add_row("[dim]— sin llamadas todavía —[/]", "", "", "")

    total_in = getattr(llm, "total_input_tokens", 0)
    total_out = getattr(llm, "total_output_tokens", 0)
    totals = Text.from_markup(
        f"[dim]Total:[/] [bold]{total_in:,}[/] in · [bold]{total_out:,}[/] out "
        f"· [bold]{total_in + total_out:,}[/] tokens"
    )
    parts: list[Any] = [phases, Text.from_markup("[dim]" + "─" * 36 + "[/]"), tbl, totals]
    waiting = getattr(llm, "waiting_reason", "")
    if waiting:
        parts.append(Text.from_markup(f"[yellow]⏳ esperando · {esc(waiting)}[/]"))
    return Panel(Group(*parts), title=title, border_style="cyan", expand=False)


def live_run(orchestrator: Any, work: Callable[[], Any], *, title: str = BRAND) -> Any:
    """Ejecuta ``work`` en un thread mostrando un panel en vivo del progreso.

    El panel refleja la fase actual del pipeline, el modelo en uso y el consumo
    de tokens por modelo, leídos de ``orchestrator.status`` y ``orchestrator.llm``.
    Silencia los logs INFO/WARNING mientras dura (el panel ya muestra el estado);
    los ERROR siguen visibles.

    Args:
        orchestrator: Orquestador en ejecución (expone ``status`` y ``llm``).
        work: Función sin argumentos que ejecuta el pipeline y retorna su valor.
        title: Título del panel.

    Returns:
        El valor retornado por ``work`` (re-lanza su excepción si falla).
    """
    previous = _quiet_hexflaw_logs(logging.ERROR)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(work)
            with Live(
                _render_pipeline(orchestrator, title),
                console=console,
                refresh_per_second=4,
                transient=True,
            ) as live:
                while not future.done():
                    live.update(_render_pipeline(orchestrator, title))
                    time.sleep(0.25)
                live.update(_render_pipeline(orchestrator, title))
            return future.result()
    finally:
        _restore_logs(previous)


@contextmanager
def step(description: str) -> Iterator[None]:
    """Spinner para una operación larga, silenciando logs INFO mientras corre.

    Evita que los logs INFO del pipeline corrompan el spinner; los WARNING/ERROR
    (relevantes para seguridad) siguen visibles.

    Args:
        description: Texto a mostrar junto al spinner.
    """
    previous: dict[str, int] = {}
    for name, logger in logging.root.manager.loggerDict.items():
        if name.startswith("hexflaw") and isinstance(logger, logging.Logger):
            previous[name] = logger.level
            logger.setLevel(logging.WARNING)
    try:
        with console.status(f"[cyan]{description}[/]", spinner="dots"):
            yield
    finally:
        for name, level in previous.items():
            logging.getLogger(name).setLevel(level)

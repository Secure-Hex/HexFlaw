"""Comando ``hexflaw report`` — M6a → M6b (reportes ejecutivo y técnico)."""

from __future__ import annotations

import typer

from hexflaw.cli import console
from hexflaw.cli.helpers import build_orchestrator, handle_project_errors


def report_command(
    fmt: str = typer.Option(
        "markdown", "--format", help="markdown | pdf | json | sarif."
    ),
) -> None:
    """Genera los reportes de los hallazgos confirmados."""
    fmt = fmt.lower()
    valid = {"markdown", "pdf", "json", "sarif"}
    if fmt not in valid:
        console.error(f"Formato inválido '{fmt}'. Opciones: {', '.join(sorted(valid))}.")
        raise typer.Exit(code=1)
    with handle_project_errors():
        orchestrator = build_orchestrator()
        results = console.live_run(
            orchestrator,
            lambda: orchestrator.run_output(
                do_report=True, do_poc=False, report_format=fmt
            ),
            title="HexFlaw · report",
        )

    paths = results["reports"]
    if not paths:
        console.success("Sin hallazgos confirmados para reportar.")
        return
    console.success(f"{len(paths)} archivo(s) de reporte generados:")
    for path in paths:
        console.info(f"  [dim]{path}[/]")

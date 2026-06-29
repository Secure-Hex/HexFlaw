"""Comando ``hexflaw run`` — pipeline completo en un solo paso (CLAUDE.md §10)."""

from __future__ import annotations

import typer

from hexflaw.cli import console
from hexflaw.cli.helpers import build_orchestrator, handle_project_errors


def run_command(
    source: str = typer.Argument(
        ..., help="Directorio, .zip, URL git o URL http(s) a analizar."
    ),
    target: str = typer.Option(
        None, "--target", help="Funcionalidad a analizar (directed); vacío = discovery."
    ),
    fmt: str = typer.Option(
        "markdown", "--format", help="markdown | pdf | json | sarif."
    ),
) -> None:
    """Ejecuta ingest → analyze → report + poc de una sola vez."""
    fmt = fmt.lower()
    valid = {"markdown", "pdf", "json", "sarif"}
    if fmt not in valid:
        console.error(f"Formato inválido '{fmt}'. Opciones: {', '.join(sorted(valid))}.")
        raise typer.Exit(code=1)
    console.banner("Pipeline completo · M1 → M6c")
    with handle_project_errors():
        orchestrator = build_orchestrator()
        result = console.live_run(
            orchestrator,
            lambda: orchestrator.run_pipeline(source, target, report_format=fmt),
            title="HexFlaw · run",
        )

    findings = result["findings"]
    confirmed = [f for f in findings.findings if f.status.value == "confirmed"]
    console.kv_panel(
        "Pipeline completo",
        [
            ("Hallazgos", str(len(findings.findings))),
            ("Confirmados", f"[bold red]{len(confirmed)}[/]"),
            ("Reportes", f"{len(result['reports'])} archivo(s)"),
            ("PoCs", f"{len(result['pocs'])} directorio(s)"),
        ],
        border="green",
    )

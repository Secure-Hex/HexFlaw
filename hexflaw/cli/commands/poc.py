"""Comando ``hexflaw poc`` — M6a → M6c (generación de PoCs)."""

from __future__ import annotations

from hexflaw.cli import console
from hexflaw.cli.helpers import build_orchestrator, handle_project_errors


def poc_command() -> None:
    """Genera los PoCs estáticos de los hallazgos confirmados."""
    with handle_project_errors():
        orchestrator = build_orchestrator()
        results = console.live_run(
            orchestrator,
            lambda: orchestrator.run_output(do_report=False, do_poc=True),
            title="HexFlaw · poc",
        )

    paths = results["pocs"]
    if not paths:
        console.success("Sin hallazgos confirmados para PoC.")
        return
    console.success(f"{len(paths)} PoC(s) generados:")
    for path in paths:
        console.info(f"  [dim]{path}/[/]")
    console.warn("Revisar manualmente antes de ejecutar. HexFlaw nunca ejecuta PoCs.")

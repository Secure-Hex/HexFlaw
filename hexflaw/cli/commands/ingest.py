"""Comando ``hexflaw ingest`` — M1 Ingestion sobre directorio / zip / git / url."""

from __future__ import annotations

import typer

from hexflaw.cli import console
from hexflaw.cli.helpers import build_orchestrator, handle_project_errors


def ingest_command(
    source: str = typer.Argument(
        ..., help="Directorio, archivo .zip, URL git o URL http(s) a ingerir."
    ),
    incremental: bool = typer.Option(
        False, "--incremental", help="Re-indexar solo archivos modificados."
    ),
) -> None:
    """Ingesta un codebase: detecta lenguajes, hashea y chunkea por AST."""
    with handle_project_errors():
        orchestrator = build_orchestrator()
        with console.step(f"Ingiriendo {source}..."):
            result = orchestrator.run_ingest(source, incremental=incremental)

    console.kv_panel(
        "Ingestión completa",
        [
            ("Archivos", str(len(result.file_map))),
            ("Chunks", str(len(result.chunks))),
            ("Lenguajes", ", ".join(result.languages) or "—"),
            ("App type", result.app_type.value),
        ],
        border="green",
    )
    if result.skipped:
        console.warn(f"Saltados por seguridad: {len(result.skipped)}")
    if result.dropped_from_prior:
        n = len(result.dropped_from_prior)
        sample = ", ".join(result.dropped_from_prior[:3])
        more = f" (+{n - 3} más)" if n > 3 else ""
        console.warn(
            f"⚠ {n} archivo(s) del índice previo quedaron FUERA: {sample}{more}. "
            "Si querías sumar este path al índice, usá --incremental; "
            "si no, ingerí un directorio raíz que cubra todo."
        )

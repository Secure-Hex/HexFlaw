"""Comando ``hexflaw tui`` — lanza el modo TUI (Textual).

Toma toda la terminal y permite operar el proyecto desde adentro. La lógica vive
en el Core Engine; este comando solo arranca la capa de presentación TUI.
"""

from __future__ import annotations

import typer


def tui_command() -> None:
    """Lanza la interfaz TUI de HexFlaw sobre el proyecto detectado."""
    try:
        from hexflaw.tui.app import run_tui
    except ImportError as exc:
        typer.secho(
            "El modo TUI requiere 'textual'. Instalalo con:\n"
            "  pip install --user textual",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1) from exc
    run_tui()

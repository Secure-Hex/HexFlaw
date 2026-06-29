"""Comando ``hexflaw init`` — inicializa un proyecto en el CWD."""

from __future__ import annotations

from pathlib import Path

import typer

from hexflaw.cli import console
from hexflaw.core import project as project_mod

app = typer.Typer()


def init_command(
    name: str = typer.Option(None, "--name", help="Nombre descriptivo del proyecto."),
) -> None:
    """Inicializa un proyecto HexFlaw en el directorio actual.

    Crea ``.hexflaw/`` con la metadata del proyecto, análogo a ``git init``.
    """
    try:
        project = project_mod.init_project(Path.cwd(), name=name)
    except project_mod.ProjectExistsError as exc:
        console.warn(str(exc))
        raise typer.Exit(code=1) from exc

    console.success(f"Proyecto inicializado: [bold]{project.metadata.name}[/]")
    console.kv_panel(
        "Proyecto",
        [("ID", project.metadata.project_id), ("Path", str(project.hexflaw_dir))],
        border="green",
    )

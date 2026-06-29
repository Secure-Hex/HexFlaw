"""Helpers compartidos por los comandos de la CLI.

Mantienen los comandos delgados: construcción del orchestrator, resolución de
config y manejo uniforme de errores de proyecto. Sin lógica de negocio.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

import typer

from hexflaw.cli import console
from hexflaw.core import project as project_mod
from hexflaw.core.orchestrator import Orchestrator
from hexflaw.infrastructure import config as config_mod
from hexflaw.infrastructure.config import Config
from hexflaw.modules import source_resolver


def resolve_active_config(overrides: dict[str, Any] | None = None) -> Config:
    """Resuelve la config efectiva, anclada al proyecto si existe.

    Args:
        overrides: Overrides provenientes de flags de la CLI.

    Returns:
        Config efectiva (usa solo global+defaults si no hay proyecto).
    """
    try:
        root = project_mod.find_project_root()
    except project_mod.ProjectNotFoundError:
        root = None
    return config_mod.resolve_config(project_dir=root, overrides=overrides)


def build_orchestrator(overrides: dict[str, Any] | None = None) -> Orchestrator:
    """Carga el proyecto activo y construye su orchestrator.

    Args:
        overrides: Overrides de config provenientes de la CLI.

    Returns:
        Orchestrator listo para ejecutar el pipeline.

    Raises:
        ProjectNotFoundError: Si no hay proyecto inicializado (manejado por
            :func:`handle_project_errors`).
    """
    project = project_mod.load_project()
    config = config_mod.resolve_config(project_dir=project.root, overrides=overrides)
    return Orchestrator(project, config)


@contextmanager
def handle_project_errors() -> Iterator[None]:
    """Traduce errores comunes del Core a mensajes de CLI y exit codes.

    Convierte excepciones de dominio (proyecto no encontrado, artefactos
    faltantes, rutas inválidas) en salida amigable sin trazas crudas.
    """
    try:
        yield
    except project_mod.ProjectNotFoundError as exc:
        console.error(console.esc(exc))
        raise typer.Exit(code=1) from exc
    except source_resolver.IngestSourceError as exc:
        console.error(f"Fuente de ingestión inválida: {console.esc(exc)}")
        raise typer.Exit(code=1) from exc
    except (FileNotFoundError, NotADirectoryError) as exc:
        console.error(console.esc(exc))
        raise typer.Exit(code=1) from exc
    except ValueError as exc:
        console.error(f"Error de configuración: {console.esc(exc)}")
        raise typer.Exit(code=1) from exc

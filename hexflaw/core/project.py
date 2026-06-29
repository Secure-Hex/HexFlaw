"""Detección y carga del proyecto desde el CWD (CLAUDE.md §14).

Análogo a git: busca ``.hexflaw/`` en el directorio actual y sube por los
padres hasta encontrarlo. Si no encuentra ninguno, lanza un error claro
indicando que se debe correr ``hexflaw init`` primero.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from hexflaw.core.models import ProjectMetadata
from hexflaw.infrastructure import storage

HEXFLAW_DIR = ".hexflaw"


class ProjectNotFoundError(RuntimeError):
    """Se lanza cuando no existe ``.hexflaw/`` en el CWD ni en sus padres."""


class ProjectExistsError(RuntimeError):
    """Se lanza al intentar ``init`` sobre un directorio ya inicializado."""


@dataclass(frozen=True)
class Project:
    """Proyecto HexFlaw activo, anclado a un directorio de trabajo.

    Attributes:
        root: Directorio de trabajo (el que contiene ``.hexflaw/``).
        metadata: Metadata cargada de ``.hexflaw/metadata.json``.
    """

    root: Path
    metadata: ProjectMetadata

    @property
    def hexflaw_dir(self) -> Path:
        """Ruta al directorio de datos ``.hexflaw/`` del proyecto."""
        return self.root / HEXFLAW_DIR

    @property
    def findings_path(self) -> Path:
        """Ruta a ``findings.json``."""
        return self.hexflaw_dir / "findings.json"

    @property
    def file_hashes_path(self) -> Path:
        """Ruta a ``file_hashes.json``."""
        return self.hexflaw_dir / "file_hashes.json"

    @property
    def chunks_path(self) -> Path:
        """Ruta al artefacto de chunks de ingestión."""
        return self.hexflaw_dir / "chunks.json"

    def save_metadata(self) -> None:
        """Persiste la metadata actual a disco con permisos ``600``."""
        data = self.metadata.model_dump(mode="json")
        storage.write_json(self.hexflaw_dir / "metadata.json", data)


def find_project_root(start: Path | None = None) -> Path:
    """Busca la raíz del proyecto subiendo por los directorios padre.

    Args:
        start: Directorio desde donde comenzar la búsqueda (default: CWD).

    Returns:
        El directorio que contiene ``.hexflaw/``.

    Raises:
        ProjectNotFoundError: Si no se encuentra en el CWD ni en ningún padre.
    """
    current = (start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        if (candidate / HEXFLAW_DIR).is_dir():
            return candidate
    raise ProjectNotFoundError(
        "No se encontró un proyecto HexFlaw (.hexflaw/) en este directorio "
        "ni en sus padres. Ejecuta 'hexflaw init' primero."
    )


def load_project(start: Path | None = None) -> Project:
    """Detecta y carga el proyecto activo desde el CWD.

    Args:
        start: Directorio desde donde comenzar la búsqueda (default: CWD).

    Returns:
        Proyecto cargado con su metadata.

    Raises:
        ProjectNotFoundError: Si no hay proyecto inicializado.
    """
    root = find_project_root(start)
    meta_path = root / HEXFLAW_DIR / "metadata.json"
    metadata = ProjectMetadata.model_validate(storage.read_json(meta_path))
    return Project(root=root, metadata=metadata)


def init_project(root: Path, name: str | None = None) -> Project:
    """Inicializa un nuevo proyecto en ``root`` creando ``.hexflaw/``.

    Args:
        root: Directorio de trabajo a inicializar.
        name: Nombre descriptivo opcional (default: nombre del directorio).

    Returns:
        El proyecto recién creado.

    Raises:
        ProjectExistsError: Si ``root`` ya contiene un ``.hexflaw/``.
    """
    root = root.resolve()
    hexflaw_dir = root / HEXFLAW_DIR
    if hexflaw_dir.exists():
        raise ProjectExistsError(
            f"El directorio ya está inicializado como proyecto HexFlaw: {hexflaw_dir}"
        )

    storage.ensure_dir(hexflaw_dir)
    metadata = ProjectMetadata(
        project_id=str(uuid.uuid4()),
        name=name or root.name,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    project = Project(root=root, metadata=metadata)
    project.save_metadata()
    return project

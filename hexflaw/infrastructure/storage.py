"""Persistencia en disco con permisos estrictos (CLAUDE.md §15, Infrastructure).

Escribe JSON con permisos restrictivos por diseño:
- Directorios sensibles: ``700``
- Archivos sensibles (config, code_graph, findings): ``600``

En plataformas sin soporte POSIX de permisos (Windows) el ``chmod`` es no-op,
lo cual es aceptable: la garantía dura es en Linux/macOS, el target primario.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from hexflaw.infrastructure.logging import get_logger

logger = get_logger(__name__)

DIR_MODE = 0o700
FILE_MODE = 0o600


def ensure_dir(path: Path, mode: int = DIR_MODE) -> Path:
    """Crea un directorio (y padres) con permisos restrictivos.

    Args:
        path: Directorio a crear.
        mode: Permisos POSIX a aplicar (default ``700``).

    Returns:
        El mismo ``path``, ya creado.
    """
    path.mkdir(parents=True, exist_ok=True)
    _chmod(path, mode)
    return path


def write_json(path: Path, data: Any, mode: int = FILE_MODE) -> None:
    """Escribe ``data`` como JSON con permisos restrictivos.

    La escritura es atómica (archivo temporal + ``os.replace``) para evitar
    estados parciales si el proceso muere a mitad.

    Args:
        path: Ruta destino.
        data: Estructura serializable a JSON.
        mode: Permisos POSIX del archivo resultante (default ``600``).
    """
    ensure_dir(path.parent)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False, default=str)
    _chmod(tmp, mode)
    os.replace(tmp, path)
    logger.debug("Wrote JSON to %s", path)


def read_json(path: Path) -> Any:
    """Lee y parsea un archivo JSON.

    Args:
        path: Ruta del archivo a leer.

    Returns:
        Estructura deserializada.

    Raises:
        FileNotFoundError: Si el archivo no existe.
        json.JSONDecodeError: Si el contenido no es JSON válido.
    """
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _chmod(path: Path, mode: int) -> None:
    """Aplica permisos POSIX, tolerando plataformas sin soporte."""
    try:
        os.chmod(path, mode)
    except (NotImplementedError, OSError) as exc:  # Windows / FS exótico
        logger.debug("chmod no aplicado en %s: %s", path, exc)

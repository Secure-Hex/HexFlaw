"""Persistencia del system profile con integridad (CLAUDE.md §6 M0, §15 T-M0-2).

Almacena ``~/.hexflaw/system_profile.json`` y un sidecar con su SHA-256 para
detectar modificaciones externas en runs subsiguientes.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from hexflaw.core.models import SystemProfile
from hexflaw.infrastructure import storage
from hexflaw.infrastructure.config import global_home
from hexflaw.infrastructure.logging import get_logger

logger = get_logger(__name__)


def _paths() -> tuple[Path, Path]:
    home = global_home()
    return home / "system_profile.json", home / "system_profile.integrity.json"


def save_profile(profile: SystemProfile) -> None:
    """Persiste el system profile y su sidecar de integridad.

    Args:
        profile: Perfil a guardar.
    """
    storage.ensure_dir(global_home())
    profile_path, integrity_path = _paths()
    payload = profile.model_dump(mode="json")
    serialized = json.dumps(payload, sort_keys=True, default=str)
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    storage.write_json(profile_path, payload)
    storage.write_json(integrity_path, {"sha256": digest})
    logger.debug("system_profile.json persistido (sha256=%s)", digest[:12])


def load_profile() -> SystemProfile | None:
    """Carga el system profile verificando integridad.

    Returns:
        El perfil si existe y es íntegro; ``None`` si falta o fue manipulado.
    """
    profile_path, integrity_path = _paths()
    if not (profile_path.exists() and integrity_path.exists()):
        return None
    try:
        payload = storage.read_json(profile_path)
        integrity = storage.read_json(integrity_path)
    except (ValueError, OSError) as exc:
        logger.warning("No se pudo leer system_profile: %s", exc)
        return None

    serialized = json.dumps(payload, sort_keys=True, default=str)
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    if digest != integrity.get("sha256"):
        logger.warning("Integridad de system_profile.json comprometida (T-M0-2)")
        return None
    return SystemProfile.model_validate(payload)

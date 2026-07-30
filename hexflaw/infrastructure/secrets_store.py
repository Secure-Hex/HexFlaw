"""Almacenamiento de API keys en el keyring del SO (CLAUDE.md §15, T-INFRA-1).

Las API keys NO deben vivir en texto plano en disco. Este módulo las guarda en el
keyring del sistema (Keychain en macOS, Secret Service en Linux, Credential
Manager en Windows) vía la librería ``keyring``.

``keyring`` es una dependencia opcional (extra ``secrets``). Si no está instalada
—o no hay un backend usable, p.ej. un servidor headless sin Secret Service— las
funciones degradan limpio: :func:`available` devuelve ``False`` y el caller cae al
fallback documentado (``config.json`` con permisos ``600`` y una advertencia).
"""

from __future__ import annotations

from typing import Any

from hexflaw.infrastructure.logging import get_logger

logger = get_logger(__name__)

#: Nombre de servicio bajo el que se agrupan los secretos en el keyring.
_SERVICE = "hexflaw"

#: Claves de config que son secretos (se almacenan en keyring, nunca en JSON).
SECRET_KEYS = ("anthropic_api_key", "voyage_api_key", "openai_api_key")


def _keyring() -> Any:
    """Importa ``keyring`` de forma perezosa; ``None`` si no está instalada."""
    try:
        import keyring
    except ImportError:
        return None
    return keyring


def available() -> bool:
    """Indica si hay un keyring usable (instalado y con backend real).

    Un backend ``fail`` (el que keyring elige cuando no hay ninguno disponible) se
    considera no usable.
    """
    kr = _keyring()
    if kr is None:
        return False
    try:
        backend = kr.get_keyring()
        from keyring.backends.fail import Keyring as FailKeyring

        return not isinstance(backend, FailKeyring)
    except Exception as exc:  # backend mal configurado / sin D-Bus / etc.
        logger.debug("keyring no usable: %s", exc)
        return False


def set_secret(key: str, value: str) -> bool:
    """Guarda un secreto en el keyring.

    Returns:
        ``True`` si se almacenó en el keyring; ``False`` si no hay keyring usable
        (el caller debe aplicar el fallback).
    """
    kr = _keyring()
    if kr is None or not available():
        return False
    try:
        kr.set_password(_SERVICE, key, value)
        return True
    except Exception as exc:
        logger.warning("No se pudo escribir el secreto '%s' en el keyring: %s", key, exc)
        return False


def get_secret(key: str) -> str | None:
    """Lee un secreto del keyring, o ``None`` si no hay keyring o no existe."""
    kr = _keyring()
    if kr is None:
        return None
    try:
        value = kr.get_password(_SERVICE, key)
        return str(value) if value is not None else None
    except Exception as exc:
        logger.debug("No se pudo leer el secreto '%s' del keyring: %s", key, exc)
        return None


def delete_secret(key: str) -> None:
    """Elimina un secreto del keyring si existe (no falla si no está)."""
    kr = _keyring()
    if kr is None:
        return
    try:
        kr.delete_password(_SERVICE, key)
    except Exception as exc:
        logger.debug("No se pudo borrar el secreto '%s' del keyring: %s", key, exc)

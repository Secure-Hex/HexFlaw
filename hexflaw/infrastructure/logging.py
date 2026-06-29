"""Logging estructurado con sanitización (CLAUDE.md §15, T-INFRA-3).

Antes de escribir cualquier string al log se eliminan caracteres de control
(ANSI, null bytes, newlines incrustados) para evitar log injection desde el
código analizado.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

# Caracteres de control salvo tab. Incluye CR/LF para evitar inyección de líneas.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\x1b]")


def sanitize_log_value(value: Any) -> str:
    """Limpia un valor para escritura segura en logs.

    Args:
        value: Valor arbitrario a serializar como texto.

    Returns:
        Representación en texto sin caracteres de control ni saltos de línea.
    """
    text = str(value)
    text = text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    return _CONTROL_CHARS.sub("", text)


class _SanitizingFormatter(logging.Formatter):
    """Formatter que sanitiza el mensaje renderizado antes de emitirlo."""

    def format(self, record: logging.LogRecord) -> str:
        rendered = super().format(record)
        return sanitize_log_value(rendered)


def get_logger(name: str) -> logging.Logger:
    """Devuelve un logger configurado con sanitización y nivel desde entorno.

    El nivel se toma de ``HEXFLAW_LOG_LEVEL`` (default INFO). API keys, código
    fuente y taint paths completos solo deben loguearse en DEBUG (CLAUDE.md §15).

    Args:
        name: Nombre del logger (típicamente ``__name__``).

    Returns:
        Logger configurado e idempotente entre llamadas.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    level_name = os.environ.get("HEXFLAW_LOG_LEVEL", "INFO").upper()
    logger.setLevel(getattr(logging, level_name, logging.INFO))

    handler = logging.StreamHandler()
    handler.setFormatter(
        _SanitizingFormatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    logger.addHandler(handler)
    logger.propagate = False
    return logger

"""Secret scanning de snippets antes de escribirlos a reportes (CLAUDE.md §15).

Aplica a M6a/M6b (T-M6a-1): ningún snippet con secretos reales debe quedar en
un reporte. Los matches se reemplazan por ``[REDACTED]``.

Detección por patrones de los tipos más comunes; no pretende ser exhaustivo,
sino una red de seguridad por defecto.
"""

from __future__ import annotations

import re

# (nombre, patrón). El orden importa: los más específicos primero.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("pem_private_key", re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----.*?"
        r"-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
        re.DOTALL,
    )),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("generic_secret_assignment", re.compile(
        r"(?i)\b(password|passwd|secret|api[_-]?key|token|access[_-]?key)\b"
        r"\s*[:=]\s*['\"]?[^\s'\"]{6,}['\"]?"
    )),
]

_REDACTED = "[REDACTED]"


def redact_secrets(text: str) -> tuple[str, list[str]]:
    """Redacta secretos detectados en ``text``.

    Args:
        text: Contenido (típicamente un snippet de código) a sanear.

    Returns:
        Tupla ``(texto_redactado, tipos_detectados)``. ``tipos_detectados`` lista
        los nombres de patrón que coincidieron (para logging/auditoría).
    """
    detected: list[str] = []
    result = text
    for name, pattern in _PATTERNS:
        if pattern.search(result):
            if name == "generic_secret_assignment":
                # Conserva la clave, redacta solo el valor.
                result = pattern.sub(_redact_assignment_value, result)
            else:
                result = pattern.sub(_REDACTED, result)
            detected.append(name)
    return result, detected


def _redact_assignment_value(match: re.Match[str]) -> str:
    """Redacta el valor de una asignación ``clave = valor`` preservando la clave."""
    whole = match.group(0)
    sep_idx = max(whole.find("="), whole.find(":"))
    if sep_idx == -1:
        return _REDACTED
    return f"{whole[:sep_idx + 1]} {_REDACTED}"

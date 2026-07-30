"""Política de selección de modelo por tarea (CLAUDE.md §16, estrategias 5 y 6).

Aplica el modelo más barato suficiente para cada tarea, escalando a Opus solo
donde su razonamiento profundo lo justifica. La selección depende del modo de
análisis (``thorough`` | ``balanced`` | ``economy``) y de la severidad cuando
aplica.

Centralizar esto evita hardcodear modelos en los módulos (CLAUDE.md §2.2).
"""

from __future__ import annotations

from enum import Enum

from hexflaw.core.models import AnalysisMode, Severity

HAIKU = "claude-haiku-4-5-20251001"
SONNET = "claude-sonnet-4-6"
OPUS = "claude-opus-4-8"


class Task(str, Enum):
    """Tareas del pipeline que consumen LLM, con perfil de complejidad distinto."""

    STATIC_SIMPLE = "static_simple"
    TARGET_DISCOVERY = "target_discovery"
    TAINT = "taint"
    ROOTCAUSE = "rootcause"
    POC = "poc"


# Tabla base por modo (CLAUDE.md §16, estrategia 6). Severidad refina ROOTCAUSE/POC.
_POLICY: dict[AnalysisMode, dict[Task, str]] = {
    AnalysisMode.THOROUGH: {
        Task.STATIC_SIMPLE: SONNET,
        Task.TARGET_DISCOVERY: OPUS,
        Task.TAINT: OPUS,
        Task.ROOTCAUSE: OPUS,
        Task.POC: OPUS,
    },
    AnalysisMode.BALANCED: {
        Task.STATIC_SIMPLE: HAIKU,
        Task.TARGET_DISCOVERY: OPUS,
        Task.TAINT: OPUS,
        Task.ROOTCAUSE: SONNET,
        Task.POC: SONNET,
    },
    AnalysisMode.ECONOMY: {
        Task.STATIC_SIMPLE: HAIKU,
        Task.TARGET_DISCOVERY: SONNET,
        Task.TAINT: SONNET,
        Task.ROOTCAUSE: SONNET,
        Task.POC: SONNET,
    },
}

# Tareas donde Critical/High escalan a Opus salvo en economy (§16 estrategia 5).
_SEVERITY_SENSITIVE = {Task.ROOTCAUSE, Task.POC}


def choose_model(
    task: Task,
    mode: AnalysisMode = AnalysisMode.BALANCED,
    severity: Severity | None = None,
    *,
    exhaustive: bool = False,
) -> str:
    """Selecciona el modelo para una tarea según modo y severidad.

    Args:
        task: Tarea del pipeline.
        mode: Modo de análisis activo.
        severity: Severidad del hallazgo (relevante en root cause / PoC).
        exhaustive: Si ``True``, usa Opus en TODAS las tareas (modo ``--exhaustive``:
            máxima capacidad sin importar el costo).

    Returns:
        Identificador del modelo de Anthropic a usar.
    """
    if exhaustive:
        return OPUS
    base = _POLICY[mode][task]
    if (
        task in _SEVERITY_SENSITIVE
        and mode != AnalysisMode.ECONOMY
        and severity in (Severity.CRITICAL, Severity.HIGH)
    ):
        return OPUS
    return base

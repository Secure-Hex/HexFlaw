"""Política de selección de modelo por tarea (CLAUDE.md §16, estrategias 5 y 6).

Aplica el modelo más barato suficiente para cada tarea, escalando al tier profundo
solo donde su razonamiento lo justifica. La selección depende del modo de análisis
(``thorough`` | ``balanced`` | ``economy``) y de la severidad cuando aplica.

**Lo que se elige acá es un tier, no un modelo.** El core no conoce el catálogo de
ningún proveedor: decide cuánta capacidad necesita la tarea, y cada backend traduce
ese tier al modelo concreto que tenga configurado (ver
:meth:`hexflaw.services.llm_service.LLMService._resolve_model`).

Antes esta capa devolvía directamente un id de Anthropic y el tier quedaba implícito
dentro de ese string, lo que obligaba al backend de OpenAI a recuperarlo por
substring (``"opus" in model``). Un modelo cuyo nombre no llevara la palabra correcta
caía al tier del medio en silencio: un mapeo por casualidad léxica, no por contrato.
"""

from __future__ import annotations

from enum import Enum

from hexflaw.core.models import AnalysisMode, Severity


class ModelTier(str, Enum):
    """Cuánta capacidad de razonamiento necesita una tarea.

    Los nombres son neutrales al proveedor a propósito: son el contrato entre el
    pipeline y el backend, y el pipeline no debe saber si abajo hay Claude, GPT o
    un agente humano en el loop.
    """

    CHEAP = "cheap"
    """Decisiones binarias y patrones directos (screening, análisis simple)."""

    MID = "mid"
    """Análisis estándar con contexto suficiente (reportes, root cause predecible)."""

    DEEP = "deep"
    """Razonamiento multi-paso sobre información dispersa (taint, discovery)."""


class Task(str, Enum):
    """Tareas del pipeline que consumen LLM, con perfil de complejidad distinto."""

    STATIC_SIMPLE = "static_simple"
    TARGET_DISCOVERY = "target_discovery"
    TAINT = "taint"
    ROOTCAUSE = "rootcause"
    POC = "poc"


# Tabla base por modo (CLAUDE.md §16, estrategia 6). Severidad refina ROOTCAUSE/POC.
_POLICY: dict[AnalysisMode, dict[Task, ModelTier]] = {
    AnalysisMode.THOROUGH: {
        Task.STATIC_SIMPLE: ModelTier.MID,
        Task.TARGET_DISCOVERY: ModelTier.DEEP,
        Task.TAINT: ModelTier.DEEP,
        Task.ROOTCAUSE: ModelTier.DEEP,
        Task.POC: ModelTier.DEEP,
    },
    AnalysisMode.BALANCED: {
        Task.STATIC_SIMPLE: ModelTier.CHEAP,
        Task.TARGET_DISCOVERY: ModelTier.DEEP,
        Task.TAINT: ModelTier.DEEP,
        Task.ROOTCAUSE: ModelTier.MID,
        Task.POC: ModelTier.MID,
    },
    AnalysisMode.ECONOMY: {
        Task.STATIC_SIMPLE: ModelTier.CHEAP,
        Task.TARGET_DISCOVERY: ModelTier.MID,
        Task.TAINT: ModelTier.MID,
        Task.ROOTCAUSE: ModelTier.MID,
        Task.POC: ModelTier.MID,
    },
}

# Tareas donde Critical/High escalan al tier profundo salvo en economy (§16 est. 5).
_SEVERITY_SENSITIVE = {Task.ROOTCAUSE, Task.POC}


def choose_model(
    task: Task,
    mode: AnalysisMode = AnalysisMode.BALANCED,
    severity: Severity | None = None,
    *,
    exhaustive: bool = False,
) -> ModelTier:
    """Selecciona el tier de modelo para una tarea según modo y severidad.

    Args:
        task: Tarea del pipeline.
        mode: Modo de análisis activo.
        severity: Severidad del hallazgo (relevante en root cause / PoC).
        exhaustive: Si ``True``, usa el tier profundo en TODAS las tareas (modo
            ``--exhaustive``: máxima capacidad sin importar el costo).

    Returns:
        El tier a usar. El backend activo lo traduce al modelo concreto.
    """
    if exhaustive:
        return ModelTier.DEEP
    base = _POLICY[mode][task]
    if (
        task in _SEVERITY_SENSITIVE
        and mode != AnalysisMode.ECONOMY
        and severity in (Severity.CRITICAL, Severity.HIGH)
    ):
        return ModelTier.DEEP
    return base


def tasks_by_tier(mode: AnalysisMode = AnalysisMode.BALANCED) -> dict[ModelTier, list[Task]]:
    """Agrupa las tareas por el tier que les toca en un modo dado.

    Lo usa ``hexflaw models list`` para responder la pregunta que importa antes de
    cambiar un modelo: qué parte del pipeline se ve afectada.

    Args:
        mode: Modo de análisis a consultar.

    Returns:
        ``{tier: [tareas]}`` con las tareas en el orden de :class:`Task`.
    """
    grouped: dict[ModelTier, list[Task]] = {tier: [] for tier in ModelTier}
    for task in Task:
        grouped[_POLICY[mode][task]].append(task)
    return grouped

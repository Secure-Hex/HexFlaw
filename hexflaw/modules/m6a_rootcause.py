"""M6a — Root Cause Analysis (CLAUDE.md §6 M6a, §15 M6a).

Por cada hallazgo confirmado, el LLM genera causa raíz, archivos/líneas
afectadas, blast radius, CVSS v3.1 y remediación sugerida. El modelo se elige
por severidad (Critical/High → Opus) vía :mod:`hexflaw.core.model_policy`.

Defensa: los snippets que llegan a los artefactos pasarán por secret scanning
en M6b/M6c; aquí se conserva el código tal cual para el análisis del LLM.
"""

from __future__ import annotations

import json
from typing import Any

from hexflaw.core.model_policy import Task, choose_model
from hexflaw.core.models import (
    AnalysisMode,
    CodeGraph,
    Finding,
    IngestionResult,
    PoCConfidence,
    RootCause,
    Severity,
)
from hexflaw.infrastructure.logging import get_logger
from hexflaw.modules.m4_static import _extract_json_object
from hexflaw.services.llm_service import LLMService, LLMServiceError

logger = get_logger(__name__)

_INSTRUCTION = (
    "Eres un analista senior de seguridad. Para el hallazgo confirmado, genera un "
    "análisis de causa raíz. Responde SOLO JSON con esta forma exacta:\n"
    '{"summary": "<riesgo en lenguaje de negocio, sin código>", '
    '"root_cause": "<por qué existe, no solo el síntoma>", '
    '"blast_radius": "<qué más se ve afectado si se explota>", '
    '"cvss_vector": "<vector CVSS v3.1>", "cvss_score": <0..10>, '
    '"severity": "critical|high|medium|low", '
    '"remediation_summary": "<acción recomendada no técnica>", '
    '"vulnerable_code": "<línea(s) vulnerable(s)>", '
    '"fixed_code": "<código corregido sugerido>", '
    '"poc_confidence": "high_confidence|medium_confidence|requires_manual_tuning", '
    '"llm_confidence": <0..1>}'
)


def analyze_root_cause(
    finding: Finding,
    ingestion: IngestionResult,
    graph: CodeGraph,
    llm: LLMService,
    *,
    mode: AnalysisMode = AnalysisMode.BALANCED,
) -> RootCause:
    """Genera el root cause de un hallazgo confirmado.

    Args:
        finding: Hallazgo confirmado/condicional.
        ingestion: Resultado de M1 (para recuperar el código del nodo).
        graph: Code graph de M3 (para archivos afectados y blast radius).
        llm: Servicio LLM inyectado.
        mode: Modo de análisis (afecta la selección de modelo).

    Returns:
        :class:`RootCause` con todos los campos completos (best-effort si el LLM
        falla, devuelve un esqueleto con la info determinística disponible).
    """
    node_code = _node_code(finding, ingestion)
    model = choose_model(Task.ROOTCAUSE, mode, finding.severity)
    affected_lines = _affected_lines(finding)
    affected_files = sorted({finding.file, *(s.file for s in finding.taint_path)})

    fallback = RootCause(
        finding_id=finding.id,
        type=finding.type,
        affected_files=affected_files,
        affected_lines=affected_lines,
        severity=finding.severity or Severity.MEDIUM,
        vulnerable_code=finding.snippet,
        llm_confidence=finding.confidence,
    )

    try:
        response = llm.analyze_code(_INSTRUCTION, node_code, model=model)
    except LLMServiceError as exc:
        logger.error("[%s] fallo LLM en root cause: %s", finding.id, exc)
        return fallback

    data = _parse(response.text)
    if not data:
        return fallback

    return RootCause(
        finding_id=finding.id,
        type=finding.type,
        summary=str(data.get("summary", "")),
        root_cause=str(data.get("root_cause", "")),
        affected_files=affected_files,
        affected_lines=affected_lines,
        blast_radius=str(data.get("blast_radius", "")),
        cvss_vector=str(data.get("cvss_vector", "")),
        cvss_score=_clamp_score(data.get("cvss_score")),
        severity=_severity(data.get("severity"), finding.severity),
        remediation_summary=str(data.get("remediation_summary", "")),
        vulnerable_code=str(data.get("vulnerable_code", "")) or finding.snippet,
        fixed_code=str(data.get("fixed_code", "")),
        poc_confidence=_poc_confidence(data.get("poc_confidence")),
        llm_confidence=_clamp_unit(data.get("llm_confidence", finding.confidence)),
    )


def _node_code(finding: Finding, ingestion: IngestionResult) -> str:
    """Recupera el código del chunk asociado al hallazgo."""
    for chunk in ingestion.chunks:
        if chunk.file == finding.file and (
            chunk.name == finding.function
            or chunk.line_start <= finding.line <= chunk.line_end
        ):
            return chunk.code
    return finding.snippet


def _affected_lines(finding: Finding) -> list[str]:
    """Construye referencias 'archivo:línea' a partir del hallazgo y su path."""
    lines = [f"{finding.file}:{finding.line}"]
    return lines


def _parse(text: str) -> dict[str, Any]:
    candidate = _extract_json_object(text)
    if candidate is None:
        return {}
    try:
        data = json.loads(candidate)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _clamp_score(value: object) -> float:
    try:
        return max(0.0, min(10.0, float(value)))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0


def _clamp_unit(value: object) -> float:
    try:
        return max(0.0, min(1.0, float(value)))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0


def _severity(value: object, fallback: Severity | None) -> Severity:
    try:
        return Severity(str(value).lower())
    except ValueError:
        return fallback or Severity.MEDIUM


def _poc_confidence(value: object) -> PoCConfidence:
    try:
        return PoCConfidence(str(value))
    except ValueError:
        return PoCConfidence.MANUAL

"""M2 — Target Definition (CLAUDE.md §6 M2).

Modo *directed*: el usuario especifica la funcionalidad a analizar; el módulo
arma la superficie de ataque y el perfil de vulnerabilidades a partir de los
lenguajes presentes y de heurísticas sobre los chunks ingeridos.

Modo *discovery*: el LLM analiza el inventario de funciones del codebase y
propone la superficie de ataque más riesgosa (target, attack_surface,
vuln_profile, entry_points). Ante fallo del LLM cae a un target global
determinístico. Ambos modos devuelven :class:`TargetDefinition` con su ``mode``.
"""

from __future__ import annotations

import json
from typing import Any

from hexflaw.core.models import EntryPoint, IngestionResult, TargetDefinition
from hexflaw.infrastructure.logging import get_logger
from hexflaw.services.language_service import LanguageService
from hexflaw.services.llm_service import LLMService, LLMServiceError

logger = get_logger(__name__)

_DISCOVERY_INSTRUCTION = (
    "Eres un pentester. A partir del inventario de funciones del codebase, "
    "propón la superficie de ataque más riesgosa a analizar. Considera input "
    "handling, auth, crypto, IPC, network, file ops y command execution. "
    "Responde SOLO JSON: {\"target\": \"<descripción>\", \"attack_surface\": "
    "[\"archivo1\", ...], \"vuln_profile\": [\"command_injection\", ...], "
    "\"entry_points\": [{\"file\": \"...\", \"function\": \"...\", \"type\": "
    "\"user_input\"}]}."
)


def define_target_directed(
    target: str,
    ingestion: IngestionResult,
    languages_service: LanguageService,
) -> TargetDefinition:
    """Construye la definición de target en modo directed.

    Args:
        target: Descripción de la funcionalidad a analizar (texto libre).
        ingestion: Resultado de M1.
        languages_service: Servicio para consultar perfiles de vuln por lenguaje.

    Returns:
        :class:`TargetDefinition` con superficie de ataque, perfil de vulns y
        puntos de entrada heurísticos.
    """
    vuln_profile: set[str] = set()
    entry_patterns: list[tuple[str, str]] = []  # (language_id, pattern)
    for lang_id in ingestion.languages:
        definition = languages_service.get(lang_id)
        if definition is None:
            continue
        vuln_profile.update(definition.vuln_profile)
        entry_patterns.extend((lang_id, p) for p in definition.entry_point_patterns)

    attack_surface = sorted({entry.path for entry in ingestion.file_map})
    entry_points = _heuristic_entry_points(ingestion, entry_patterns)

    logger.info(
        "Target directed: '%s' | superficie=%d archivos | vuln_profile=%s",
        target,
        len(attack_surface),
        sorted(vuln_profile),
    )
    return TargetDefinition(
        target_confirmed=target,
        attack_surface=attack_surface,
        vuln_profile=sorted(vuln_profile),
        entry_points=entry_points,
        mode="directed",
    )


def define_target_discovery(
    ingestion: IngestionResult,
    llm: LLMService,
    languages_service: LanguageService,
    *,
    model: str | None = None,
) -> TargetDefinition:
    """Construye la definición de target en modo discovery (propuesta del LLM).

    El LLM analiza el inventario de funciones y propone la superficie de ataque
    más riesgosa. Ante fallo del LLM, cae a un target global determinístico
    equivalente al modo directed sobre todo el codebase.

    Args:
        ingestion: Resultado de M1.
        llm: Servicio LLM inyectado.
        languages_service: Para perfiles de vuln por lenguaje (fallback).
        model: Modelo a usar (Discovery justifica Opus, §16 estrategia 5).

    Returns:
        :class:`TargetDefinition` con ``mode='discovery'``.
    """
    inventory = "\n".join(
        f"{c.file}::{c.name} (L{c.line_start}-{c.line_end})"
        for c in ingestion.chunks[:400]  # acota la superficie de injection (§15)
    )
    try:
        response = llm.analyze_code(_DISCOVERY_INSTRUCTION, inventory, model=model)
        data = _parse_discovery(response.text)
    except LLMServiceError as exc:
        logger.warning("Discovery LLM falló (%s); usando target global", exc)
        data = None

    if not data:
        fallback = define_target_directed(
            "global attack surface", ingestion, languages_service
        )
        return fallback.model_copy(update={"mode": "discovery"})

    entry_points = [
        EntryPoint(
            file=str(ep.get("file", "")),
            function=str(ep.get("function", "")),
            type=str(ep.get("type", "user_input")),
        )
        for ep in data.get("entry_points", [])
        if isinstance(ep, dict)
    ]
    logger.info("Target discovery: %s", data.get("target", ""))
    return TargetDefinition(
        target_confirmed=str(data.get("target", "global attack surface")),
        attack_surface=[str(p) for p in data.get("attack_surface", [])],
        vuln_profile=[str(v) for v in data.get("vuln_profile", [])],
        entry_points=entry_points,
        mode="discovery",
    )


def _parse_discovery(text: str) -> dict[str, Any] | None:
    """Extrae el JSON de la propuesta de discovery, tolerante a ruido."""
    from hexflaw.modules.m4_static import _extract_json_object

    candidate = _extract_json_object(text)
    if candidate is None:
        return None
    try:
        data = json.loads(candidate)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _heuristic_entry_points(
    ingestion: IngestionResult, entry_patterns: list[tuple[str, str]]
) -> list[EntryPoint]:
    """Detecta puntos de entrada por coincidencia de patrones en los chunks."""
    entry_points: list[EntryPoint] = []
    seen: set[tuple[str, str]] = set()
    for chunk in ingestion.chunks:
        for lang_id, pattern in entry_patterns:
            if chunk.language != lang_id:
                continue
            if pattern in chunk.code:
                key = (chunk.file, chunk.name)
                if key in seen:
                    continue
                seen.add(key)
                entry_points.append(
                    EntryPoint(file=chunk.file, function=chunk.name, type="user_input")
                )
                break
    return entry_points

"""Tests del modo discovery de M2."""

from __future__ import annotations

from pathlib import Path

from hexflaw.modules import m1_ingestion, m2_target
from hexflaw.services.language_service import LanguageService
from hexflaw.services.llm_service import LLMResponse, LLMService

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


class DiscoveryLLM(LLMService):
    """Propone una superficie de ataque fija."""

    def __init__(self) -> None:
        super().__init__(api_key="fake")

    def analyze_code(self, instruction: str, code: str, **kwargs: object) -> LLMResponse:
        payload = (
            '{"target": "ping handler", "attack_surface": ["ping.c"], '
            '"vuln_profile": ["command_injection"], '
            '"entry_points": [{"file": "ping.c", "function": "main", "type": "user_input"}]}'
        )
        return LLMResponse(text=payload, model="fake")


def test_discovery_uses_llm_proposal() -> None:
    langs = LanguageService()
    ingestion = m1_ingestion.ingest(FIXTURES / "sample_c", "p", langs)

    target = m2_target.define_target_discovery(ingestion, DiscoveryLLM(), langs)
    assert target.mode == "discovery"
    assert target.target_confirmed == "ping handler"
    assert "command_injection" in target.vuln_profile
    assert any(ep.function == "main" for ep in target.entry_points)


def test_discovery_falls_back_without_api_key() -> None:
    langs = LanguageService()
    ingestion = m1_ingestion.ingest(FIXTURES / "sample_c", "p", langs)

    # LLM real sin key → LLMServiceError → fallback determinístico global.
    target = m2_target.define_target_discovery(ingestion, LLMService(api_key=None), langs)
    assert target.mode == "discovery"
    assert "command_injection" in target.vuln_profile  # del perfil del lenguaje

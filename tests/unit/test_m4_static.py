"""Tests de M4 — Static Analysis con un LLM falso (sin API real)."""

from __future__ import annotations

from pathlib import Path

from hexflaw.core.models import FindingStatus
from hexflaw.modules import m1_ingestion, m2_target, m4_static
from hexflaw.modules.m4_static import _parse_findings, _prefilter
from hexflaw.services.language_service import LanguageService
from hexflaw.services.llm_service import LLMResponse, LLMService

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


class FakeLLM(LLMService):
    """LLMService que devuelve un finding fijo sin llamar a la API."""

    def __init__(self) -> None:
        super().__init__(api_key="fake")
        self.calls = 0

    def analyze_code(self, instruction: str, code: str, **kwargs: object) -> LLMResponse:
        self.calls += 1
        payload = (
            '{"findings": [{"type": "command_injection", "file": "ping.c", '
            '"line": 12, "function": "handle_ping_input", "confidence": 0.9, '
            '"snippet": "system(cmd)", "rationale": "argv llega a system sin sanitizar"}]}'
        )
        return LLMResponse(text=payload, model="fake", input_tokens=10, output_tokens=5)


def test_prefilter_keeps_sink_chunks_drops_inert() -> None:
    langs = LanguageService()
    ingestion = m1_ingestion.ingest(FIXTURES / "sample_python", "p", langs)
    target = m2_target.define_target_directed("util", ingestion, langs)

    kept = _prefilter(ingestion, target, langs)
    # safe_util.py no tiene sinks → ningún chunk debería pasar.
    assert kept == []


def test_analyze_produces_confirmed_shape_finding() -> None:
    langs = LanguageService()
    ingestion = m1_ingestion.ingest(FIXTURES / "sample_c", "p", langs)
    target = m2_target.define_target_directed("ping", ingestion, langs)
    llm = FakeLLM()

    result = m4_static.analyze(ingestion, target, llm, langs, mode="balanced")

    assert llm.calls >= 1
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.type == "command_injection"
    assert finding.status == FindingStatus.PRELIMINARY
    assert finding.id == "F001"
    assert finding.confidence == 0.9


def test_parse_findings_tolerates_fenced_json() -> None:
    text = 'aquí va:\n```json\n{"findings": [{"type": "sqli"}]}\n```\nfin'
    parsed = _parse_findings(text)
    assert parsed == [{"type": "sqli"}]


def test_parse_findings_handles_garbage() -> None:
    assert _parse_findings("no hay json aquí") == []

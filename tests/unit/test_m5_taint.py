"""Tests de M5 — Taint Tracing + Confirmation con un LLM falso."""

from __future__ import annotations

from hexflaw.core.models import CodeGraph, IngestionResult
from pathlib import Path

from hexflaw.core.models import Finding, FindingSet, FindingStatus
from hexflaw.modules import m1_ingestion, m3_graph, m5_taint
from hexflaw.modules.m5_taint import _find_paths_to
from hexflaw.services.language_service import LanguageService
from hexflaw.services.llm_service import LLMResponse, LLMService

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


class ConfirmingLLM(LLMService):
    """Devuelve siempre veredicto 'confirmed'."""

    def __init__(self) -> None:
        super().__init__(api_key="fake")
        self.calls = 0

    def analyze_code(self, instruction: str, code: str, **kwargs: object) -> LLMResponse:
        self.calls += 1
        payload = (
            '{"status": "confirmed", "severity": "high", '
            '"notes": ["argv entra sin sanitizar", "se pasa a system() vía sprintf"]}'
        )
        return LLMResponse(text=payload, model="fake")


def _setup() -> tuple[IngestionResult, CodeGraph]:
    langs = LanguageService()
    ingestion = m1_ingestion.ingest(FIXTURES / "sample_c", "p", langs)
    graph = m3_graph.build_graph(ingestion, langs)
    return ingestion, graph


def test_paths_from_entry_to_sink() -> None:
    ingestion, graph = _setup()
    sink = next(n for n in graph.nodes if n.name == "handle_ping_input")
    paths = _find_paths_to(sink.id, graph)
    assert paths
    # Debe existir un path que arranca en un entry point (main).
    main_id = next(n.id for n in graph.nodes if n.name == "main")
    assert any(p[0] == main_id and p[-1] == sink.id for p in paths)


def test_confirm_marks_reachable_finding_confirmed() -> None:
    ingestion, graph = _setup()
    finding = Finding(
        id="F001",
        type="command_injection",
        file="ping.c",
        line=12,
        function="handle_ping_input",
        confidence=0.9,
        status=FindingStatus.PRELIMINARY,
    )
    prelim = FindingSet(project_id="p", findings=[finding])
    llm = ConfirmingLLM()

    result = m5_taint.confirm(prelim, graph, ingestion, llm)
    out = result.findings[0]
    assert llm.calls == 1
    assert out.status == FindingStatus.CONFIRMED
    assert out.severity is not None and out.severity.value == "high"
    assert len(out.taint_path) >= 1
    assert out.taint_path[0].function in {"main", "handle_ping_input"}


def test_no_path_still_consults_llm() -> None:
    ingestion, graph = _setup()
    # Sin entry points no hay call path; el grafo heurístico es incompleto, así
    # que M5 NO debe auto-descartar: evalúa el código con el LLM igual.
    graph.entry_points = []
    finding = Finding(
        id="F001",
        type="command_injection",
        file="ping.c",
        line=12,
        function="handle_ping_input",
        snippet="system(cmd)",
        status=FindingStatus.PRELIMINARY,
    )
    prelim = FindingSet(project_id="p", findings=[finding])
    llm = ConfirmingLLM()

    result = m5_taint.confirm(prelim, graph, ingestion, llm)
    assert llm.calls == 1  # se consulta al LLM aunque no haya path
    # El veredicto proviene del LLM (aquí confirma), no de la topología del grafo.
    assert result.findings[0].status == FindingStatus.CONFIRMED

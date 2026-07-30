"""Tests del historial de runs, needs_review y re-check de M5."""

from __future__ import annotations

from pathlib import Path

from hexflaw.core.models import CodeGraph, Finding, FindingSet, FindingStatus, IngestionResult
from hexflaw.infrastructure.runs import RunStore, new_run_id
from hexflaw.modules import m1_ingestion, m3_graph, m5_taint
from hexflaw.services.language_service import LanguageService
from hexflaw.services.llm_service import LLMResponse, LLMService

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _finding(fid: str = "F001") -> Finding:
    return Finding(
        id=fid,
        type="command_injection",
        file="ping.c",
        line=12,
        function="handle_ping_input",
        snippet="system(cmd)",
        status=FindingStatus.PRELIMINARY,
    )


# --------------------------- historial de runs --------------------------- #
def test_run_store_archives_and_lists(tmp_path: Path) -> None:
    store = RunStore(tmp_path)
    fs = FindingSet(project_id="p", findings=[_finding()])
    rid1 = new_run_id()
    store.save_run(rid1, fs, {"created_at": "2026-01-01T00:00:00", "target": "a"})
    rid2 = new_run_id()
    store.save_run(rid2, fs, {"created_at": "2026-01-02T00:00:00", "target": "b"})

    runs = store.list_runs()
    assert len(runs) == 2
    assert store.latest_id() == rid2
    assert runs[0]["run_id"] == rid2  # más reciente primero
    loaded = store.load_run(rid1)
    assert loaded.findings[0].id == "F001"


def test_run_ids_are_unique() -> None:
    assert new_run_id() != new_run_id()


# ----------------------------- needs_review ------------------------------ #
class AmbiguousLLM(LLMService):
    """Devuelve un veredicto con status no clasificable."""

    def __init__(self) -> None:
        super().__init__(api_key="fake")

    def analyze_code(self, i: str, c: str, **k: object) -> LLMResponse:  # type: ignore[override]
        return LLMResponse(text='{"status": "maybe", "notes": ["unclear"]}', model="x")


def _setup() -> tuple[IngestionResult, CodeGraph]:
    langs = LanguageService()
    ing = m1_ingestion.ingest(FIXTURES / "sample_c", "p", langs)
    graph = m3_graph.build_graph(ing, langs)
    return ing, graph


def test_ambiguous_verdict_becomes_needs_review() -> None:
    ing, graph = _setup()
    prelim = FindingSet(project_id="p", findings=[_finding()])
    result = m5_taint.confirm(prelim, graph, ing, AmbiguousLLM())
    out = result.findings[0]
    assert out.status == FindingStatus.NEEDS_REVIEW
    assert out.review_reason  # explica por qué


class FailingLLM(LLMService):
    """Sin API key real → la llamada lanza LLMServiceError."""

    def __init__(self) -> None:
        super().__init__(api_key=None)


def test_llm_error_becomes_needs_review() -> None:
    ing, graph = _setup()
    prelim = FindingSet(project_id="p", findings=[_finding()])
    result = m5_taint.confirm(prelim, graph, ing, FailingLLM())
    out = result.findings[0]
    assert out.status == FindingStatus.NEEDS_REVIEW
    assert "no pudo evaluar" in out.review_reason.lower()

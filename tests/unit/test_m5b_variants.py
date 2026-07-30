"""Tests de M5b — Variant Hunting (hexflaw/modules/m5b_variants.py).

Se mockean M4 y M5 (testeados aparte) para verificar SOLO la orquestación de
M5b: selección de vecinos por coseno, delegación del filtro de sink a M4,
etiquetado de ``variant_of`` y convergencia del loop iterativo.
"""

from __future__ import annotations

import pytest

import hashlib
from pathlib import Path

from hexflaw.core.models import (
    CodeChunk,
    CodeGraph,
    Finding,
    FindingSet,
    FindingStatus,
    IngestionResult,
    TargetDefinition,
)
from hexflaw.infrastructure.analysis_cache import AnalysisCache
from hexflaw.modules import m4_static, m5_taint, m5b_variants
from hexflaw.services.embedding.base import EmbeddingService
from hexflaw.services.language_service import LanguageService
from hexflaw.services.llm_service import LLMService


class _FakeEmbedding(EmbeddingService):
    """Embedding determinístico: vector fijo por hash de código (via tabla)."""

    def __init__(self, table: dict[str, list[float]]) -> None:
        self._table = table

    def embed(self, code: str) -> list[float]:
        return self._table[code]

    def embed_batch(self, chunks: list[str]) -> list[list[float]]:
        return [self._table[c] for c in chunks]


def _chunk(name: str, code: str, line: int) -> CodeChunk:
    return CodeChunk(
        id=f"c_{name}",
        file=f"src/{name}.c",
        language="c",
        name=name,
        code=code,
        line_start=line,
        line_end=line + 3,
        hash=hashlib.sha256(code.encode()).hexdigest(),
    )


def test_hunts_twin_with_sink_and_converges(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A = semilla (RCE), B = gemelo cercano CON sink, C = cercano SIN sink.
    a = _chunk("a", "void a(char*x){ system(x); }", 10)
    b = _chunk("b", "void b(char*y){ int r = system(y); }", 20)
    c = _chunk("c", "int c(int n){ return n + 1; }", 30)
    ingestion = IngestionResult(project_id="p1", languages=["c"], chunks=[a, b, c])

    # A, B y C todos cercanos en el espacio (coseno > 0.9): la vecindad no basta
    # para descartar C — quien lo descarta es el pre-filtro de sink de M4.
    embedding = _FakeEmbedding(
        {a.code: [1.0, 0.0], b.code: [0.98, 0.05], c.code: [0.97, 0.08]}
    )

    seed = Finding(
        id="F001", type="command_injection", file=a.file, line=11,
        function="a", status=FindingStatus.CONFIRMED,
    )
    seed_set = FindingSet(project_id="p1", findings=[seed])

    # M4-fake = capa-1 (tiene sink) + clasificación: marca preliminary solo los
    # chunks del recorte cuyo código contiene "system".
    def fake_m4(
        recorte: IngestionResult,
        target: TargetDefinition,
        llm: object,
        languages: object,
        **kw: object,
    ) -> FindingSet:
        found = [
            Finding(
                id=f"P_{ch.name}", type="command_injection",
                file=ch.file, line=ch.line_start, function=ch.name,
                status=FindingStatus.PRELIMINARY,
            )
            for ch in recorte.chunks
            if "system" in ch.code
        ]
        return FindingSet(project_id=recorte.project_id, findings=found)

    # M5-fake = confirma todo lo preliminar que reciba.
    def fake_m5(
        prelim: FindingSet,
        graph: CodeGraph,
        ingestion: IngestionResult,
        llm: object,
        **kw: object,
    ) -> FindingSet:
        for f in prelim.findings:
            f.status = FindingStatus.CONFIRMED
        return prelim

    monkeypatch.setattr(m4_static, "analyze", fake_m4)
    monkeypatch.setattr(m5_taint, "confirm", fake_m5)

    result = m5b_variants.hunt_variants(
        seed_set, ingestion, TargetDefinition(target_confirmed="ping",
        vuln_profile=["command_injection"]), CodeGraph(project_id="p1"), embedding,
        llm=LLMService(api_key="fake"), languages=LanguageService(), cache=AnalysisCache(tmp_path),
        min_similarity=0.9, top_k=10,
    )

    variants = result.findings
    # (a) se cazó la gemela B aunque no estaba en los findings de M4.
    assert [v.file for v in variants] == [b.file]
    # (b) confirmada y trazada a la semilla.
    assert variants[0].status == FindingStatus.CONFIRMED
    assert variants[0].variant_of == "F001"
    # (c) C (cercano pero sin sink) lo filtró M4-capa1: no aparece.
    assert all(v.file != c.file for v in variants)
    # (d) converge (no loop infinito): retornó, y no re-propuso A/B/C.
    assert len(variants) == 1


def test_no_seeds_returns_empty(tmp_path: Path) -> None:
    ingestion = IngestionResult(project_id="p1", chunks=[_chunk("a", "x", 1)])
    empty_seeds = FindingSet(project_id="p1", findings=[])
    out = m5b_variants.hunt_variants(
        empty_seeds, ingestion, TargetDefinition(target_confirmed="t"),
        CodeGraph(project_id="p1"), _FakeEmbedding({}), llm=LLMService(api_key="fake"), languages=LanguageService(),
        cache=AnalysisCache(tmp_path),
    )
    assert out.findings == []


def test_converges_when_no_variants_confirmed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Regresión: si M4 no confirma nada, M5b debe parar tras UNA ronda, no seguir
    # rondando con las semillas viejas (bug: `continue` no actualizaba el frontier).
    a = _chunk("a", "system(x)", 10)
    b = _chunk("b", "system(y)", 20)  # vecino cercano, pero M4 no lo marcará
    ingestion = IngestionResult(project_id="p1", chunks=[a, b])
    embedding = _FakeEmbedding({a.code: [1.0, 0.0], b.code: [0.98, 0.05]})
    seed = Finding(id="F1", type="command_injection", file=a.file, line=11,
                   function="a", status=FindingStatus.CONFIRMED)

    calls = {"n": 0}
    def fake_m4(recorte: IngestionResult, *a: object, **k: object) -> FindingSet:
        calls["n"] += 1
        return FindingSet(project_id="p1", findings=[])  # nunca confirma variantes

    monkeypatch.setattr(m4_static, "analyze", fake_m4)
    out = m5b_variants.hunt_variants(
        FindingSet(project_id="p1", findings=[seed]), ingestion,
        TargetDefinition(target_confirmed="t"), CodeGraph(project_id="p1"),
        embedding, llm=LLMService(api_key="fake"), languages=LanguageService(), cache=AnalysisCache(tmp_path),
        min_similarity=0.9, max_rounds=5,
    )
    assert out.findings == []
    assert calls["n"] == 1  # exactamente una ronda: sin confirmados, converge ya

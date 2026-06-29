"""Tests de las optimizaciones de M4: caché por chunk y filtro por embeddings."""

from __future__ import annotations

from pathlib import Path

from hexflaw.infrastructure.analysis_cache import AnalysisCache
from hexflaw.modules import m1_ingestion, m2_target, m4_static
from hexflaw.services.embedding import LocalCPUEmbedding
from hexflaw.services.language_service import LanguageService
from hexflaw.services.llm_service import LLMResponse, LLMService

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


class CountingLLM(LLMService):
    """Devuelve un finding y cuenta llamadas."""

    def __init__(self) -> None:
        super().__init__(api_key="fake")
        self.calls = 0

    def analyze_code(self, instruction: str, code: str, **kwargs: object) -> LLMResponse:  # type: ignore[override]
        self.calls += 1
        payload = (
            '{"findings": [{"type": "command_injection", "file": "ping.c", '
            '"line": 12, "function": "handle_ping_input", "confidence": 0.9, '
            '"snippet": "system(cmd)"}]}'
        )
        return LLMResponse(text=payload, model="fake")


def _setup():
    langs = LanguageService()
    ingestion = m1_ingestion.ingest(FIXTURES / "sample_c", "p", langs)
    target = m2_target.define_target_directed("ping", ingestion, langs)
    return langs, ingestion, target


def test_cache_avoids_second_llm_call(tmp_path: Path) -> None:
    langs, ingestion, target = _setup()

    cache1 = AnalysisCache(tmp_path)
    llm1 = CountingLLM()
    m4_static.analyze(ingestion, target, llm1, langs, cache=cache1)
    assert llm1.calls >= 1

    # Segundo run con caché poblada → 0 llamadas al LLM.
    cache2 = AnalysisCache(tmp_path)
    llm2 = CountingLLM()
    result = m4_static.analyze(ingestion, target, llm2, langs, cache=cache2)
    assert llm2.calls == 0
    assert cache2.hits > 0
    # El finding cacheado se reconstruye.
    assert any(f.type == "command_injection" for f in result.findings)


def test_embedding_filter_keeps_relevant_chunk() -> None:
    langs, ingestion, target = _setup()
    embedding = LocalCPUEmbedding(dim=128)
    embedding._model = None  # fuerza el fallback por hashing

    result = m4_static.analyze(
        ingestion, target, CountingLLM(), langs, embedding=embedding
    )
    # El filtro no debe eliminar el chunk vulnerable (red de seguridad incluida).
    assert any(f.type == "command_injection" for f in result.findings)

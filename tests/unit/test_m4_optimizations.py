"""Tests de las optimizaciones de M4: caché por chunk y filtro por embeddings."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hexflaw.core.model_policy import ModelTier
from hexflaw.core.models import IngestionResult, TargetDefinition
from hexflaw.infrastructure.analysis_cache import AnalysisCache
from hexflaw.modules import m1_ingestion, m2_target, m4_static
from hexflaw.services.embedding import LocalCPUEmbedding
from hexflaw.services.language_service import LanguageService
from hexflaw.services.llm_service import (
    ANTHROPIC_MODELS,
    OPENAI_MODELS,
    LLMResponse,
    LLMService,
    OpenAILLMService,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


class CountingLLM(LLMService):
    """Devuelve un finding y cuenta llamadas."""

    def __init__(self) -> None:
        super().__init__(api_key="fake")
        self.calls = 0

    def analyze_code(self, instruction: str, code: str, **kwargs: object) -> LLMResponse:
        self.calls += 1
        payload = (
            '{"findings": [{"type": "command_injection", "file": "ping.c", '
            '"line": 12, "function": "handle_ping_input", "confidence": 0.9, '
            '"snippet": "system(cmd)"}]}'
        )
        return LLMResponse(text=payload, model="fake")


def _setup() -> tuple[LanguageService, IngestionResult, TargetDefinition]:
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


def test_exhaustive_analyzes_all_chunks() -> None:
    """--exhaustive analiza TODO el codebase, sin el prefiltro de sinks por keyword."""
    langs, ingestion, target = _setup()

    cov_normal: dict[str, Any] = {}
    m4_static.analyze(ingestion, target, CountingLLM(), langs,
                      exhaustive=False, coverage=cov_normal)
    cov_exh: dict[str, Any] = {}
    m4_static.analyze(ingestion, target, CountingLLM(), langs,
                      exhaustive=True, coverage=cov_exh)

    # Exhaustive cubre TODOS los chunks; normal solo los que pasan el prefiltro.
    assert cov_exh["scoped"] == len(ingestion.chunks)
    assert cov_normal["scoped"] <= cov_exh["scoped"]


class CapturingLLM(LLMService):
    """Guarda las instrucciones (prompts) recibidas."""

    def __init__(self) -> None:
        super().__init__(api_key="fake")
        self.prompts: list[str] = []

    def analyze_code(self, instruction: str, code: str, **kwargs: object) -> LLMResponse:
        self.prompts.append(instruction)
        return LLMResponse(text='{"findings": []}', model="fake")


def test_exhaustive_prompt_searches_all_classes() -> None:
    """En --exhaustive el prompt no se limita al vuln_profile (busca cualquier clase)."""
    langs, ingestion, target = _setup()

    normal = CapturingLLM()
    m4_static.analyze(ingestion, target, normal, langs, exhaustive=False)
    assert any(v in normal.prompts[0] for v in target.vuln_profile)

    exh = CapturingLLM()
    m4_static.analyze(ingestion, target, exh, langs, exhaustive=True)
    assert "CUALQUIER" in exh.prompts[0]


def test_cache_is_not_shared_across_backends(tmp_path: Path) -> None:
    """REGRESIÓN E2E: cambiar de backend no puede servir el análisis del otro.

    La clave del caché usaba el modelo que *pedía* el pipeline, no el que realmente
    corrió. Con el backend de OpenAI, un chunk analizado por ``gpt-4o-mini`` quedaba
    bajo una clave que decía ``claude-haiku-…``, y el run siguiente con Anthropic lo
    reutilizaba como si lo hubiera producido Claude. Este test corre M4 de verdad,
    no solo la función de la clave.
    """
    langs, ingestion, target = _setup()

    anthropic = CountingLLM()
    m4_static.analyze(ingestion, target, anthropic, langs, cache=AnalysisCache(tmp_path))
    assert anthropic.calls >= 1

    class CountingOpenAI(OpenAILLMService):
        """Mismo stub, pero con el catálogo de OpenAI."""

        def __init__(self) -> None:
            super().__init__(api_key="fake", models=dict(OPENAI_MODELS))
            self.calls = 0

        def analyze_code(self, instruction: str, code: str, **kwargs: object) -> LLMResponse:
            self.calls += 1
            return LLMResponse(text='{"findings": []}', model="fake")

    openai = CountingOpenAI()
    cache = AnalysisCache(tmp_path)
    m4_static.analyze(ingestion, target, openai, langs, cache=cache)

    assert openai.calls >= 1, "OpenAI reutilizó el análisis hecho por Anthropic"
    assert cache.hits == 0


def test_changing_the_model_reanalyzes(tmp_path: Path) -> None:
    """Estrenar un modelo nuevo no puede servir las respuestas del viejo."""
    langs, ingestion, target = _setup()

    class Pinned(CountingLLM):
        """Fija el tier MID, que es el que usa analyze() sin 'model' explícito."""

        def __init__(self, mid: str) -> None:
            super().__init__()
            self.models = {**ANTHROPIC_MODELS, ModelTier.MID: mid}

    viejo = Pinned("claude-sonnet-viejo")
    m4_static.analyze(ingestion, target, viejo, langs, cache=AnalysisCache(tmp_path))
    assert viejo.calls >= 1

    nuevo = Pinned("claude-sonnet-nuevo")
    cache = AnalysisCache(tmp_path)
    m4_static.analyze(ingestion, target, nuevo, langs, cache=cache)
    assert nuevo.calls >= 1, "reutilizó respuestas producidas por otro modelo"
    assert cache.hits == 0

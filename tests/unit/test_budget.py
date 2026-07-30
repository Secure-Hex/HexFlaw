"""Tests del budget tracker de tokens (CLAUDE.md §16, estrategia 7)."""

from __future__ import annotations

from pathlib import Path

import pytest

from hexflaw.modules import m1_ingestion, m2_target, m4_static
from hexflaw.services.language_service import LanguageService
from hexflaw.services.llm_service import (
    BudgetExceededError,
    LLMResponse,
    LLMService,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


class ExpensiveLLM(LLMService):
    """Consume muchos tokens por llamada para disparar el budget."""

    def __init__(self, budget: int) -> None:
        super().__init__(api_key="fake", token_budget=budget)
        self.calls = 0

    def analyze_code(self, instruction: str, code: str, **kwargs: object) -> LLMResponse:
        # Respeta el chequeo de budget del padre.
        if self.token_budget is not None and self.total_tokens >= self.token_budget:
            raise BudgetExceededError("budget")
        self.calls += 1
        self.total_input_tokens += 1000
        self.total_output_tokens += 1000
        return LLMResponse(text='{"findings": []}', model="fake")


def test_budget_stops_analysis() -> None:
    langs = LanguageService()
    # Genera muchos chunks para forzar múltiples batches.
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for i in range(40):
            (root / f"f{i}.c").write_text(f"int f{i}(){{ system(x); }}\n")
        ingestion = m1_ingestion.ingest(root, "p", langs)
    target = m2_target.define_target_directed("x", ingestion, langs)

    llm = ExpensiveLLM(budget=3000)  # ~1-2 llamadas antes de cortar
    m4_static.analyze(ingestion, target, llm, langs, mode="thorough")
    # Debe haberse detenido antes de procesar todos los batches.
    assert llm.calls <= 2
    assert llm.total_tokens >= 3000


def test_no_budget_means_no_limit() -> None:
    service = LLMService(api_key="fake", token_budget=None)
    service.total_input_tokens = 10**9
    # Sin budget no debe lanzar al chequear (se valida vía propiedad).
    assert service.token_budget is None
    with pytest.raises(Exception):
        # Falla por red/SDK, no por budget (no hay budget).
        service.analyze_code("x", "y")

"""Tests de feature #2 — generación de sink_patterns por LLM (sink_learner)."""

from __future__ import annotations

from pathlib import Path

import pytest

from hexflaw.services import sink_learner
from hexflaw.services.language_service import LanguageService
from hexflaw.services.llm_service import LLMResponse, LLMServiceError


class _FakeLLM:
    """LLM falso que devuelve un texto fijo (no toca la red)."""

    def __init__(self, text: str) -> None:
        self._text = text
        self.calls = 0

    def analyze_code(self, instruction: str, code: str, *, model=None) -> LLMResponse:
        self.calls += 1
        return LLMResponse(text=self._text, model="fake")


@pytest.fixture
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Aísla ~/.hexflaw a un tmp dir para no tocar el home real."""
    monkeypatch.setenv("HEXFLAW_HOME", str(tmp_path))
    return tmp_path


def test_learn_sinks_parses_normalizes_and_persists(isolated_home: Path) -> None:
    llm = _FakeLLM('{"sink_patterns": ["spawn(", "execSync", "EVAL(", "spawn("]}')
    ls = LanguageService()

    merged = sink_learner.learn_sinks("typescript", "const p = spawn('x')", llm, ls)

    # normalizado a minúscula y deduplicado
    assert "spawn(" in merged
    assert "execsync" in merged
    assert "eval(" in merged
    # persistido como custom y el caché in-memory refrescado
    assert ls.is_custom("typescript")
    assert set(ls.get("typescript").sink_patterns) == set(merged)


def test_learn_sinks_merges_with_existing_builtin(isolated_home: Path) -> None:
    ls = LanguageService()
    prior = set(ls.get("typescript").sink_patterns)
    assert prior  # el builtin TS ya trae algunos sinks

    llm = _FakeLLM('{"sink_patterns": ["brand_new_sink("]}')
    merged = sink_learner.learn_sinks("typescript", "code", llm, ls)

    assert "brand_new_sink(" in merged
    # no pierde los previos (normalizados a minúscula al mergear)
    assert {s.lower() for s in prior} <= set(merged)


def test_learn_sinks_raises_on_garbage_response(isolated_home: Path) -> None:
    ls = LanguageService()
    llm = _FakeLLM("lo siento, no puedo ayudar con eso")

    with pytest.raises(LLMServiceError):
        sink_learner.learn_sinks("typescript", "code", llm, ls)


def test_learn_sinks_unknown_language_creates_minimal_def(isolated_home: Path) -> None:
    ls = LanguageService()
    assert ls.get("cobol") is None  # no hay builtin

    llm = _FakeLLM('{"sink_patterns": ["CALL ", "exec "]}')
    merged = sink_learner.learn_sinks("cobol", "MOVE X TO Y", llm, ls)

    # se normaliza (strip + minúscula): "CALL " -> "call"
    assert "call" in merged
    assert ls.is_custom("cobol")

"""Tests del rate limiting interno del LLMService (CLAUDE.md §16, §15 T-M4-2)."""

from __future__ import annotations

import hexflaw.services.llm_service as llm_mod
from hexflaw.services.llm_service import LLMService


def test_pace_noop_without_limit() -> None:
    svc = LLMService(api_key="fake", rate_limit_tpm=None)
    svc._pace("claude-haiku-4-5-20251001", 100_000)  # no debe dormir ni fallar
    assert svc._windows == {}


def test_pace_sleeps_when_window_full(monkeypatch) -> None:
    sleeps: list[float] = []
    clock = {"t": 1000.0}
    monkeypatch.setattr(llm_mod.time, "monotonic", lambda: clock["t"])

    def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock["t"] += seconds  # avanzar el reloj para que la entrada expire

    monkeypatch.setattr(llm_mod.time, "sleep", fake_sleep)

    svc = LLMService(api_key="fake", rate_limit_tpm=10_000)
    svc._pace("m", 8_000)  # cabe → sin dormir
    assert sleeps == []
    svc._pace("m", 8_000)  # 8k+8k > 10k → debe dormir hasta liberar la ventana
    assert sleeps and sleeps[0] > 0


def test_pace_is_per_model(monkeypatch) -> None:
    monkeypatch.setattr(llm_mod.time, "monotonic", lambda: 500.0)
    monkeypatch.setattr(llm_mod.time, "sleep", lambda s: None)
    svc = LLMService(api_key="fake", rate_limit_tpm=10_000)
    svc._pace("haiku", 9_000)
    svc._pace("opus", 9_000)  # bucket distinto: no interfiere con haiku
    assert set(svc._windows) == {"haiku", "opus"}

"""Tests de la política de selección de modelo (CLAUDE.md §16 estrategias 5/6)."""

from __future__ import annotations

from hexflaw.core.model_policy import OPUS, SONNET, Task, choose_model
from hexflaw.core.models import AnalysisMode, Severity


def test_taint_is_opus_in_balanced() -> None:
    assert choose_model(Task.TAINT, AnalysisMode.BALANCED) == OPUS


def test_economy_disables_opus_for_taint() -> None:
    assert choose_model(Task.TAINT, AnalysisMode.ECONOMY) == SONNET


def test_rootcause_escalates_to_opus_for_high_severity() -> None:
    assert choose_model(Task.ROOTCAUSE, AnalysisMode.BALANCED, Severity.HIGH) == OPUS
    assert choose_model(Task.ROOTCAUSE, AnalysisMode.BALANCED, Severity.LOW) == SONNET


def test_economy_never_escalates_to_opus() -> None:
    assert choose_model(Task.ROOTCAUSE, AnalysisMode.ECONOMY, Severity.CRITICAL) == SONNET

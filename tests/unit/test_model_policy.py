"""Tests de la política de selección de modelo (CLAUDE.md §16 estrategias 5/6)."""

from __future__ import annotations

from hexflaw.core.model_policy import ModelTier, Task, choose_model, tasks_by_tier
from hexflaw.core.models import AnalysisMode, Severity


def test_taint_is_deep_in_balanced() -> None:
    assert choose_model(Task.TAINT, AnalysisMode.BALANCED) is ModelTier.DEEP


def test_economy_disables_the_deep_tier_for_taint() -> None:
    assert choose_model(Task.TAINT, AnalysisMode.ECONOMY) is ModelTier.MID


def test_rootcause_escalates_to_deep_for_high_severity() -> None:
    assert choose_model(Task.ROOTCAUSE, AnalysisMode.BALANCED, Severity.HIGH) is ModelTier.DEEP
    assert choose_model(Task.ROOTCAUSE, AnalysisMode.BALANCED, Severity.LOW) is ModelTier.MID


def test_economy_never_escalates_to_deep() -> None:
    assert choose_model(Task.ROOTCAUSE, AnalysisMode.ECONOMY, Severity.CRITICAL) is ModelTier.MID


def test_exhaustive_forces_deep_everywhere() -> None:
    for task in Task:
        assert choose_model(task, AnalysisMode.ECONOMY, exhaustive=True) is ModelTier.DEEP


def test_policy_returns_tiers_not_vendor_model_ids() -> None:
    """El core no puede conocer el catálogo de ningún proveedor.

    Devolver un id de Anthropic acá era lo que obligaba al backend de OpenAI a
    deducir el tier por substring del nombre — un mapeo por casualidad léxica que
    se rompía en silencio con cualquier modelo que no llevara la palabra esperada.
    """
    for mode in AnalysisMode:
        for task in Task:
            assert isinstance(choose_model(task, mode), ModelTier)


def test_tasks_by_tier_covers_every_task() -> None:
    """'models list' promete mostrar qué tareas afecta cada tier: sin agujeros."""
    for mode in AnalysisMode:
        grouped = tasks_by_tier(mode)
        assert sorted(t.value for ts in grouped.values() for t in ts) == sorted(
            t.value for t in Task
        )

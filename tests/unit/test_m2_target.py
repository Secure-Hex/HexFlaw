"""Tests de M2 — Target Definition (modo directed)."""

from __future__ import annotations

from pathlib import Path

from hexflaw.modules import m1_ingestion, m2_target
from hexflaw.services.language_service import LanguageService

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def test_directed_target_builds_profile_and_surface() -> None:
    langs = LanguageService()
    ingestion = m1_ingestion.ingest(FIXTURES / "sample_c", "proj-1", langs)

    target = m2_target.define_target_directed("ping functionality", ingestion, langs)

    assert target.mode == "directed"
    assert target.target_confirmed == "ping functionality"
    assert "command_injection" in target.vuln_profile
    assert any(p.endswith("ping.c") for p in target.attack_surface)
    # main contiene 'argv' / 'int main' → debe ser entry point heurístico.
    assert any(ep.function == "main" for ep in target.entry_points)

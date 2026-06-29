"""Tests del plugin system de lenguajes (CLAUDE.md §9b, §15)."""

from __future__ import annotations

from pathlib import Path

import pytest

from hexflaw.services.language_service import LanguageService, validate_definition_dict


def _valid_def() -> dict:
    return {
        "id": "cobol",
        "name": "COBOL",
        "extensions": [".cob", ".cbl"],
        "vuln_profile": ["command_injection"],
        "sink_patterns": ["CALL 'SYSTEM'"],
    }


def test_validate_accepts_good_definition() -> None:
    assert validate_definition_dict(_valid_def()) == []


def test_validate_rejects_unknown_field() -> None:
    bad = _valid_def()
    bad["evil"] = "x"  # additionalProperties=false
    errors = validate_definition_dict(bad)
    assert any("no permitido" in e for e in errors)


def test_validate_rejects_missing_required() -> None:
    errors = validate_definition_dict({"name": "X"})
    assert any("id" in e for e in errors)


def test_validate_rejects_overlong_field() -> None:
    bad = _valid_def()
    bad["notes"] = "x" * 600
    errors = validate_definition_dict(bad)
    assert any("excede" in e for e in errors)


def test_add_and_remove_custom(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HEXFLAW_HOME", str(tmp_path / "home"))
    service = LanguageService()
    assert service.get("cobol") is None

    service.add_custom(_valid_def())
    assert service.get("cobol") is not None
    assert service.is_custom("cobol")
    # se resuelve por extensión
    assert service.detect_by_extension(Path("legacy.cob")) is not None

    assert service.remove_custom("cobol") is True
    assert service.remove_custom("cobol") is False  # ya no existe


def test_add_duplicate_requires_overwrite(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HEXFLAW_HOME", str(tmp_path / "home"))
    service = LanguageService()
    service.add_custom(_valid_def())
    with pytest.raises(ValueError):
        service.add_custom(_valid_def())
    service.add_custom(_valid_def(), overwrite=True)  # ok


def test_custom_overrides_builtin(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HEXFLAW_HOME", str(tmp_path / "home"))
    # Custom con id 'c' debe tener precedencia sobre el builtin.
    override = {"id": "c", "name": "C-custom", "extensions": [".c"], "vuln_profile": []}
    service = LanguageService()
    service.add_custom(override, overwrite=True)
    reloaded = LanguageService()
    assert reloaded.get("c").name == "C-custom"

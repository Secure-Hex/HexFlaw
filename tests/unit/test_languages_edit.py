"""Subcomando ``hexflaw languages edit`` (CLAUDE.md §9b)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import typer

from hexflaw.cli.commands import languages as lang_cmd
from hexflaw.services import language_service
from hexflaw.services.language_service import LanguageService


@pytest.fixture
def custom_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setattr(language_service, "global_home", lambda: tmp_path)
    return tmp_path


def test_edit_seeds_builtin_and_writes_custom(custom_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_edit(text: str, *, extension: str = "") -> str:
        data = json.loads(text)
        data["sink_patterns"].append("my_custom_sink(")
        return json.dumps(data)

    monkeypatch.setattr(lang_cmd, "_open_in_editor", fake_edit)
    lang_cmd.edit_language("python")

    custom_file = custom_home / "languages" / "custom" / "python.json"
    assert custom_file.exists()
    # La definición activa (custom > builtin) refleja la edición.
    svc = LanguageService()
    definition = svc.get("python")
    assert definition is not None
    assert "my_custom_sink(" in definition.sink_patterns


def test_edit_no_changes_keeps_nothing(custom_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lang_cmd, "_open_in_editor", lambda text: None)
    lang_cmd.edit_language("python")
    assert not (custom_home / "languages" / "custom" / "python.json").exists()


def test_edit_invalid_json_rejected(custom_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lang_cmd, "_open_in_editor", lambda text: "{not json")
    with pytest.raises(typer.Exit):
        lang_cmd.edit_language("python")
    assert not (custom_home / "languages" / "custom" / "python.json").exists()


def test_edit_unknown_language_errors(custom_home: Path) -> None:
    with pytest.raises(typer.Exit):
        lang_cmd.edit_language("klingon")

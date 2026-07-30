"""Tests del aprendizaje automático de sinks (``sink_learner.auto_learn``)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hexflaw.core.models import CodeChunk, IngestionResult
from hexflaw.services import sink_learner
from hexflaw.services.language_service import LanguageService
from hexflaw.services.llm_service import LLMResponse, LLMService, LLMServiceError


class _FakeLLM(LLMService):
    """Devuelve una lista fija de sinks y cuenta las llamadas."""

    def __init__(self, payload: str = '{"sink_patterns": ["run_cmd(", "eval_it("]}') -> None:
        super().__init__(api_key="fake")
        self.payload = payload
        self.calls = 0

    def analyze_code(self, instruction: str, code: str, **kwargs: object) -> LLMResponse:
        self.calls += 1
        return LLMResponse(text=self.payload, model="fake")


class _FailingLLM(LLMService):
    """Simula que el LLM no está disponible."""

    def analyze_code(self, instruction: str, code: str, **kwargs: object) -> LLMResponse:
        raise LLMServiceError("sin API key")


@pytest.fixture
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Aísla ``~/.hexflaw`` para no tocar el home real."""
    monkeypatch.setenv("HEXFLAW_HOME", str(tmp_path / "home"))
    return tmp_path


def _uncovered_language(langs: LanguageService) -> None:
    """Registra un lenguaje custom SIN ``sink_patterns`` (el caso que dispara)."""
    langs.add_custom(
        {
            "id": "cobol",
            "name": "COBOL",
            "extensions": [".cbl"],
            "vuln_profile": ["command_injection"],
        },
        overwrite=True,
    )


def _ingestion() -> IngestionResult:
    return IngestionResult(
        project_id="p",
        languages=["cobol"],
        chunks=[
            CodeChunk(
                id="c1",
                file="a.cbl",
                language="cobol",
                name="f",
                code="CALL run_cmd(x)",
                line_start=1,
                line_end=2,
                hash="h",
            )
        ],
    )


def test_auto_learn_learns_for_uncovered_languages(isolated_home: Path) -> None:
    langs = LanguageService()
    _uncovered_language(langs)
    hexflaw_dir = isolated_home / ".hexflaw"
    hexflaw_dir.mkdir()

    learned = sink_learner.auto_learn(_ingestion(), _FakeLLM(), langs, hexflaw_dir)

    assert learned["cobol"] == ["eval_it(", "run_cmd("]


def test_auto_learn_caches_per_project(isolated_home: Path) -> None:
    """La segunda corrida no vuelve a gastar tokens."""
    langs = LanguageService()
    _uncovered_language(langs)
    hexflaw_dir = isolated_home / ".hexflaw"
    hexflaw_dir.mkdir()
    llm = _FakeLLM()

    sink_learner.auto_learn(_ingestion(), llm, langs, hexflaw_dir)
    sink_learner.auto_learn(_ingestion(), llm, langs, hexflaw_dir)

    assert llm.calls == 1
    assert (hexflaw_dir / sink_learner.LEARNED_FILE).exists()


def test_auto_learn_does_not_touch_the_global_custom(isolated_home: Path) -> None:
    """Lo aprendido de un proyecto no puede marcar sinks en el siguiente.

    Es la diferencia con el comando explícito ``languages learn``: ahí el usuario
    pidió que el conocimiento sea global; acá lo dispara la herramienta sola.
    """
    langs = LanguageService()
    _uncovered_language(langs)
    hexflaw_dir = isolated_home / ".hexflaw"
    hexflaw_dir.mkdir()

    sink_learner.auto_learn(_ingestion(), _FakeLLM(), langs, hexflaw_dir)

    custom = isolated_home / "home" / "languages" / "custom" / "cobol.json"
    persisted = json.loads(custom.read_text(encoding="utf-8"))
    assert not persisted.get("sink_patterns"), "no debe escribir sinks en el global"


def test_auto_learn_skips_languages_with_curated_sinks(isolated_home: Path) -> None:
    """Python ya trae sinks curados: no se gasta una llamada en re-aprenderlos."""
    langs = LanguageService()
    hexflaw_dir = isolated_home / ".hexflaw"
    hexflaw_dir.mkdir()
    llm = _FakeLLM()
    ingestion = IngestionResult(
        project_id="p",
        languages=["python"],
        chunks=[
            CodeChunk(
                id="c1",
                file="a.py",
                language="python",
                name="f",
                code="import os",
                line_start=1,
                line_end=1,
                hash="h",
            )
        ],
    )

    assert sink_learner.auto_learn(ingestion, llm, langs, hexflaw_dir) == {}
    assert llm.calls == 0


def test_auto_learn_degrades_when_the_llm_fails(isolated_home: Path) -> None:
    """Aprender es una optimización: si falla, el fail-open sigue cubriendo."""
    langs = LanguageService()
    _uncovered_language(langs)
    hexflaw_dir = isolated_home / ".hexflaw"
    hexflaw_dir.mkdir()

    learned = sink_learner.auto_learn(
        _ingestion(), _FailingLLM(api_key="fake"), langs, hexflaw_dir
    )

    assert learned == {}


def test_overlay_is_session_scoped(isolated_home: Path) -> None:
    """``apply_overlay`` suma en memoria; un servicio nuevo no lo ve."""
    langs = LanguageService()
    before = list(langs.get("python").sink_patterns)  # type: ignore[union-attr]

    langs.apply_overlay({"python": ["mi_helper("]})

    updated = langs.get("python")
    assert updated is not None and "mi_helper(" in updated.sink_patterns
    fresh = LanguageService().get("python")
    assert fresh is not None and "mi_helper(" not in fresh.sink_patterns
    assert len(before) < len(updated.sink_patterns)

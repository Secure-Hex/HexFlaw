"""Tests de detección de proyecto (estilo git) y jerarquía de config."""

from __future__ import annotations

from pathlib import Path

import pytest

from hexflaw.core import project as project_mod
from hexflaw.infrastructure import config as config_mod
from hexflaw.services.llm_service import build_llm_service


def test_init_and_detect_from_subdir(tmp_path: Path) -> None:
    project = project_mod.init_project(tmp_path, name="Demo")
    assert project.hexflaw_dir.is_dir()

    subdir = tmp_path / "src" / "deep"
    subdir.mkdir(parents=True)
    found = project_mod.find_project_root(subdir)
    assert found == tmp_path.resolve()


def test_init_twice_raises(tmp_path: Path) -> None:
    project_mod.init_project(tmp_path)
    with pytest.raises(project_mod.ProjectExistsError):
        project_mod.init_project(tmp_path)


def test_find_project_raises_when_absent(tmp_path: Path) -> None:
    with pytest.raises(project_mod.ProjectNotFoundError):
        project_mod.find_project_root(tmp_path)


def test_config_precedence_cli_overrides_local(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Aísla el home global para no leer la config real del usuario.
    monkeypatch.setenv("HEXFLAW_HOME", str(tmp_path / "globalhome"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    project_mod.init_project(tmp_path)
    from hexflaw.infrastructure import storage

    storage.write_json(
        tmp_path / ".hexflaw" / "config.json", {"analysis_mode": "economy"}
    )

    cfg = config_mod.resolve_config(
        project_dir=tmp_path, overrides={"analysis_mode": "thorough"}
    )
    assert cfg.get("analysis_mode") == "thorough"
    assert "cli-override" in cfg.sources

    # Sin override, gana la local sobre el default.
    cfg2 = config_mod.resolve_config(project_dir=tmp_path)
    assert cfg2.get("analysis_mode") == "economy"


def test_defaults_present_without_any_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEXFLAW_HOME", str(tmp_path / "empty"))
    cfg = config_mod.resolve_config()
    assert cfg.get("embedding_backend") == "local-cpu"
    # Los modelos ya no viven en la config: son None por defecto y el backend usa
    # su catálogo. Lo que importa es que ese catálogo resuelva los tres tiers.
    assert cfg.get("anthropic_model_deep") is None
    models = build_llm_service(cfg).models
    assert {t.value for t in models} == {"cheap", "mid", "deep"}
    assert all(models.values())

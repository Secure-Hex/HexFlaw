"""Tests de los perfiles de calibración (fast / audit / paranoid)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hexflaw.infrastructure import secrets_store
from hexflaw.infrastructure.config import DEFAULT_CONFIG, PROFILES, resolve_config


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Aísla ``~/.hexflaw`` para no leer la config real del usuario."""
    monkeypatch.setenv("HEXFLAW_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(secrets_store, "get_secret", lambda key: None)


def _write_local(project: Path, data: dict[str, object]) -> Path:
    """Crea un ``.hexflaw/config.json`` con ``data``."""
    hexflaw_dir = project / ".hexflaw"
    hexflaw_dir.mkdir(parents=True, exist_ok=True)
    (hexflaw_dir / "config.json").write_text(json.dumps(data), encoding="utf-8")
    return project


def test_every_profile_covers_the_same_knobs() -> None:
    """Un perfil que olvida una perilla la deja en el valor del anterior.

    Como los perfiles se aplican por capas sobre la config acumulada, una clave
    ausente no vuelve al default: hereda lo que hubiera. Que los tres declaren el
    mismo conjunto de decisiones evita ese arrastre silencioso.
    """
    decisive = {
        "analysis_mode",
        "token_budget",
        "scope_max_chunks",
        "m4_sink_rescue_hops",
        "m4_semantic_rescue_threshold",
        "auto_learn_sinks",
        "variant_hunting",
        "exhaustive",
    }
    for name, settings in PROFILES.items():
        assert decisive <= set(settings), f"perfil '{name}' no decide sobre {decisive - set(settings)}"


def test_profiles_are_ordered_by_aggressiveness() -> None:
    """fast < audit < paranoid en cobertura y en costo."""
    fast, audit, paranoid = PROFILES["fast"], PROFILES["audit"], PROFILES["paranoid"]
    assert fast["token_budget"] < audit["token_budget"] < paranoid["token_budget"]
    assert fast["scope_max_chunks"] < audit["scope_max_chunks"] < paranoid["scope_max_chunks"]
    assert fast["m4_sink_rescue_hops"] < audit["m4_sink_rescue_hops"] < paranoid["m4_sink_rescue_hops"]
    # Umbral MÁS BAJO = rescata más. En fast está por encima de 1.0, que el coseno
    # no puede alcanzar: la capa queda apagada, no solo estricta.
    assert fast["m4_semantic_rescue_threshold"] > 1.0
    assert audit["m4_semantic_rescue_threshold"] > paranoid["m4_semantic_rescue_threshold"]
    assert paranoid["exhaustive"] is True and audit["exhaustive"] is False


def test_default_is_audit() -> None:
    """Sin perfil declarado, la config efectiva es la de audit."""
    cfg = resolve_config()
    assert cfg.get("profile") == "audit"
    for key, value in PROFILES["audit"].items():
        assert cfg.get(key) == value


def test_explicit_flag_beats_the_profile() -> None:
    """El perfil aporta defaults; un flag explícito los pisa."""
    cfg = resolve_config(overrides={"profile": "paranoid", "token_budget": 1000})
    assert cfg.get("exhaustive") is True, "el resto del perfil sigue aplicando"
    assert cfg.get("token_budget") == 1000


def test_cli_profile_beats_a_stale_local_setting(tmp_path: Path) -> None:
    """Pedir un perfil en la CLI no puede quedar capado por el config del proyecto.

    El perfil se expande dentro de la capa que lo declara. Si se expandiera una
    sola vez al inicio, este ``scope_max_chunks`` de un run viejo silenciaría al
    ``--profile paranoid`` que el usuario acaba de pedir.
    """
    project = _write_local(tmp_path, {"scope_max_chunks": 50})
    capped = resolve_config(project)
    assert capped.get("scope_max_chunks") == 50

    asked = resolve_config(project, overrides={"profile": "paranoid"})
    assert asked.get("scope_max_chunks") == PROFILES["paranoid"]["scope_max_chunks"]


def test_local_profile_applies_but_loses_to_its_own_explicit_keys(tmp_path: Path) -> None:
    """Dentro de una misma capa, lo escrito a mano le gana al perfil."""
    project = _write_local(tmp_path, {"profile": "fast", "token_budget": 999_999})
    cfg = resolve_config(project)
    assert cfg.get("variant_hunting") is False, "el resto del perfil fast aplica"
    assert cfg.get("token_budget") == 999_999


def test_unknown_profile_fails_loudly() -> None:
    """Un typo en el perfil no puede degradar el análisis en silencio."""
    with pytest.raises(ValueError, match="Perfil desconocido"):
        resolve_config(overrides={"profile": "parnoid"})


def test_default_config_matches_the_audit_profile() -> None:
    """DEFAULT_CONFIG y el perfil audit no pueden contradecirse.

    Son dos fuentes del mismo valor; si divergen, la config efectiva depende de
    si el perfil llegó a expandirse, que es exactamente el bug difícil de ver.
    """
    for key, value in PROFILES["audit"].items():
        assert DEFAULT_CONFIG[key] == value, f"'{key}' difiere entre DEFAULT_CONFIG y audit"

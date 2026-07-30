"""API keys en keyring del SO con fallback a config.json (CLAUDE.md §15 T-INFRA-1)."""

from __future__ import annotations

from pathlib import Path

import pytest

from hexflaw.infrastructure import config as config_mod
from hexflaw.infrastructure import secrets_store


class _FakeKeyring:
    """Keyring en memoria para simular un backend usable en tests."""

    def __init__(self) -> None:
        self.store: dict[tuple[str, str], str] = {}

    def set_password(self, service: str, key: str, value: str) -> None:
        self.store[(service, key)] = value

    def get_password(self, service: str, key: str) -> str | None:
        return self.store.get((service, key))

    def delete_password(self, service: str, key: str) -> None:
        self.store.pop((service, key), None)


def _patch_keyring(monkeypatch: pytest.MonkeyPatch, fake: _FakeKeyring | None) -> None:
    monkeypatch.setattr(secrets_store, "_keyring", lambda: fake)
    monkeypatch.setattr(secrets_store, "available", lambda: fake is not None)


def test_set_get_delete_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeKeyring()
    _patch_keyring(monkeypatch, fake)
    assert secrets_store.set_secret("anthropic_api_key", "sk-ant-xyz") is True
    assert secrets_store.get_secret("anthropic_api_key") == "sk-ant-xyz"
    secrets_store.delete_secret("anthropic_api_key")
    assert secrets_store.get_secret("anthropic_api_key") is None


def test_unavailable_keyring_returns_false(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_keyring(monkeypatch, None)
    assert secrets_store.set_secret("anthropic_api_key", "x") is False
    assert secrets_store.get_secret("anthropic_api_key") is None


def test_save_secret_uses_keyring_not_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake = _FakeKeyring()
    _patch_keyring(monkeypatch, fake)
    monkeypatch.setattr(config_mod, "global_home", lambda: tmp_path)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)  # que no gane el entorno

    where = config_mod.save_secret("anthropic_api_key", "sk-ant-secret")
    assert where == "keyring"
    # No debe quedar en config.json.
    cfg_json = tmp_path / "config.json"
    if cfg_json.exists():
        assert "sk-ant-secret" not in cfg_json.read_text()
    # resolve_config la recupera desde el keyring.
    cfg = config_mod.resolve_config()
    assert cfg.values.get("anthropic_api_key") == "sk-ant-secret"


def test_save_secret_falls_back_to_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch_keyring(monkeypatch, None)  # sin keyring
    monkeypatch.setattr(config_mod, "global_home", lambda: tmp_path)

    where = config_mod.save_secret("anthropic_api_key", "sk-ant-fallback")
    assert where == "config.json"
    assert "sk-ant-fallback" in (tmp_path / "config.json").read_text()


def test_save_secret_strips_existing_plaintext(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Si había una copia en texto plano, al pasar al keyring se borra del JSON."""
    monkeypatch.setattr(config_mod, "global_home", lambda: tmp_path)
    # Estado heredado: key en texto plano.
    config_mod.save_global_config({"anthropic_api_key": "old-plaintext"})
    fake = _FakeKeyring()
    _patch_keyring(monkeypatch, fake)

    config_mod.save_secret("anthropic_api_key", "new-secret")
    assert "old-plaintext" not in (tmp_path / "config.json").read_text()
    assert fake.get_password("hexflaw", "anthropic_api_key") == "new-secret"

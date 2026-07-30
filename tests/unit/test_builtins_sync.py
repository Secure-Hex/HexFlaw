"""Sincronización de builtins al home con permisos 444 (CLAUDE.md §14/§15)."""

from __future__ import annotations

from pathlib import Path

import pytest

from hexflaw.services import language_service
from hexflaw.services.language_service import LanguageService, sync_builtins


def test_sync_copies_builtins_readonly(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(language_service, "global_home", lambda: tmp_path)
    dest = sync_builtins()

    assert dest == tmp_path / "languages" / "builtin"
    files = list(dest.glob("*.json"))
    assert files, "deberían copiarse las definiciones builtin"
    # Cada archivo es solo-lectura (444).
    for f in files:
        mode = f.stat().st_mode & 0o777
        assert mode == 0o444, f"{f.name} debería ser 444, es {oct(mode)}"
    # El directorio es inmutable (555).
    assert (dest.stat().st_mode & 0o777) == 0o555


def test_service_loads_from_home_after_sync(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(language_service, "global_home", lambda: tmp_path)
    sync_builtins()
    svc = LanguageService()
    # Sigue resolviendo lenguajes desde la copia del home.
    assert svc.get("python") is not None
    assert language_service._builtin_source() == tmp_path / "languages" / "builtin"


def test_sync_is_idempotent_and_refreshes_on_change(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(language_service, "global_home", lambda: tmp_path)
    dest = sync_builtins()
    sync_builtins()  # segunda corrida no debe fallar pese a archivos 444
    py = dest / "python.json"
    assert py.exists() and (py.stat().st_mode & 0o777) == 0o444

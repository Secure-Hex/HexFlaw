"""Tests de M0 — System Profiling: recomendación, perfilado e integridad."""

from __future__ import annotations

import pytest

from pathlib import Path

from hexflaw.infrastructure import profile_store
from hexflaw.modules import m0_profiling
from hexflaw.modules.m0_profiling import recommend_backend


def test_recommend_gpu_with_ollama() -> None:
    backend, _ = recommend_backend(ram_gb=32, gpu_type="cuda", ollama=True, internet=True)
    assert backend == "ollama"


def test_recommend_gpu_without_ollama_falls_to_local() -> None:
    backend, _ = recommend_backend(ram_gb=32, gpu_type="cuda", ollama=False, internet=True)
    assert backend == "local-cpu"


def test_recommend_high_ram_no_gpu_is_local() -> None:
    backend, _ = recommend_backend(ram_gb=16, gpu_type=None, ollama=False, internet=True)
    assert backend == "local-cpu"


def test_recommend_low_ram_requires_api() -> None:
    backend, _ = recommend_backend(ram_gb=4, gpu_type=None, ollama=False, internet=True)
    assert backend == "voyage"


def test_recommend_no_internet_forces_local() -> None:
    backend, _ = recommend_backend(ram_gb=4, gpu_type=None, ollama=False, internet=False)
    assert backend == "local-cpu"


def test_profile_system_runs_and_benchmarks() -> None:
    profile = m0_profiling.profile_system()
    assert profile.cpu_cores >= 1
    assert profile.ram_total_gb > 0
    assert "local-cpu" in profile.benchmarks
    assert profile.recommended_backend in {"local-cpu", "ollama", "voyage"}


def test_profile_store_integrity_roundtrip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEXFLAW_HOME", str(tmp_path / "home"))
    profile = m0_profiling.profile_system()
    profile_store.save_profile(profile)

    loaded = profile_store.load_profile()
    assert loaded is not None
    assert loaded.recommended_backend == profile.recommended_backend


def test_profile_store_detects_tampering(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEXFLAW_HOME", str(tmp_path / "home"))
    profile = m0_profiling.profile_system()
    profile_store.save_profile(profile)

    from hexflaw.infrastructure import storage

    profile_path = (tmp_path / "home" / "system_profile.json")
    payload = storage.read_json(profile_path)
    payload["recommended_backend"] = "openai"  # manipulación externa
    storage.write_json(profile_path, payload)

    assert profile_store.load_profile() is None  # integridad rota

"""Tests de M1 — Ingestion: detección de lenguaje, chunking y guards de seguridad."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from hexflaw.core.models import AppType
from hexflaw.modules import m1_ingestion
from hexflaw.services.language_service import LanguageService

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture
def langs() -> LanguageService:
    return LanguageService()


def test_ingest_detects_c_and_chunks_functions(langs: LanguageService) -> None:
    result = m1_ingestion.ingest(FIXTURES / "sample_c", "proj-1", langs)

    assert "c" in result.languages
    assert result.app_type in (AppType.BINARY, AppType.FIRMWARE)
    assert any(entry.path.endswith("ping.c") for entry in result.file_map)

    names = {chunk.name for chunk in result.chunks}
    assert "handle_ping_input" in names
    assert "main" in names


def test_ingest_python_fixture(langs: LanguageService) -> None:
    result = m1_ingestion.ingest(FIXTURES / "sample_python", "proj-2", langs)

    assert "python" in result.languages
    names = {chunk.name for chunk in result.chunks}
    assert {"add", "greet"} <= names


def test_ingest_skips_symlinks(tmp_path: Path, langs: LanguageService) -> None:
    real = tmp_path / "real.c"
    real.write_text("int main(){return 0;}\n")
    secret = tmp_path / "secret.c"
    secret.write_text("int leaked(){return 1;}\n")
    link = tmp_path / "link.c"
    try:
        os.symlink(secret, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks no soportados en esta plataforma")

    result = m1_ingestion.ingest(tmp_path, "proj-3", langs)
    ingested = {entry.path for entry in result.file_map}
    assert "real.c" in ingested
    assert "link.c" not in ingested
    assert any("link.c" in s for s in result.skipped)


def test_ingest_respects_file_size_limit(tmp_path: Path, langs: LanguageService) -> None:
    big = tmp_path / "big.c"
    big.write_text("int main(){return 0;}\n" + "// padding\n" * 1000)

    result = m1_ingestion.ingest(tmp_path, "proj-4", langs, max_file_bytes=50)
    assert not result.file_map
    assert any("big.c" in s for s in result.skipped)


def test_ingest_ignores_binary_disguised_as_source(
    tmp_path: Path, langs: LanguageService
) -> None:
    sneaky = tmp_path / "evil.c"
    sneaky.write_bytes(b"\x7fELF\x00\x00 not real source")

    result = m1_ingestion.ingest(tmp_path, "proj-5", langs)
    assert not result.file_map


# --- Regresión del footgun de ingest multi-path (clobber silencioso) ------- #


def _two_subdirs(tmp_path: Path) -> None:
    """Crea project_root/backend/app.py y project_root/common/util.py."""
    (tmp_path / "backend").mkdir()
    (tmp_path / "common").mkdir()
    (tmp_path / "backend" / "app.py").write_text("def handler():\n    return 1\n")
    (tmp_path / "common" / "util.py").write_text("def helper():\n    return 2\n")


def test_ingest_paths_are_project_relative(tmp_path: Path, langs: LanguageService) -> None:
    """Con project_root, las rutas son relativas al root del proyecto, no al source."""
    _two_subdirs(tmp_path)
    result = m1_ingestion.ingest(
        tmp_path / "backend", "p", langs, project_root=tmp_path
    )
    assert {e.path for e in result.file_map} == {"backend/app.py"}


def test_incremental_accumulates_across_subpaths(
    tmp_path: Path, langs: LanguageService
) -> None:
    """`ingest pathA` + `ingest pathB --incremental` ACUMULA (no clobea pathA)."""
    _two_subdirs(tmp_path)
    first = m1_ingestion.ingest(tmp_path / "backend", "p", langs, project_root=tmp_path)
    second = m1_ingestion.ingest(
        tmp_path / "common",
        "p",
        langs,
        prior=first,
        project_root=tmp_path,
        incremental=True,
    )
    assert {e.path for e in second.file_map} == {"backend/app.py", "common/util.py"}
    assert {"handler", "helper"} <= {c.name for c in second.chunks}
    assert not second.dropped_from_prior


def test_non_incremental_subpath_reports_dropped(
    tmp_path: Path, langs: LanguageService
) -> None:
    """Un ingest no-incremental de un sub-path reemplaza el índice PERO reporta drops."""
    _two_subdirs(tmp_path)
    full = m1_ingestion.ingest(tmp_path, "p", langs, project_root=tmp_path)
    assert {"backend/app.py", "common/util.py"} <= {e.path for e in full.file_map}

    narrowed = m1_ingestion.ingest(
        tmp_path / "backend",
        "p",
        langs,
        prior=full,
        project_root=tmp_path,
        incremental=False,
    )
    assert {e.path for e in narrowed.file_map} == {"backend/app.py"}
    assert "common/util.py" in narrowed.dropped_from_prior


def test_incremental_drops_deleted_file_under_same_root(
    tmp_path: Path, langs: LanguageService
) -> None:
    """La semántica original sigue: re-ingest del MISMO root dropea archivos borrados."""
    (tmp_path / "a.py").write_text("def f():\n    return 1\n")
    (tmp_path / "b.py").write_text("def g():\n    return 2\n")
    first = m1_ingestion.ingest(tmp_path, "p", langs, project_root=tmp_path)
    assert {"a.py", "b.py"} <= {e.path for e in first.file_map}

    (tmp_path / "b.py").unlink()
    second = m1_ingestion.ingest(
        tmp_path, "p", langs, prior=first, project_root=tmp_path, incremental=True
    )
    assert {e.path for e in second.file_map} == {"a.py"}
    assert "b.py" in second.dropped_from_prior

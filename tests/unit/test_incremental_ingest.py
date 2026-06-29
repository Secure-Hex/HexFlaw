"""Tests del re-ingest incremental de M1."""

from __future__ import annotations

from pathlib import Path

from hexflaw.modules import m1_ingestion
from hexflaw.services.language_service import LanguageService


def test_incremental_reuses_unchanged_and_reprocesses_changed(tmp_path: Path) -> None:
    langs = LanguageService()
    (tmp_path / "a.c").write_text("int alpha(){return 0;}\n")
    (tmp_path / "b.c").write_text("int beta(){return 1;}\n")

    first = m1_ingestion.ingest(tmp_path, "p", langs)
    assert {c.name for c in first.chunks} == {"alpha", "beta"}

    # Modifica solo b.c
    (tmp_path / "b.c").write_text("int beta(){return 42;}\nint gamma(){return 2;}\n")

    second = m1_ingestion.ingest(tmp_path, "p", langs, prior=first)
    names = {c.name for c in second.chunks}
    assert names == {"alpha", "beta", "gamma"}

    # El chunk de a.c es el mismo objeto reutilizado (mismo hash).
    a_first = next(c for c in first.chunks if c.file == "a.c")
    a_second = next(c for c in second.chunks if c.file == "a.c")
    assert a_first.hash == a_second.hash

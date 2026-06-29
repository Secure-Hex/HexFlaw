"""Normalización de fuente de ingestión: zip/git/url + guards (CLAUDE.md §15 M1)."""

from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path

import pytest

from hexflaw.modules import source_resolver
from hexflaw.modules.source_resolver import IngestSourceError, classify_source


def test_classify_source() -> None:
    assert classify_source("git@github.com:u/r.git") == "git"
    assert classify_source("https://github.com/u/r") == "git"
    assert classify_source("https://example.com/repo.git") == "git"
    assert classify_source("https://example.com/code.zip") == "url"
    assert classify_source("ssh://git@host/r") == "git"


def test_classify_directory_and_zip(tmp_path: Path) -> None:
    assert classify_source(str(tmp_path)) == "directory"
    z = tmp_path / "a.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("x.py", "x=1")
    assert classify_source(str(z)) == "zip"


def test_classify_unknown_raises() -> None:
    with pytest.raises(IngestSourceError):
        classify_source("/no/such/path/xyz")


def test_directory_passthrough_no_sandbox(tmp_path: Path) -> None:
    with source_resolver.resolved_source(tmp_path) as d:
        assert d == tmp_path  # mismo dir, sin copia


def test_zip_extraction(tmp_path: Path) -> None:
    z = tmp_path / "src.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("src/app.py", "import os\nos.system(x)\n")
        zf.writestr("README.md", "hi")
    with source_resolver.resolved_source(str(z)) as d:
        assert (d / "src" / "app.py").read_text().startswith("import os")
        assert (d / "README.md").exists()
    # sandbox eliminado al salir
    assert not d.exists()


def test_zip_slip_rejected(tmp_path: Path) -> None:
    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("../../escape.txt", "pwned")
        zf.writestr("ok.py", "x=1")
    with source_resolver.resolved_source(str(z)) as d:
        # El miembro malicioso NO se materializa fuera del sandbox.
        assert (d / "ok.py").exists()
    # Nada se escribió en el árbol padre.
    assert not (tmp_path.parent / "escape.txt").exists()


def test_zip_symlink_skipped(tmp_path: Path) -> None:
    import stat as stat_mod

    z = tmp_path / "link.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zi = zipfile.ZipInfo("evil_link")
        zi.external_attr = (stat_mod.S_IFLNK | 0o777) << 16
        zf.writestr(zi, "/etc/passwd")
        zf.writestr("real.py", "x=1")
    with source_resolver.resolved_source(str(z)) as d:
        assert (d / "real.py").exists()
        assert not (d / "evil_link").exists()  # symlink no extraído


def test_git_clone_disables_hooks(tmp_path: Path) -> None:
    """Clona un repo local con un hook malicioso; el hook NO debe ejecutarse."""
    origin = tmp_path / "origin"
    origin.mkdir()
    env = {"GIT_CONFIG_NOSYSTEM": "1", "HOME": str(tmp_path)}

    def git(*args: str, cwd: Path = origin) -> None:
        subprocess.run(
            ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
            cwd=cwd, env={**env}, check=True, capture_output=True,
        )

    git("init", "-q")
    (origin / "main.py").write_text("print(1)\n")
    git("add", ".")
    git("commit", "-qm", "init")

    canary = tmp_path / "PWNED"
    hooks = origin / ".git" / "hooks"
    hook = hooks / "post-checkout"
    hook.write_text(f"#!/bin/sh\ntouch {canary}\n")
    hook.chmod(0o755)

    url = f"file://{origin}"
    with source_resolver.resolved_source(url) as d:
        assert (d / "main.py").exists()
    assert not canary.exists()  # el hook del repo no corrió

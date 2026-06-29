"""Detección de lenguaje por shebang (fallback para archivos sin extensión)."""

from __future__ import annotations

from pathlib import Path

from hexflaw.modules import m1_ingestion
from hexflaw.services.language_service import LanguageService


def test_detect_by_shebang_env_form() -> None:
    svc = LanguageService()
    assert svc.detect_by_shebang("#!/usr/bin/env python3").id == "python"
    assert svc.detect_by_shebang("#!/usr/bin/env node").id == "javascript"


def test_detect_by_shebang_direct_path_and_versions() -> None:
    svc = LanguageService()
    assert svc.detect_by_shebang("#!/usr/bin/php8").id == "php"
    assert svc.detect_by_shebang("#!/usr/local/bin/ruby2.7").id == "ruby"


def test_detect_by_shebang_non_shebang_and_unknown() -> None:
    svc = LanguageService()
    assert svc.detect_by_shebang("import os") is None
    assert svc.detect_by_shebang("#!/bin/bash") is None  # sin bash.json builtin
    assert svc.detect_by_shebang("") is None


def test_ingest_picks_up_extensionless_python(tmp_path: Path) -> None:
    """Un script Python sin extensión se ingiere gracias al shebang."""
    script = tmp_path / "cgi-handler"
    script.write_text("#!/usr/bin/env python3\nimport os\nos.system(x)\n")
    langs = LanguageService()
    result = m1_ingestion.ingest(tmp_path, "test-project", langs, project_root=tmp_path)
    assert "python" in result.languages
    assert any(f.path == "cgi-handler" for f in result.file_map)

"""Tests de los importadores de catálogos de sinks (``scripts/``).

Los fixtures son inventados a propósito: **no se vendoriza contenido de Semgrep**,
cuya licencia prohíbe redistribuirlo.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent.parent / "scripts"


def _load(name: str) -> ModuleType:
    """Carga un script de ``scripts/`` como módulo (no son un paquete)."""
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- #
# CodeQL (MIT — sí se puede redistribuir lo derivado)
# --------------------------------------------------------------------------- #
def test_codeql_import_maps_kind_and_keeps_the_receiver(tmp_path: Path) -> None:
    module = _load("import_codeql_sinks")
    (tmp_path / "java" / "ql" / "lib" / "ext").mkdir(parents=True)
    (tmp_path / "java" / "ql" / "lib" / "ext" / "x.model.yml").write_text(
        "extensions:\n"
        "  - addsTo: {pack: codeql/java-all, extensible: sinkModel}\n"
        "    data:\n"
        '      - ["java.lang", "Runtime", false, "exec", "(String)", "", '
        '"Argument[0]", "command-injection", "manual"]\n',
        encoding="utf-8",
    )

    models = module.extract(tmp_path)

    assert models["java"] == [["Runtime.exec", "command_execution"]]


def test_codeql_import_drops_unmodelled_kinds(tmp_path: Path) -> None:
    """``log-injection`` es el 29% del catálogo y no aporta hallazgos accionables."""
    module = _load("import_codeql_sinks")
    (tmp_path / "java" / "ql" / "lib" / "ext").mkdir(parents=True)
    (tmp_path / "java" / "ql" / "lib" / "ext" / "x.model.yml").write_text(
        "extensions:\n"
        "  - addsTo: {pack: codeql/java-all, extensible: sinkModel}\n"
        "    data:\n"
        '      - ["org.slf4j", "Logger", false, "info", "(String)", "", '
        '"Argument[0]", "log-injection", "manual"]\n',
        encoding="utf-8",
    )

    assert module.extract(tmp_path) == {}


def test_codeql_import_drops_generic_method_names(tmp_path: Path) -> None:
    module = _load("import_codeql_sinks")
    (tmp_path / "java" / "ql" / "lib" / "ext").mkdir(parents=True)
    (tmp_path / "java" / "ql" / "lib" / "ext" / "x.model.yml").write_text(
        "extensions:\n"
        "  - addsTo: {pack: codeql/java-all, extensible: sinkModel}\n"
        "    data:\n"
        '      - ["p", "T", false, "write", "(String)", "", "Argument[0]", '
        '"path-injection", "manual"]\n',
        encoding="utf-8",
    )

    assert module.extract(tmp_path) == {}


# --------------------------------------------------------------------------- #
# Semgrep (licencia propietaria — solo import local del usuario)
# --------------------------------------------------------------------------- #
_FAKE_RULES = """rules:
- id: inventada-exec
  mode: taint
  languages: [go]
  metadata:
    cwe: ['CWE-78: OS Command Injection']
  pattern-sinks:
  - patterns:
    - pattern-either:
      - pattern: exec.Command($CMD, ...)
      - pattern: $TOKEN.SignedString($F)
- id: inventada-sin-cwe
  mode: taint
  languages: [go]
  metadata: {cwe: ['CWE-999: No mapeado']}
  pattern-sinks:
  - pattern: foo.Bar($X)
"""


def test_semgrep_import_ignores_metavariable_receivers(tmp_path: Path) -> None:
    """``$TOKEN.SignedString`` NO es un tipo y no puede entrar al catálogo.

    Regresión: ``$`` no es carácter de palabra, así que un ``\\b`` al principio del
    patrón matchea igual dentro de ``$TOKEN.foo()`` y la metavariable se colaba
    como si fuera un tipo receptor.
    """
    module = _load("import_semgrep_sinks")
    (tmp_path / "r.yaml").write_text(_FAKE_RULES, encoding="utf-8")

    models = module.extract(tmp_path)

    assert models["go"] == [["exec.Command", "command_execution"]]
    assert all("TOKEN" not in pattern for pattern, _ in models["go"])


def test_semgrep_import_requires_accepting_the_license(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sin ``--accept-license`` no escribe nada: la licencia la acepta el usuario."""
    module = _load("import_semgrep_sinks")
    (tmp_path / "r.yaml").write_text(_FAKE_RULES, encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["x", str(tmp_path)])

    assert module.main() == 2


def test_semgrep_import_refuses_to_write_inside_the_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Escribir en el paquete sería redistribuir reglas que no se pueden redistribuir."""
    module = _load("import_semgrep_sinks")
    (tmp_path / "r.yaml").write_text(_FAKE_RULES, encoding="utf-8")
    inside = SCRIPTS.parent / "hexflaw" / "infrastructure" / "languages"
    monkeypatch.setattr(
        sys, "argv", ["x", str(tmp_path), "--accept-license", "--out", str(inside)]
    )

    assert module.main() == 1


def test_semgrep_import_writes_to_the_custom_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """El destino por defecto es el custom del usuario, fuera del paquete."""
    module = _load("import_semgrep_sinks")
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "r.yaml").write_text(_FAKE_RULES, encoding="utf-8")
    out = tmp_path / "custom"
    monkeypatch.setattr(
        sys, "argv", ["x", str(rules), "--accept-license", "--out", str(out)]
    )

    assert module.main() == 0
    written = json.loads((out / "go.json").read_text(encoding="utf-8"))
    assert written["sink_models"] == [["exec.Command", "command_execution"]]

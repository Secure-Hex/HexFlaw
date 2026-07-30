#!/usr/bin/env python3
"""Importa sinks desde una copia LOCAL de semgrep-rules, en tu propia máquina.

**HexFlaw no distribuye ninguna regla de Semgrep.** Este script es código nuestro
(GPL-3.0) que lee un checkout tuyo. La Semgrep Rules License v1.0 permite el uso
"for your own internal business purposes" pero **prohíbe redistribuirlas**:

    "This license does not allow you to distribute the rules, or to make them
     available to others as a service"

Por eso el resultado se escribe en tu directorio de lenguajes **custom**
(``~/.hexflaw/languages/custom/``), nunca dentro del paquete. Si contribuís
cambios a HexFlaw, esos archivos no van al repositorio.

Antes de usarlo, leé https://semgrep.dev/legal/rules-license y decidí si tu uso
cae dentro de sus términos. El script no toma esa decisión por vos: exige
``--accept-license`` para correr.

**Qué tan bien funciona.** Los sinks de Semgrep son patrones estructurales
(``$TOKEN.SignedString($F)``), no nombres. Cuando el receptor es una
metavariable solo queda el nombre del método, que sin el tipo es demasiado
ambiguo para el matcher de HexFlaw y se descarta. El rendimiento real es bueno
en reglas con receptor literal (``exec.Command(...)``) y pobre en el resto.

Uso:

    git clone --depth 1 https://github.com/semgrep/semgrep-rules ~/semgrep-rules
    python scripts/import_semgrep_sinks.py ~/semgrep-rules --accept-license
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import pathlib
import re
import sys
from typing import Any

import yaml

#: CWE → ``sink_type`` de HexFlaw. Las reglas de Semgrep traen el CWE en
#: ``metadata.cwe``, que es más estable que su taxonomía de categorías.
CWE_MAP: dict[str, str] = {
    "78": "command_execution",
    "77": "command_execution",
    "94": "code_execution",
    "95": "code_execution",
    "89": "sql_query",
    "90": "ldap_query",
    "643": "xpath_query",
    "22": "file_op",
    "23": "file_op",
    "73": "file_op",
    "918": "network_send",
    "601": "open_redirect",
    "502": "deserialization",
    "611": "xml_parse",
    "1321": "prototype_pollution",
}

#: Lenguajes de Semgrep → ids de HexFlaw.
LANGUAGES = {
    "python": "python", "go": "go", "java": "java", "javascript": "javascript",
    "typescript": "typescript", "php": "php", "ruby": "ruby", "csharp": "csharp",
    "c": "c", "cpp": "cpp", "rust": "rust", "kotlin": "kotlin", "swift": "swift",
    "scala": "scala", "bash": "bash", "solidity": "solidity",
}

#: Llamada con receptor literal: ``exec.Command(...)``. Se exige que el receptor
#: NO sea una metavariable (``$TOKEN``), porque sin tipo el nombre del método es
#: demasiado ambiguo — es el mismo criterio que en el import de CodeQL.
#:
#: El lookbehind sobre ``$`` es imprescindible: ``$`` no es carácter de palabra,
#: así que un ``\b`` al principio matchea igual dentro de ``$TOKEN.foo()`` y la
#: metavariable se colaría como si fuera un tipo.
_QUALIFIED_CALL = re.compile(r"(?<![$\w.])([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\(")

_LICENSE_NOTICE = """
Semgrep Rules License v1.0 — https://semgrep.dev/legal/rules-license

  "You may use the rules only for your own internal business purposes"
  "This license does not allow you to distribute the rules, or to make them
   available to others as a service"

Los sinks derivados se escriben en tu directorio custom, NUNCA dentro del
paquete de HexFlaw. No los redistribuyas ni los subas a un repositorio público.
"""


def extract(root: pathlib.Path) -> dict[str, list[list[str]]]:
    """Extrae sinks calificados de las reglas taint de un checkout local.

    Args:
        root: Raíz del checkout de semgrep-rules.

    Returns:
        ``{lenguaje_hexflaw: [[patrón, sink_type], ...]}``.
    """
    found: dict[str, set[tuple[str, str]]] = collections.defaultdict(set)
    skipped: collections.Counter[str] = collections.Counter()

    for path in list(root.rglob("*.yaml")) + list(root.rglob("*.yml")):
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError, UnicodeDecodeError):
            continue
        if not isinstance(document, dict):
            continue
        for rule in document.get("rules", []) or []:
            if not isinstance(rule, dict) or rule.get("mode") != "taint":
                continue
            sink_type = _sink_type_of(rule)
            if sink_type is None:
                skipped["sin CWE mapeable"] += 1
                continue
            languages = [
                LANGUAGES[lang]
                for lang in rule.get("languages", []) or []
                if lang in LANGUAGES
            ]
            if not languages:
                skipped["lenguaje no soportado"] += 1
                continue
            for pattern in _sink_patterns_of(rule.get("pattern-sinks", []) or []):
                for receiver, method in _QUALIFIED_CALL.findall(pattern):
                    if receiver.startswith("$") or method.startswith("$"):
                        continue
                    for language in languages:
                        found[language].add((f"{receiver}.{method}", sink_type))

    for reason, count in skipped.most_common(5):
        print(f"  descartadas por {reason}: {count}", file=sys.stderr)
    return {lang: [list(m) for m in sorted(models)] for lang, models in found.items()}


def _sink_type_of(rule: dict[str, Any]) -> str | None:
    """Mapea el CWE de una regla a un ``sink_type``, o ``None`` si no aplica."""
    metadata = rule.get("metadata") or {}
    entries = metadata.get("cwe") or []
    if isinstance(entries, str):
        entries = [entries]
    for entry in entries:
        match = re.search(r"CWE-(\d+)", str(entry))
        if match and match.group(1) in CWE_MAP:
            return CWE_MAP[match.group(1)]
    return None


def _sink_patterns_of(node: Any) -> list[str]:
    """Aplana los strings de patrón de un bloque ``pattern-sinks`` anidado."""
    out: list[str] = []
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, list):
        for item in node:
            out.extend(_sink_patterns_of(item))
    elif isinstance(node, dict):
        for key, value in node.items():
            if key.startswith("pattern") or key in ("patterns", "focus-metavariable"):
                out.extend(_sink_patterns_of(value))
    return out


def _custom_dir() -> pathlib.Path:
    """Directorio de lenguajes custom del usuario (``~/.hexflaw/languages/custom``)."""
    home = pathlib.Path(os.environ.get("HEXFLAW_HOME", "~/.hexflaw")).expanduser()
    return home / "languages" / "custom"


def main() -> int:
    """Punto de entrada del script."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("semgrep_root", type=pathlib.Path, help="Checkout local de semgrep-rules")
    parser.add_argument(
        "--accept-license",
        action="store_true",
        help="Confirma que leíste la Semgrep Rules License y que tu uso la respeta.",
    )
    parser.add_argument("--out", type=pathlib.Path, default=None, help="Destino (default: custom)")
    args = parser.parse_args()

    print(_LICENSE_NOTICE)
    if not args.accept_license:
        print("Falta --accept-license. No se escribió nada.", file=sys.stderr)
        return 2
    if not args.semgrep_root.is_dir():
        print(f"No existe: {args.semgrep_root}", file=sys.stderr)
        return 1

    destination = args.out or _custom_dir()
    package_languages = pathlib.Path(__file__).resolve().parent.parent / "hexflaw"
    if package_languages in destination.resolve().parents:
        print(
            "Negado: el destino está dentro del paquete. Estos sinks derivan de "
            "reglas que no se pueden redistribuir.",
            file=sys.stderr,
        )
        return 1

    models = extract(args.semgrep_root)
    if not models:
        print("No se extrajo ningún sink calificado.")
        return 1

    destination.mkdir(parents=True, exist_ok=True)
    for language, entries in sorted(models.items()):
        target = destination / f"{language}.json"
        definition: dict[str, Any] = (
            json.loads(target.read_text(encoding="utf-8")) if target.exists() else {}
        )
        definition.setdefault("id", language)
        definition.setdefault("name", language)
        definition.setdefault("extensions", [])
        merged = {tuple(m) for m in definition.get("sink_models", [])} | {
            tuple(m) for m in entries
        }
        definition["sink_models"] = [list(m) for m in sorted(merged)]
        target.write_text(
            json.dumps(definition, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print(f"  {language:12} {len(entries):>4} sinks → {target}")

    print("\nUn custom con el mismo id pisa al builtin: revisá 'hexflaw languages show <id>'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

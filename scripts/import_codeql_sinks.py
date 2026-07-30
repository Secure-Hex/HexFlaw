#!/usr/bin/env python3
"""Importa el catálogo de sinks de CodeQL a definiciones de lenguaje de HexFlaw.

CodeQL publica sus modelos de taint como **datos planos** (Models-as-Data), no
solo como código QL:

    - ["java.lang", "Runtime", False, "exec", "(String)", "", "Argument[0]",
       "command-injection", "manual"]
       └paquete    └tipo            └método            └arg      └clase de vuln

Eso es más rico que ``sink_patterns`` (strings sueltos): trae el **tipo receptor**
y la clase de vulnerabilidad ya resuelta. Se emite a ``sink_models``.

**Licencia.** github/codeql es MIT, compatible con la GPL-3.0 de HexFlaw. Se
conserva la atribución en el archivo generado. *No* se importa semgrep-rules: su
licencia (Semgrep Rules License v1.0) prohíbe redistribuir las reglas, y HexFlaw
se distribuye por PyPI.

Uso:

    git clone --depth 1 --filter=blob:none --sparse https://github.com/github/codeql
    cd codeql && git sparse-checkout set --no-cone '*/ql/lib/ext/**'
    python scripts/import_codeql_sinks.py <ruta-al-clone> --write
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import sys
from typing import Any

import yaml

#: Clase de vulnerabilidad de CodeQL → ``sink_type`` de HexFlaw. Lo que no está
#: acá se descarta a propósito: importar clases que el pipeline no modela solo
#: agrega ruido. ``log-injection`` es el caso claro — es el 29% del catálogo y
#: sus métodos se llaman ``log``/``info``/``debug``, que matchearían en todos
#: lados sin aportar un hallazgo accionable.
KIND_MAP: dict[str, str] = {
    "command-injection": "command_execution",
    "code-injection": "code_execution",
    "sql-injection": "sql_query",
    "path-injection": "file_op",
    "path-injection[read]": "file_op",
    "file-content-store": "file_op",
    "request-forgery": "network_send",
    "url-redirection": "open_redirect",
    "ldap-injection": "ldap_query",
    "xpath-injection": "xpath_query",
    "xslt-injection": "code_execution",
    "template-injection": "code_execution",
    "jndi-injection": "code_execution",
    "ognl-injection": "code_execution",
    "unsafe-deserialization": "deserialization",
    "xxe": "xml_parse",
}

#: Nombres de método demasiado comunes para usarlos aunque vengan calificados: el
#: tipo receptor que infiere el AST es heurístico, así que un ``get``/``write``
#: puede colisionar con cualquier clase homónima.
TOO_GENERIC = frozenset(
    {
        "log", "trace", "info", "debug", "error", "warn", "fatal", "logf", "logv",
        "print", "println", "printf", "write", "read", "format", "equals",
        "compare", "toString", "append", "add", "get", "set", "put", "run",
        "call", "load", "parse", "open", "close", "send", "apply", "accept",
    }
)

#: Lenguaje de CodeQL → id de lenguaje en HexFlaw.
LANGUAGES = {"java": "java", "go": "go", "csharp": "csharp", "javascript": "javascript"}


def extract(root: pathlib.Path) -> dict[str, list[list[str]]]:
    """Recorre los ``.model.yml`` del clone y devuelve los sinks por lenguaje.

    Args:
        root: Raíz del clone de github/codeql.

    Returns:
        ``{lenguaje_hexflaw: [[patrón, sink_type], ...]}`` ordenado y sin repetir.
    """
    found: dict[str, set[tuple[str, str]]] = collections.defaultdict(set)
    skipped: collections.Counter[str] = collections.Counter()

    for path in root.rglob("*.model.yml"):
        language = LANGUAGES.get(path.parts[len(root.parts)] if path.is_absolute() else path.parts[0])
        if language is None:
            language = next((LANGUAGES[p] for p in path.parts if p in LANGUAGES), None)
        if language is None:
            continue
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError) as exc:
            print(f"  ! {path}: {exc}", file=sys.stderr)
            continue

        for extension in (document or {}).get("extensions", []) or []:
            if extension.get("addsTo", {}).get("extensible") != "sinkModel":
                continue
            for row in extension.get("data", []) or []:
                model = _row_to_model(row, skipped)
                if model is not None:
                    found[language].add(model)

    for reason, count in skipped.most_common():
        print(f"  descartados por {reason}: {count}", file=sys.stderr)
    return {lang: [list(m) for m in sorted(models)] for lang, models in found.items()}


def _row_to_model(
    row: Any, skipped: collections.Counter[str]
) -> tuple[str, str] | None:
    """Convierte una fila de CodeQL en ``(patrón, sink_type)``, o ``None``."""
    if not isinstance(row, list) or len(row) < 4:
        return None
    kind = str(row[-2])
    sink_type = KIND_MAP.get(kind)
    if sink_type is None:
        skipped[f"clase no modelada ({kind})"] += 1
        return None

    receiver = row[1] if isinstance(row[1], str) else ""
    method = row[3] if isinstance(row[3], str) else ""
    if not method or not receiver:
        skipped["sin tipo o método"] += 1
        return None
    if method in TOO_GENERIC:
        skipped["nombre demasiado genérico"] += 1
        return None
    # Solo el último segmento del tipo: el AST infiere `Runtime`, no
    # `java.lang.Runtime`.
    return f"{receiver.rsplit('.', 1)[-1]}.{method}", sink_type


def main() -> int:
    """Punto de entrada del script."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("codeql_root", type=pathlib.Path, help="Clone de github/codeql")
    parser.add_argument(
        "--write", action="store_true", help="Escribe las definiciones (si no, dry-run)"
    )
    parser.add_argument(
        "--languages-dir",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parent.parent
        / "hexflaw"
        / "infrastructure"
        / "languages",
    )
    args = parser.parse_args()

    if not args.codeql_root.is_dir():
        print(f"No existe: {args.codeql_root}", file=sys.stderr)
        return 1

    models = extract(args.codeql_root)
    if not models:
        print("No se extrajo ningún sink; ¿el sparse-checkout incluye */ql/lib/ext?")
        return 1

    for language, entries in sorted(models.items()):
        target = args.languages_dir / f"{language}.json"
        if not target.exists():
            print(f"  {language}: sin definición en {target}, se salta")
            continue
        definition = json.loads(target.read_text(encoding="utf-8"))
        previous = len(definition.get("sink_models", []))
        print(f"  {language:12} {previous:>4} → {len(entries):>4} sink_models")
        if args.write:
            definition["sink_models"] = entries
            target.write_text(
                json.dumps(definition, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )

    if not args.write:
        print("\n(dry-run; usá --write para aplicar)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

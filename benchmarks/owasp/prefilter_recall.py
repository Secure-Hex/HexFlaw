#!/usr/bin/env python3
"""Mide el recall del prefiltro de M4 contra el OWASP Benchmark v1.2.

**No gasta un solo token.** M3 y las 4 capas del prefiltro no usan LLM, así que
este número se puede medir gratis y cuantas veces haga falta. Es el **techo de
recall del pipeline**: un testcase cuyo chunk vulnerable no sobrevive al
prefiltro nunca llega al LLM, y por lo tanto es un falso negativo garantizado,
sin importar lo bueno que sea el modelo.

Lo que NO mide: si el LLM detecta la vuln en el chunk que sí le llega. Eso exige
correr M4+M5 completos y cuesta dinero real.

Uso:

    python benchmarks/owasp/prefilter_recall.py --limit 400
    python benchmarks/owasp/prefilter_recall.py --category cmdi
    python benchmarks/owasp/prefilter_recall.py --no-semantic   # aísla capas 0-2
"""

from __future__ import annotations

import argparse
import csv
import shutil
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))

from hexflaw.core.models import CodeChunk  # noqa: E402
from hexflaw.modules import m1_ingestion, m2_target, m3_graph  # noqa: E402
from hexflaw.modules.m4_static import _prefilter, _semantic_rescue  # noqa: E402
from hexflaw.services.language_service import LanguageService  # noqa: E402

VENDOR = REPO / "benchmarks" / "vendor" / "benchmark"
GROUND_TRUTH = VENDOR / "expectedresults-1.2.csv"
TESTCASES = VENDOR / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"


def load_ground_truth() -> dict[str, tuple[str, bool]]:
    """``{BenchmarkTestNNNNN: (categoría, es_vulnerable)}``."""
    truth: dict[str, tuple[str, bool]] = {}
    with GROUND_TRUTH.open(encoding="utf-8") as handle:
        for row in csv.reader(handle):
            if not row or row[0].startswith("#"):
                continue
            name, category, vulnerable = row[0].strip(), row[1].strip(), row[2].strip()
            truth[name] = (category, vulnerable == "true")
    return truth


def build_corpus(
    truth: dict[str, tuple[str, bool]], category: str | None, limit: int | None
) -> tuple[Path, dict[str, tuple[str, bool]]]:
    """Copia los testcases elegidos a un directorio temporal.

    Returns:
        ``(directorio, subconjunto_del_ground_truth)``.
    """
    selected = {
        name: meta
        for name, meta in sorted(truth.items())
        if category is None or meta[0] == category
    }
    if limit is not None:
        # Se alterna vulnerable/seguro para que el subconjunto quede balanceado y
        # el recall no salga inflado por muestrear solo casos fáciles.
        vulnerable = [n for n, m in selected.items() if m[1]][: limit // 2]
        safe = [n for n, m in selected.items() if not m[1]][: limit - len(vulnerable)]
        selected = {n: selected[n] for n in sorted(vulnerable + safe)}

    destination = Path(tempfile.mkdtemp(prefix="owasp-recall-"))
    code = destination / "code"
    code.mkdir()
    for name in selected:
        source = TESTCASES / f"{name}.java"
        if source.exists():
            shutil.copyfile(source, code / source.name)
    return destination, selected


def testcase_of(chunk: CodeChunk) -> str:
    """Nombre del testcase al que pertenece un chunk (``BenchmarkTest00001.java``)."""
    return Path(chunk.file).stem


def main() -> int:
    """Punto de entrada."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--category", help="Solo esta categoría CWE (ej. cmdi)")
    parser.add_argument("--limit", type=int, help="Cantidad de testcases (balanceado)")
    parser.add_argument(
        "--no-semantic", action="store_true", help="Desactiva la capa 3 (aísla 0-2)"
    )
    parser.add_argument("--hops", type=int, default=2, help="m4_sink_rescue_hops")
    parser.add_argument(
        "--max-rescued",
        type=int,
        default=0,
        help="Tope de la capa 3. 0 = sin tope (mide el techo, no el default real).",
    )
    args = parser.parse_args()

    if not GROUND_TRUTH.exists():
        print(f"Falta el corpus en {VENDOR}", file=sys.stderr)
        return 1

    truth = load_ground_truth()
    corpus, selected = build_corpus(truth, args.category, args.limit)
    print(f"corpus: {len(selected)} testcases → {corpus}")

    started = time.monotonic()
    langs = LanguageService()
    ingestion = m1_ingestion.ingest(corpus / "code", "bench", langs)
    target = m2_target.define_target_directed(
        "procesamiento de entrada HTTP no confiable", ingestion, langs
    )
    graph = m3_graph.build_graph(ingestion, langs)
    kept = _prefilter(ingestion, target, langs, graph, args.hops)

    if not args.no_semantic:
        from hexflaw.services.embedding import get_embedding_service

        embedding = get_embedding_service("local-cpu", {})
        kept_ids = {c.id for c in kept}
        kept += _semantic_rescue(
            [c for c in ingestion.chunks if c.id not in kept_ids],
            target,
            embedding,
            threshold=0.22,
            max_rescued=args.max_rescued or len(ingestion.chunks),
        )
    elapsed = time.monotonic() - started

    covered = {testcase_of(chunk) for chunk in kept}
    stats: Counter[str] = Counter()
    missed: list[str] = []
    for name, (category, vulnerable) in selected.items():
        bucket = "vuln" if vulnerable else "safe"
        if name in covered:
            stats[f"{bucket}_kept"] += 1
        else:
            stats[f"{bucket}_dropped"] += 1
            if vulnerable:
                missed.append(f"{name} ({category})")

    total_vuln = stats["vuln_kept"] + stats["vuln_dropped"]
    total_safe = stats["safe_kept"] + stats["safe_dropped"]
    recall = stats["vuln_kept"] / total_vuln if total_vuln else 0.0
    noise = stats["safe_kept"] / total_safe if total_safe else 0.0

    print(f"\n{'':22}{'llegan al LLM':>15}{'descartados':>14}")
    print(f"  {'VULNERABLES':20}{stats['vuln_kept']:>15}{stats['vuln_dropped']:>14}")
    print(f"  {'seguros':20}{stats['safe_kept']:>15}{stats['safe_dropped']:>14}")
    print(f"\n  RECALL del prefiltro : {recall:6.1%}   ← techo del pipeline")
    print(f"  seguros que igual pasan: {noise:6.1%}   ← lo que se paga en tokens")
    print(f"  chunks totales: {len(ingestion.chunks)} · al LLM: {len(kept)}")
    print(f"  tiempo: {elapsed:.1f}s (sin una sola llamada al LLM)")

    if missed:
        print(f"\n  falsos negativos garantizados ({len(missed)}):")
        for entry in missed[:15]:
            print(f"    {entry}")
        if len(missed) > 15:
            print(f"    … y {len(missed) - 15} más")
    shutil.rmtree(corpus, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

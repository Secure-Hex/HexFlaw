"""Tests de framework awareness (detección + efecto real sobre el code graph)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hexflaw.core.models import CodeGraph
from hexflaw.modules import m1_ingestion, m3_graph
from hexflaw.services import framework_service
from hexflaw.services.framework_service import FrameworkDefinition
from hexflaw.services.language_service import LanguageService

FLASK_APP = '''from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)


@app.route("/hello")
def hello():
    """Handler vulnerable."""
    name = request.args.get("name")
    return show(name)


@app.route("/safe")
def safe():
    """Handler que escapa."""
    name = escape(request.args.get("name"))
    return show(name)


def show(text):
    """Renderiza el template."""
    return render_template_string("<h1>" + text + "</h1>")
'''


def _build(tmp_path: Path, source: str, *, with_frameworks: bool) -> CodeGraph:
    """Ingesta ``source`` y construye el grafo con o sin framework awareness."""
    (tmp_path / "views.py").write_text(source, encoding="utf-8")
    languages = LanguageService()
    ingestion = m1_ingestion.ingest(tmp_path, "p", languages)
    frameworks = framework_service.detect(ingestion.chunks) if with_frameworks else []
    if frameworks:
        sinks, entries = framework_service.overlays(frameworks)
        languages.apply_overlay(sinks, entries)
    taint = {
        language: framework_service.taint_patterns(frameworks, language)
        for language in ingestion.languages
    }
    return m3_graph.build_graph(ingestion, languages, taint)


def test_builtin_definitions_load_and_validate() -> None:
    """Todas las definiciones que se distribuyen deben parsear y validar."""
    definitions = framework_service.load_definitions()
    assert {d.id for d in definitions} >= {
        "flask", "fastapi", "django", "express", "nestjs", "nextjs",
        "spring", "rails", "laravel",
    }
    for definition in definitions:
        assert definition.markers, f"{definition.id} sin marcadores no se detecta nunca"
        assert definition.sink_patterns or definition.sources


def test_detect_needs_a_marker(tmp_path: Path) -> None:
    """Un archivo que no menciona el framework no lo activa."""
    (tmp_path / "plain.py").write_text("def helper(x):\n    return x\n", encoding="utf-8")
    ingestion = m1_ingestion.ingest(tmp_path, "p", LanguageService())
    assert framework_service.detect(ingestion.chunks) == []


def test_detect_flask_from_a_single_file(tmp_path: Path) -> None:
    """Una app de un solo módulo —lo normal en Flask— tiene que detectarse."""
    (tmp_path / "app.py").write_text(FLASK_APP, encoding="utf-8")
    ingestion = m1_ingestion.ingest(tmp_path, "p", LanguageService())
    assert [d.id for d in framework_service.detect(ingestion.chunks)] == ["flask"]


def test_framework_awareness_reveals_the_tainted_flow(tmp_path: Path) -> None:
    """El aporte concreto: sin framework el flujo del atacante no existe.

    ``request.args.get()`` no es una fuente para Python a secas, y un handler HTTP
    no recibe parámetros: sin las fuentes de Flask nada queda tainted y la arista
    ``hello -> show`` nunca se emite. Es el caso que M5 necesita para remontar.
    """
    graph = _build(tmp_path, FLASK_APP, with_frameworks=False)
    names = {n.id: n.name for n in graph.nodes}
    flows = {
        (names[e.from_], names[e.to]): e.sanitized
        for e in graph.edges
        if e.data_vars and e.data_vars != ["<return>"]
    }
    assert ("hello", "show") not in flows
    assert graph.sinks == []


def test_framework_awareness_marks_sink_source_and_sanitizer(tmp_path: Path) -> None:
    """Con Flask activo: sink reconocido, flujo crudo marcado y escape respetado."""
    graph = _build(tmp_path, FLASK_APP, with_frameworks=True)
    names = {n.id: n.name for n in graph.nodes}
    flows = {
        (names[e.from_], names[e.to]): e.sanitized
        for e in graph.edges
        if e.data_vars and e.data_vars != ["<return>"]
    }

    assert flows[("hello", "show")] is False, "el camino sin escape debe quedar crudo"
    assert flows[("safe", "show")] is True, "escape() de markupsafe corta el taint"
    assert "render_template_string" in {sink.function for sink in graph.sinks}


def test_overlay_does_not_lose_builtin_patterns() -> None:
    """El overlay suma; nunca reemplaza lo que ya sabía el lenguaje."""
    languages = LanguageService()
    before = languages.get("python")
    assert before is not None
    languages.apply_overlay({"python": ["custom_sink"]}, {"python": ["@custom.route"]})
    after = languages.get("python")
    assert after is not None
    assert set(before.sink_patterns) <= set(after.sink_patterns)
    assert set(before.entry_point_patterns) <= set(after.entry_point_patterns)
    assert "custom_sink" in after.sink_patterns
    assert "@custom.route" in after.entry_point_patterns


def test_malformed_definition_is_skipped_not_fatal(tmp_path: Path) -> None:
    """Un JSON roto degrada el soporte de ese framework, no aborta el análisis."""
    (tmp_path / "broken.json").write_text('{"frameworks": [{"id": "x"}]}', encoding="utf-8")
    (tmp_path / "ok.json").write_text(
        json.dumps({"frameworks": [{"id": "y", "name": "Y", "language": "python", "markers": ["y"]}]}),
        encoding="utf-8",
    )
    definitions = framework_service.load_definitions(tmp_path)
    assert [d.id for d in definitions] == ["y"]


def test_definition_rejects_oversized_field() -> None:
    """Límite de longitud igual que en las definiciones de lenguaje (T-LANG-2)."""
    with pytest.raises(ValueError, match="excede"):
        FrameworkDefinition.from_dict(
            {"id": "x", "name": "X", "language": "python", "markers": ["x"], "notes": "a" * 501}
        )

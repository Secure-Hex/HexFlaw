"""Tests de M3 — Code Graph Builder y de la integridad del GraphService."""

from __future__ import annotations

from pathlib import Path

from hexflaw.modules import m1_ingestion, m3_graph
from hexflaw.services.graph_service import GraphService
from hexflaw.services.language_service import LanguageService

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _graph():
    langs = LanguageService()
    ingestion = m1_ingestion.ingest(FIXTURES / "sample_c", "proj-1", langs)
    return ingestion, m3_graph.build_graph(ingestion, langs)


def test_graph_nodes_entry_and_sink() -> None:
    _, graph = _graph()
    by_name = {n.name: n for n in graph.nodes}

    assert "main" in by_name and "handle_ping_input" in by_name
    # main contiene 'int main'/'argv' → entry point.
    assert by_name["main"].is_entry_point
    # handle_ping_input contiene system()/sprintf → sink.
    assert by_name["handle_ping_input"].is_sink
    assert any(s.sink_type == "command_execution" for s in graph.sinks)


def test_graph_call_edge_main_to_handler() -> None:
    _, graph = _graph()
    by_name = {n.name: n.id for n in graph.nodes}
    edge_pairs = {(e.from_, e.to) for e in graph.edges}
    assert (by_name["main"], by_name["handle_ping_input"]) in edge_pairs


def test_graph_service_integrity_roundtrip(tmp_path: Path) -> None:
    ingestion, graph = _graph()
    service = GraphService(tmp_path)
    digest = m3_graph.source_hash(ingestion)

    service.save(graph, digest)
    loaded = service.load_if_valid(digest)
    assert loaded is not None
    assert len(loaded.nodes) == len(graph.nodes)

    # Distinto source hash → no se usa la caché.
    assert service.load_if_valid("otro-hash") is None


def test_graph_service_detects_tampering(tmp_path: Path) -> None:
    ingestion, graph = _graph()
    service = GraphService(tmp_path)
    digest = m3_graph.source_hash(ingestion)
    service.save(graph, digest)

    # Manipulación externa del code_graph.json (T-M3-2).
    from hexflaw.infrastructure import storage

    payload = storage.read_json(service.graph_path)
    payload["nodes"] = []
    storage.write_json(service.graph_path, payload)

    assert service.load_if_valid(digest) is None  # integridad rota → regenerar

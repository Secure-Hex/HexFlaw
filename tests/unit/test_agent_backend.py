"""Tests del backend LLM 'agente en el loop' (cola de archivos, sin tokens)."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from hexflaw.infrastructure.config import resolve_config
from hexflaw.services.llm_service import (
    AgentQueueLLMService,
    LLMServiceError,
    build_llm_service,
)


def test_factory_builds_agent_backend(tmp_path: Path) -> None:
    cfg = resolve_config(
        overrides={"llm_backend": "agent", "agent_queue_dir": str(tmp_path)}
    )
    svc = build_llm_service(cfg)
    assert isinstance(svc, AgentQueueLLMService)
    assert svc.queue_dir == str(tmp_path)


def test_roundtrip_parks_request_and_consumes_response(tmp_path: Path) -> None:
    svc = AgentQueueLLMService(queue_dir=str(tmp_path), poll_timeout=5, poll_interval=0.05)
    result: dict = {}

    def run() -> None:
        result["resp"] = svc.analyze_code(
            "Analyze. Output JSON only.",
            "system(cmd)",
            model="claude-haiku-4-5",
            trace_label="M4 batch 1/1",
        )

    worker = threading.Thread(target=run)
    worker.start()

    # El agente: espera el request, lo lee y deja la respuesta.
    deadline = time.monotonic() + 5
    reqs: list[Path] = []
    while not reqs and time.monotonic() < deadline:
        reqs = list(tmp_path.glob("req-*.json"))
        time.sleep(0.02)
    assert reqs, "el pipeline no parkeó ningún request"

    data = json.loads(reqs[0].read_text())
    assert data["label"] == "M4 batch 1/1"
    assert "<CODE>" in data["prompt"]  # el código va aislado en delimitadores
    rid = data["id"]
    (tmp_path / f"res-{rid}.json").write_text(json.dumps({"id": rid, "text": "{\"findings\":[]}"}))

    worker.join(timeout=6)
    resp = result["resp"]
    assert resp.text == '{"findings":[]}'
    assert resp.output_tokens > 0  # estimado cuando el agente no reporta tokens
    # Tras consumir, ambos archivos quedan archivados en done/.
    assert not (tmp_path / f"req-{rid}.json").exists()
    assert (tmp_path / "done" / f"res-{rid}.json").exists()


def test_timeout_when_no_response(tmp_path: Path) -> None:
    svc = AgentQueueLLMService(queue_dir=str(tmp_path), poll_timeout=0.3, poll_interval=0.05)
    with pytest.raises(LLMServiceError, match="Timeout"):
        svc.analyze_code("x", "y", model="claude-haiku-4-5")

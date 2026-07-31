"""Tests del backend LLM 'agente en el loop' (cola de archivos, sin tokens)."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from hexflaw.core.model_policy import ModelTier
from hexflaw.infrastructure.config import Config, resolve_config
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
    result: dict[str, Any] = {}

    def run() -> None:
        result["resp"] = svc.analyze_code(
            "Analyze. Output JSON only.",
            "system(cmd)",
            model=ModelTier.CHEAP,
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
    # El request nombra el modelo CONCRETO, no el tier: quien lo responde necesita
    # saber qué capacidad se espera, y "cheap" no se lo dice.
    assert data["model"] == "claude-haiku-4-5-20251001"
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
        svc.analyze_code("x", "y", model=ModelTier.CHEAP)


def test_agent_backend_is_not_rate_limited(tmp_path: Path) -> None:
    """El backend 'agent' no puede heredar el rate limit de la API.

    No llama a ninguna API: escribe archivos en disco y los contesta un agente
    externo con su propia suscripción. El techo de tokens-por-minuto existe para
    esquivar un 429 de Anthropic, y acá no hay 429 posible — solo sueño.

    Medido sobre una corrida real (wallos, PHP): batches de ~21,5k tokens contra el
    techo de 40k/min hacían dormir ~35 s por batch mientras el agente respondía en
    27 s. Más de la mitad del reloj esperando permiso para algo que no lo necesita.
    """
    cfg = Config(
        values={
            "llm_backend": "agent",
            "agent_queue_dir": str(tmp_path),
            "rate_limit_tokens_per_min": 40_000,
        }
    )
    svc = build_llm_service(cfg)

    assert isinstance(svc, AgentQueueLLMService)
    assert svc.rate_limit_tpm is None
    # El budget SÍ se conserva: acota el trabajo total, no el ritmo.
    assert build_llm_service(
        Config(values={"llm_backend": "agent", "agent_queue_dir": str(tmp_path), "token_budget": 123})
    ).token_budget == 123


def test_api_backends_keep_their_rate_limit(tmp_path: Path) -> None:
    """Los backends que sí pegan contra una API conservan el pacing."""
    for backend in ("api", "openai"):
        cfg = Config(values={"llm_backend": backend, "rate_limit_tokens_per_min": 40_000})
        assert build_llm_service(cfg).rate_limit_tpm == 40_000

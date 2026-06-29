"""Backends de embeddings intercambiables (CLAUDE.md §7).

La selección de backend nunca se hardcodea: se resuelve desde la configuración
y se inyecta por el orchestrator.
"""

from __future__ import annotations

from typing import Any

from hexflaw.services.embedding.base import EmbeddingService
from hexflaw.services.embedding.local_cpu import LocalCPUEmbedding
from hexflaw.services.embedding.ollama import OllamaEmbedding
from hexflaw.services.embedding.openai import OpenAIEmbedding
from hexflaw.services.embedding.voyage import VoyageEmbedding

__all__ = [
    "EmbeddingService",
    "LocalCPUEmbedding",
    "OllamaEmbedding",
    "OpenAIEmbedding",
    "VoyageEmbedding",
    "get_embedding_service",
]


def get_embedding_service(
    backend: str, config: dict[str, Any] | None = None
) -> EmbeddingService:
    """Factory de backends de embeddings por identificador.

    Args:
        backend: Identificador del backend (``local-cpu`` | ``ollama`` |
            ``voyage`` | ``openai``).
        config: Valores de configuración (API keys, modelos, host). Opcional
            para backends que no los requieren.

    Returns:
        Instancia concreta de :class:`EmbeddingService`.

    Raises:
        ValueError: Si el backend no está soportado o falta su API key.
    """
    cfg = config or {}
    if backend in ("local-cpu", "local"):
        from hexflaw.services.embedding.local_cpu import DEFAULT_MODEL

        return LocalCPUEmbedding(
            model_name=cfg.get("local_embedding_model", DEFAULT_MODEL),
            trust_remote_code=bool(cfg.get("local_embedding_trust_remote_code", False)),
        )
    if backend == "ollama":
        return OllamaEmbedding(
            model=cfg.get("ollama_embedding_model", "nomic-embed-text"),
            host=cfg.get("ollama_host", "http://127.0.0.1:11434"),
        )
    if backend == "voyage":
        return VoyageEmbedding(api_key=cfg.get("voyage_api_key", ""))
    if backend == "openai":
        return OpenAIEmbedding(api_key=cfg.get("openai_api_key", ""))
    raise ValueError(f"Backend de embeddings '{backend}' no soportado.")

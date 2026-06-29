"""Tests del backend de embeddings local (fallback determinístico)."""

from __future__ import annotations

import math

from hexflaw.services.embedding import LocalCPUEmbedding, get_embedding_service


def test_factory_returns_local_cpu() -> None:
    service = get_embedding_service("local-cpu")
    assert isinstance(service, LocalCPUEmbedding)


def test_embedding_is_deterministic_and_normalized() -> None:
    service = LocalCPUEmbedding(dim=128)
    # Forzamos el fallback por hashing (sin modelo neuronal cargado).
    service._model = None

    v1 = service.embed("system(cmd)")
    v2 = service.embed("system(cmd)")
    assert v1 == v2  # determinístico

    norm = math.sqrt(sum(x * x for x in v1))
    assert abs(norm - 1.0) < 1e-6  # L2-normalizado


def test_embed_batch_matches_single() -> None:
    service = LocalCPUEmbedding(dim=64)
    service._model = None
    chunks = ["foo()", "bar()"]
    batch = service.embed_batch(chunks)
    assert batch[0] == service.embed("foo()")
    assert len(batch) == 2


def test_unknown_backend_raises() -> None:
    import pytest

    with pytest.raises(ValueError):
        get_embedding_service("voyage")

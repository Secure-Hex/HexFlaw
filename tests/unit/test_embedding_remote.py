"""Tests de los backends de embeddings remotos y el factory (sin red)."""

from __future__ import annotations

import pytest

from hexflaw.services.embedding import (
    OllamaEmbedding,
    OpenAIEmbedding,
    VoyageEmbedding,
    get_embedding_service,
)


def test_factory_builds_ollama() -> None:
    service = get_embedding_service("ollama", {"ollama_host": "http://h:1"})
    assert isinstance(service, OllamaEmbedding)
    assert service.backend_id == "ollama"


def test_factory_builds_voyage_with_key() -> None:
    service = get_embedding_service("voyage", {"voyage_api_key": "pa-x"})
    assert isinstance(service, VoyageEmbedding)


def test_voyage_requires_key() -> None:
    with pytest.raises(ValueError):
        get_embedding_service("voyage", {})


def test_openai_requires_key() -> None:
    with pytest.raises(ValueError):
        get_embedding_service("openai", {})


def test_factory_unknown_backend() -> None:
    with pytest.raises(ValueError):
        get_embedding_service("nope", {})


def test_openai_constructs_with_key() -> None:
    service = OpenAIEmbedding(api_key="sk-x")
    assert service.dim == 1536

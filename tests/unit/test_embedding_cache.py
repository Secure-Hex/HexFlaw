"""Tests del wrapper cacheante de embeddings (CLAUDE.md §16, estrategia 3)."""

from __future__ import annotations

from pathlib import Path

from hexflaw.services.embedding.base import EmbeddingService
from hexflaw.services.embedding.caching import CachingEmbeddingService


class CountingEmbedding(EmbeddingService):
    """Embedding determinístico que cuenta cuántos vectores computa."""

    backend_id = "counting"

    def __init__(self) -> None:
        self.dim = 4
        self.computed = 0

    def embed(self, code: str) -> list[float]:
        self.computed += 1
        return [float(len(code)), 1.0, 2.0, 3.0]

    def embed_batch(self, chunks: list[str]) -> list[list[float]]:
        return [self.embed(c) for c in chunks]


def test_cache_avoids_recompute_across_instances(tmp_path: Path) -> None:
    path = tmp_path / "cache" / "emb.json"

    inner1 = CountingEmbedding()
    svc1 = CachingEmbeddingService(inner1, path)
    svc1.embed_batch(["aaa", "bb", "c"])
    assert inner1.computed == 3  # primera vez: computa todo
    svc1.flush()

    # Nueva instancia (simula otro run): debe leer del caché en disco.
    inner2 = CountingEmbedding()
    svc2 = CachingEmbeddingService(inner2, path)
    vecs = svc2.embed_batch(["aaa", "bb", "c"])
    assert inner2.computed == 0  # todo cacheado → 0 cómputos
    assert svc2.hits == 3
    assert len(vecs) == 3


def test_cache_partial_hit(tmp_path: Path) -> None:
    path = tmp_path / "emb.json"
    inner = CountingEmbedding()
    svc = CachingEmbeddingService(inner, path)
    svc.embed_batch(["x", "y"])  # 2 misses
    inner.computed = 0
    svc.embed_batch(["x", "y", "z"])  # x,y cacheados; solo z se computa
    assert inner.computed == 1
    # Contadores acumulativos: 2 hits (x,y en la 2ª llamada), 3 misses (x,y,z únicos).
    assert svc.hits == 2 and svc.misses == 3


def test_cache_invalidated_on_model_change(tmp_path: Path) -> None:
    path = tmp_path / "emb.json"
    inner1 = CountingEmbedding()
    svc1 = CachingEmbeddingService(inner1, path)
    svc1.embed("hello")
    svc1.flush()

    # Otro backend (distinto model key) → no debe reusar el caché previo.
    inner2 = CountingEmbedding()
    inner2.backend_id = "otro-modelo"
    svc2 = CachingEmbeddingService(inner2, path)
    svc2.embed("hello")
    assert inner2.computed == 1  # recomputó por cambio de modelo

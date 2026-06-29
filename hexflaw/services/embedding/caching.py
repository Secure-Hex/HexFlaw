"""Wrapper cacheante de embeddings (CLAUDE.md §16, estrategia 3 aplicada a vectores).

Cachea los vectores por hash del contenido para no re-embeber el mismo código en
runs sucesivos. Es transparente: implementa la misma interfaz
:class:`EmbeddingService`, así que M4 no necesita cambios. El caché se invalida
automáticamente si cambia el backend o el modelo subyacente.

Persiste en ``.hexflaw/cache/embedding_cache.json``.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from hexflaw.infrastructure import storage
from hexflaw.infrastructure.logging import get_logger
from hexflaw.services.embedding.base import EmbeddingService

logger = get_logger(__name__)

# Precisión de almacenamiento: 6 decimales son irrelevantes para coseno y
# reducen el tamaño del JSON respecto a float64 completo.
_ROUND = 6


class CachingEmbeddingService(EmbeddingService):
    """Decora un :class:`EmbeddingService` con caché de vectores por hash."""

    def __init__(self, inner: EmbeddingService, cache_path: Path) -> None:
        """Inicializa el wrapper.

        Args:
            inner: Backend de embeddings real a decorar.
            cache_path: Ruta del archivo de caché persistente.
        """
        self.inner = inner
        self.backend_id = f"cached:{inner.backend_id}"
        self.dim = inner.dim
        self.cache_path = cache_path
        self.hits = 0
        self.misses = 0
        self._cache: dict[str, list[float]] = {}
        self._dirty = False
        self._load()

    def _model_key(self) -> str:
        """Clave que identifica backend+modelo+dim (invalida si cambia)."""
        model = getattr(self.inner, "model_name", "")
        return f"{self.inner.backend_id}|{model}|{self.inner.dim}"

    def _load(self) -> None:
        if not self.cache_path.exists():
            return
        try:
            data = storage.read_json(self.cache_path)
        except (ValueError, OSError) as exc:
            logger.warning("Caché de embeddings ilegible (%s); ignorando", exc)
            return
        if data.get("key") != self._model_key():
            logger.info("Caché de embeddings de otro modelo; se ignora")
            return
        self._cache = data.get("vectors", {})
        logger.debug("Caché de embeddings cargado: %d vectores", len(self._cache))

    @staticmethod
    def _key(code: str) -> str:
        return hashlib.sha256(code.encode("utf-8", errors="replace")).hexdigest()

    def embed(self, code: str) -> list[float]:
        """Embedding de un fragmento, usando caché por hash (ver base)."""
        key = self._key(code)
        cached = self._cache.get(key)
        if cached is not None:
            self.hits += 1
            return cached
        self.misses += 1
        vec = [round(x, _ROUND) for x in self.inner.embed(code)]
        self._cache[key] = vec
        self._dirty = True
        return vec

    def embed_batch(self, chunks: list[str]) -> list[list[float]]:
        """Embeddings en lote: usa caché para los hits y computa solo los misses."""
        result: list[list[float] | None] = [None] * len(chunks)
        misses: list[tuple[int, str]] = []
        for i, code in enumerate(chunks):
            cached = self._cache.get(self._key(code))
            if cached is not None:
                self.hits += 1
                result[i] = cached
            else:
                misses.append((i, code))

        if misses:
            self.misses += len(misses)
            computed = self.inner.embed_batch([code for _, code in misses])
            for (i, code), vec in zip(misses, computed):
                rounded = [round(x, _ROUND) for x in vec]
                self._cache[self._key(code)] = rounded
                result[i] = rounded
                self._dirty = True
        return [vec for vec in result if vec is not None]

    def flush(self) -> None:
        """Persiste el caché a disco si hubo cambios."""
        if not self._dirty:
            return
        storage.write_json(
            self.cache_path, {"key": self._model_key(), "vectors": self._cache}
        )
        self._dirty = False
        logger.info(
            "Caché de embeddings: %d hits, %d misses (%d vectores totales)",
            self.hits,
            self.misses,
            len(self._cache),
        )

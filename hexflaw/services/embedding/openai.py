"""Backend de embeddings OpenAI (CLAUDE.md §7).

⚠️ Privacidad: envía el código a la API de OpenAI para vectorizarlo. Úsalo solo
por decisión explícita; el default recomendado es ``local-cpu``.
"""

from __future__ import annotations

from hexflaw.infrastructure.logging import get_logger
from hexflaw.services.embedding._http import EmbeddingHTTPError, post_json
from hexflaw.services.embedding.base import EmbeddingService

logger = get_logger(__name__)

_ENDPOINT = "https://api.openai.com/v1/embeddings"


class OpenAIEmbedding(EmbeddingService):
    """Embeddings vía OpenAI."""

    backend_id = "openai"

    def __init__(self, api_key: str, model: str = "text-embedding-3-small") -> None:
        """Inicializa el backend.

        Args:
            api_key: API key de OpenAI.
            model: Modelo de embeddings.

        Raises:
            ValueError: Si no se proporciona API key.
        """
        if not api_key:
            raise ValueError("OpenAIEmbedding requiere una API key de OpenAI.")
        self.api_key = api_key
        self.model = model
        self.dim = 1536  # text-embedding-3-small

    def embed(self, code: str) -> list[float]:
        """Genera el embedding de un fragmento (ver :class:`EmbeddingService`)."""
        return self.embed_batch([code])[0]

    def embed_batch(self, chunks: list[str]) -> list[list[float]]:
        """Genera embeddings en lote (ver base)."""
        if not chunks:
            return []
        try:
            response = post_json(
                _ENDPOINT,
                {"input": chunks, "model": self.model},
                {"Authorization": f"Bearer {self.api_key}"},
            )
        except EmbeddingHTTPError as exc:
            logger.error("Fallo en OpenAI embeddings: %s", exc)
            raise
        items = sorted(response.get("data", []), key=lambda d: d.get("index", 0))
        return [list(item["embedding"]) for item in items]

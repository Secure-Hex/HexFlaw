"""Backend de embeddings Voyage AI (CLAUDE.md §7).

⚠️ Privacidad: este backend envía el código a la API de Voyage para vectorizarlo.
Úsalo solo por decisión explícita; el default recomendado es ``local-cpu``.
"""

from __future__ import annotations

from hexflaw.infrastructure.logging import get_logger
from hexflaw.services.embedding._http import EmbeddingHTTPError, post_json
from hexflaw.services.embedding.base import EmbeddingService

logger = get_logger(__name__)

_ENDPOINT = "https://api.voyageai.com/v1/embeddings"


class VoyageEmbedding(EmbeddingService):
    """Embeddings vía Voyage AI (modelo orientado a código)."""

    backend_id = "voyage"

    def __init__(self, api_key: str, model: str = "voyage-code-2") -> None:
        """Inicializa el backend.

        Args:
            api_key: API key de Voyage AI.
            model: Modelo de embeddings a usar.

        Raises:
            ValueError: Si no se proporciona API key.
        """
        if not api_key:
            raise ValueError("VoyageEmbedding requiere una API key de Voyage.")
        self.api_key = api_key
        self.model = model
        self.dim = 1536  # voyage-code-2

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
            logger.error("Fallo en Voyage embeddings: %s", exc)
            raise
        items = sorted(response.get("data", []), key=lambda d: d.get("index", 0))
        return [list(item["embedding"]) for item in items]

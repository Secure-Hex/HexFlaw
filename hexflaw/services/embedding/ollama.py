"""Backend de embeddings Ollama (CLAUDE.md §7).

Offline: corre contra un servidor Ollama local. Recomendado cuando hay GPU
disponible (CLAUDE.md §6 M0). No envía código fuera de la máquina.
"""

from __future__ import annotations

from hexflaw.infrastructure.logging import get_logger
from hexflaw.services.embedding._http import EmbeddingHTTPError, post_json
from hexflaw.services.embedding.base import EmbeddingService

logger = get_logger(__name__)


class OllamaEmbedding(EmbeddingService):
    """Embeddings vía un servidor Ollama local."""

    backend_id = "ollama"

    def __init__(
        self,
        model: str = "nomic-embed-text",
        host: str = "http://127.0.0.1:11434",
    ) -> None:
        """Inicializa el backend.

        Args:
            model: Modelo de embeddings cargado en Ollama.
            host: URL base del servidor Ollama.
        """
        self.model = model
        self.host = host.rstrip("/")
        self.dim = 768  # nomic-embed-text

    def embed(self, code: str) -> list[float]:
        """Genera el embedding de un fragmento (ver :class:`EmbeddingService`)."""
        try:
            response = post_json(
                f"{self.host}/api/embeddings",
                {"model": self.model, "prompt": code},
                {},
            )
        except EmbeddingHTTPError as exc:
            logger.error("Fallo en Ollama embeddings: %s", exc)
            raise
        return list(response.get("embedding", []))

    def embed_batch(self, chunks: list[str]) -> list[list[float]]:
        """Genera embeddings en lote (Ollama vectoriza de a uno)."""
        return [self.embed(chunk) for chunk in chunks]

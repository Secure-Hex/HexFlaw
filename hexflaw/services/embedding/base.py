"""Interfaz base de embeddings (CLAUDE.md §7).

Privacidad por diseño: si un backend usa una API externa, solo deben salir
vectores numéricos, nunca código en texto plano (CLAUDE.md §2.3).
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class EmbeddingService(ABC):
    """Contrato que todo backend de embeddings debe implementar."""

    #: Identificador estable del backend (usado en config y caché).
    backend_id: str = "abstract"

    #: Dimensionalidad de los vectores producidos.
    dim: int = 0

    @abstractmethod
    def embed(self, code: str) -> list[float]:
        """Genera el embedding de un fragmento de código.

        Args:
            code: Texto del código a vectorizar.

        Returns:
            Vector de floats de longitud :attr:`dim`.
        """

    @abstractmethod
    def embed_batch(self, chunks: list[str]) -> list[list[float]]:
        """Genera embeddings para múltiples fragmentos.

        Args:
            chunks: Lista de fragmentos de código.

        Returns:
            Lista de vectores, uno por fragmento, en el mismo orden.
        """

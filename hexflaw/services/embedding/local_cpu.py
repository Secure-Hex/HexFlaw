"""Backend de embeddings local en CPU (CLAUDE.md §7).

Usa ``sentence-transformers`` con un modelo de code search si está instalado.
El modelo es configurable (``local_embedding_model``); el default es un modelo
nativo de sentence-transformers entrenado para búsqueda de código, sin requerir
``trust_remote_code`` — relevante en una herramienta de seguridad, donde no se
debe ejecutar código remoto arbitrario de HuggingFace.

Si ``sentence-transformers`` no está instalado (o el modelo falla en cargar),
cae a un embedding determinístico por hashing de tokens que funciona offline y
sin dependencias pesadas — menor calidad, pero suficiente para el pre-filtrado.
"""

from __future__ import annotations

import hashlib
import math
import re

from hexflaw.infrastructure.logging import get_logger
from hexflaw.services.embedding.base import EmbeddingService

logger = get_logger(__name__)

_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|[^\sA-Za-z0-9_]")

#: Modelo por defecto: nativo de sentence-transformers, entrenado en CodeSearchNet.
DEFAULT_MODEL = "flax-sentence-embeddings/st-codesearch-distilroberta-base"


class LocalCPUEmbedding(EmbeddingService):
    """Embeddings locales en CPU con fallback determinístico sin dependencias."""

    backend_id = "local-cpu"

    def __init__(
        self,
        dim: int = 256,
        model_name: str = DEFAULT_MODEL,
        *,
        trust_remote_code: bool = False,
    ) -> None:
        """Inicializa el backend.

        Args:
            dim: Dimensionalidad del fallback por hashing (si no carga el modelo).
            model_name: Modelo de sentence-transformers a usar.
            trust_remote_code: Permite código remoto del modelo (default ``False``
                por seguridad; necesario para algunos modelos como jina-code).
        """
        self.dim = dim
        self.model_name = model_name
        self.trust_remote_code = trust_remote_code
        self._model = self._try_load_model()

    def _try_load_model(self) -> object | None:
        """Carga perezosa de sentence-transformers si está disponible."""
        try:
            from sentence_transformers import SentenceTransformer

            model = SentenceTransformer(
                self.model_name, trust_remote_code=self.trust_remote_code
            )
            self.dim = model.get_sentence_embedding_dimension() or self.dim
            logger.info(
                "LocalCPUEmbedding usando sentence-transformers (%s)", self.model_name
            )
            return model  # type: ignore[no-any-return]
        except Exception as exc:  # ImportError o descarga fallida → fallback
            logger.info(
                "Modelo '%s' no cargó (%s); usando fallback por hashing",
                self.model_name,
                type(exc).__name__,
            )
            return None

    def embed(self, code: str) -> list[float]:
        """Genera el embedding de un fragmento (ver :class:`EmbeddingService`)."""
        if self._model is not None:
            vec = self._model.encode(code, normalize_embeddings=True)  # type: ignore[attr-defined]
            return [float(x) for x in vec]
        return self._hashing_embed(code)

    def embed_batch(self, chunks: list[str]) -> list[list[float]]:
        """Genera embeddings para múltiples fragmentos (ver base)."""
        if self._model is not None:
            vecs = self._model.encode(chunks, normalize_embeddings=True)  # type: ignore[attr-defined]
            return [[float(x) for x in v] for v in vecs]
        return [self._hashing_embed(c) for c in chunks]

    def _hashing_embed(self, code: str) -> list[float]:
        """Embedding determinístico por hashing trick, L2-normalizado.

        Cada token incrementa una posición del vector determinada por su hash
        SHA-256, con signo derivado del mismo hash. Aproxima similitud de
        bag-of-tokens — barata y reproducible entre runs.
        """
        vec = [0.0] * self.dim
        for token in _TOKEN_RE.findall(code.lower()):
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            idx = int.from_bytes(digest[:4], "big") % self.dim
            sign = 1.0 if digest[4] & 1 else -1.0
            vec[idx] += sign
        norm = math.sqrt(sum(x * x for x in vec))
        if norm == 0.0:
            return vec
        return [x / norm for x in vec]

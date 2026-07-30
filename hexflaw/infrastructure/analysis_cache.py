"""Caché de análisis por hash de chunk (CLAUDE.md §16, estrategia 3).

Si un chunk ya fue analizado y su SHA-256 no cambió, se reutiliza el resultado
sin llamar al LLM. La caché se invalida cuando cambia el modelo o el vuln_profile
activo (forman parte de la clave).

Persiste en ``.hexflaw/cache/analysis_cache.json``.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from hexflaw.infrastructure import storage
from hexflaw.infrastructure.logging import get_logger

logger = get_logger(__name__)


class AnalysisCache:
    """Caché key-value de findings por chunk, modelo y perfil de vulns."""

    def __init__(self, hexflaw_dir: Path) -> None:
        """Inicializa la caché anclada al proyecto.

        Args:
            hexflaw_dir: Directorio ``.hexflaw/`` del proyecto.
        """
        self.path = hexflaw_dir / "cache" / "analysis_cache.json"
        self._data: dict[str, list[dict[str, Any]]] = {}
        self.hits = 0
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                self._data = dict(storage.read_json(self.path))
            except (ValueError, OSError) as exc:
                logger.warning("Caché de análisis ilegible (%s); ignorando", exc)
                self._data = {}

    @staticmethod
    def make_key(
        chunk_hash: str,
        model: str,
        vuln_profile: list[str],
        prompt_version: int = 1,
    ) -> str:
        """Construye la clave de caché combinando chunk, modelo, perfil y prompt.

        ``prompt_version`` es imprescindible: la respuesta cacheada depende tanto
        del código como de **lo que se le preguntó al modelo**. Cuando el prompt
        de M4 cambia de forma material —por ejemplo al empezar a incluir el
        contexto del grafo en la cabecera de cada chunk— las respuestas viejas
        dejan de ser equivalentes, y sin versionar la clave un proyecto ya
        analizado se quedaría con ellas para siempre.

        Args:
            chunk_hash: SHA-256 del texto del chunk.
            model: Modelo usado en el análisis.
            vuln_profile: Perfil de vulnerabilidades activo.
            prompt_version: Versión del prompt que produjo la respuesta.

        Returns:
            Clave hexadecimal estable.
        """
        material = (
            f"{chunk_hash}|{model}|{','.join(sorted(vuln_profile))}|v{prompt_version}"
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def get(self, key: str) -> list[dict[str, Any]] | None:
        """Devuelve los findings cacheados para ``key``, o ``None``."""
        value = self._data.get(key)
        if value is not None:
            self.hits += 1
        return value

    def set(self, key: str, findings: list[dict[str, Any]]) -> None:
        """Almacena los findings de un chunk bajo ``key`` (en memoria)."""
        self._data[key] = findings

    def flush(self) -> None:
        """Persiste la caché a disco con permisos ``600``."""
        storage.write_json(self.path, self._data)

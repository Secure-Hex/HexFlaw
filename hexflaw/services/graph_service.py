"""GraphService — persistencia e integridad del code graph (CLAUDE.md §14, §15).

El ``code_graph.json`` es el artefacto más crítico del pipeline. Si existe y el
código no cambió (hash de la ingestión) no se re-ejecuta M3: se carga de disco.

Integridad (T-M3-2): se almacena el SHA-256 del grafo en un sidecar y se verifica
antes de cargarlo; si no coincide, se fuerza regeneración.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from hexflaw.core.models import CodeGraph
from hexflaw.infrastructure import storage
from hexflaw.infrastructure.logging import get_logger

logger = get_logger(__name__)


class GraphService:
    """Lee/escribe el code graph con verificación de integridad y caché.

    Attributes:
        graph_path: Ruta a ``code_graph.json``.
        integrity_path: Ruta al sidecar con ``{sha256, source_hash}``.
    """

    def __init__(self, hexflaw_dir: Path) -> None:
        """Inicializa el servicio anclado al ``.hexflaw/`` del proyecto.

        Args:
            hexflaw_dir: Directorio de datos del proyecto.
        """
        self.graph_path = hexflaw_dir / "code_graph.json"
        self.integrity_path = hexflaw_dir / "code_graph.integrity.json"

    def save(self, graph: CodeGraph, source_hash: str) -> None:
        """Persiste el grafo con permisos ``600`` y su sidecar de integridad.

        Args:
            graph: Grafo a persistir.
            source_hash: Hash agregado del codebase que produjo este grafo
                (para decidir si re-ejecutar M3 en runs futuros).
        """
        payload = graph.model_dump(mode="json", by_alias=True)
        serialized = json.dumps(payload, sort_keys=True, default=str)
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        storage.write_json(self.graph_path, payload)
        storage.write_json(
            self.integrity_path, {"sha256": digest, "source_hash": source_hash}
        )
        logger.debug("code_graph.json persistido (sha256=%s)", digest[:12])

    def load_if_valid(self, source_hash: str) -> CodeGraph | None:
        """Carga el grafo cacheado si es íntegro y corresponde al código actual.

        Args:
            source_hash: Hash agregado del codebase actual.

        Returns:
            El grafo cacheado válido, o ``None`` si hay que regenerarlo.
        """
        if not (self.graph_path.exists() and self.integrity_path.exists()):
            return None
        try:
            integrity = storage.read_json(self.integrity_path)
            payload = storage.read_json(self.graph_path)
        except (ValueError, OSError) as exc:
            logger.warning("No se pudo leer code_graph cacheado: %s", exc)
            return None

        if integrity.get("source_hash") != source_hash:
            logger.info("El código cambió; se regenerará el code graph")
            return None

        serialized = json.dumps(payload, sort_keys=True, default=str)
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        if digest != integrity.get("sha256"):
            logger.warning("Integridad de code_graph.json comprometida; regenerando")
            return None

        logger.info("code_graph.json válido en caché; M3 no se re-ejecuta")
        return CodeGraph.model_validate(payload)

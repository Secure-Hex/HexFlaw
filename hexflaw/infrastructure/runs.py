"""Historial de análisis: cada ``analyze`` se archiva como un run con su ID.

Un nuevo análisis ya no sobrescribe el anterior: se guarda bajo
``.hexflaw/runs/<run_id>/`` y se actualiza un índice. La copia "latest" se
mantiene en ``.hexflaw/findings.json`` para que ``report``/``poc``/``findings``
operen sobre el último run por defecto.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from hexflaw.core.models import FindingSet
from hexflaw.infrastructure import storage
from hexflaw.infrastructure.logging import get_logger

logger = get_logger(__name__)


def new_run_id() -> str:
    """Genera un ID de run legible: ``run-YYYYMMDD-HHMMSS-<4hex>``."""
    now = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"run-{now}-{uuid4().hex[:4]}"


class RunStore:
    """Persiste y consulta el historial de runs de análisis."""

    def __init__(self, hexflaw_dir: Path) -> None:
        """Inicializa el store anclado al ``.hexflaw/`` del proyecto."""
        self.dir = hexflaw_dir / "runs"
        self.index_path = self.dir / "index.json"

    def save_run(self, run_id: str, findings: FindingSet, meta: dict[str, Any]) -> None:
        """Archiva un run (findings + metadata) y actualiza el índice.

        Args:
            run_id: Identificador del run.
            findings: Hallazgos del run.
            meta: Metadata (target, paths, mode, conteos por estado).
        """
        run_dir = storage.ensure_dir(self.dir / run_id)
        storage.write_json(run_dir / "findings.json", findings.model_dump(mode="json"))
        record = {"run_id": run_id, **meta}
        storage.write_json(run_dir / "meta.json", record)

        index = self._load_index()
        index["latest"] = run_id
        index["runs"] = [r for r in index.get("runs", []) if r.get("run_id") != run_id]
        index["runs"].append(record)
        storage.write_json(self.index_path, index)
        logger.info("Run archivado: %s", run_id)

    def list_runs(self) -> list[dict[str, Any]]:
        """Devuelve la metadata de todos los runs, del más reciente al más viejo."""
        runs = self._load_index().get("runs", [])
        return sorted(runs, key=lambda r: r.get("created_at", ""), reverse=True)

    def latest_id(self) -> str | None:
        """ID del run más reciente, o ``None`` si no hay runs."""
        return self._load_index().get("latest")

    def load_run(self, run_id: str) -> FindingSet:
        """Carga los findings de un run específico.

        Raises:
            FileNotFoundError: Si el run no existe.
        """
        path = self.dir / run_id / "findings.json"
        if not path.exists():
            raise FileNotFoundError(f"No existe el run '{run_id}'.")
        return FindingSet.model_validate(storage.read_json(path))

    def _load_index(self) -> dict[str, Any]:
        if not self.index_path.exists():
            return {"latest": None, "runs": []}
        try:
            return dict(storage.read_json(self.index_path))
        except (ValueError, OSError):
            return {"latest": None, "runs": []}

"""M6c — PoC Generator (CLAUDE.md §6 M6c, §15 M6c).

Por cada hallazgo confirmado genera un directorio de PoC estático con payloads
seguros y disclaimer. HexFlaw nunca ejecuta el PoC (inamovible por diseño).

Corre en paralelo con M6b una vez que M6a finaliza.
"""

from __future__ import annotations

from pathlib import Path

from hexflaw.core.models import RootCause
from hexflaw.infrastructure import storage
from hexflaw.infrastructure.logging import get_logger
from hexflaw.services import poc_service
from hexflaw.services.llm_service import LLMService

logger = get_logger(__name__)


def generate_pocs(
    root_causes: list[RootCause],
    poc_dir: Path,
    *,
    llm: LLMService | None = None,
    model: str | None = None,
    code_by_finding: dict[str, str] | None = None,
) -> list[Path]:
    """Genera el directorio de PoC de cada hallazgo.

    Args:
        root_causes: Root causes producidos por M6a.
        poc_dir: Directorio raíz de PoCs (``.hexflaw/poc/``).
        llm: Servicio LLM. Si se provee, el ``poc.py`` se genera adaptado al
            target; si no, se usa el template estático.
        model: Modelo para la generación del PoC.
        code_by_finding: Código de la función vulnerable por ``finding_id``.

    Returns:
        Lista de rutas de directorios de PoC creados.
    """
    storage.ensure_dir(poc_dir)
    code_by_finding = code_by_finding or {}
    created: list[Path] = []
    for rc in root_causes:
        target = storage.ensure_dir(poc_dir / f"{rc.finding_id}_{rc.type}")
        if llm is not None:
            files = poc_service.render_poc_llm(
                rc, llm, model=model, code_context=code_by_finding.get(rc.finding_id, "")
            )
        else:
            files = poc_service.render_poc(rc)
        _write(target / "poc.py", files.poc_py)
        _write(target / "README.md", files.readme_md)
        _write(target / "requirements.txt", files.requirements_txt)
        _write(target / "expected_output.md", files.expected_output_md)
        created.append(target)
        logger.info("PoC generado para %s (%s)", rc.finding_id, rc.poc_confidence.value)
    return created


def _write(path: Path, content: str) -> None:
    """Escribe un archivo de PoC con permisos ``600``."""
    path.write_text(content, encoding="utf-8")
    storage._chmod(path, storage.FILE_MODE)

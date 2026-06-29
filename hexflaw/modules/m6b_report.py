"""M6b — Report Generator (CLAUDE.md §6 M6b).

Genera, por cada hallazgo, un reporte ejecutivo y uno técnico en Markdown, con
snippets secret-scanned y contenido escapado. Devuelve las rutas escritas.

Corre en paralelo con M6c una vez que M6a finaliza (orquestado en el Core).
"""

from __future__ import annotations

from pathlib import Path

from hexflaw.core.models import RootCause
from hexflaw.infrastructure import storage
from hexflaw.infrastructure.logging import get_logger
from hexflaw.services import report_service

logger = get_logger(__name__)


def generate_reports(
    root_causes: list[RootCause], reports_dir: Path, *, fmt: str = "markdown"
) -> list[Path]:
    """Escribe los reportes ejecutivo y técnico de cada hallazgo + consolidado.

    Args:
        root_causes: Root causes producidos por M6a.
        reports_dir: Directorio destino (``.hexflaw/reports/``).
        fmt: ``"markdown"`` | ``"pdf"`` | ``"json"`` | ``"sarif"``. ``pdf``
            también escribe el Markdown; ``json``/``sarif`` emiten solo el export
            estructurado (para integración CI/CD).

    Returns:
        Lista de rutas de los archivos escritos.
    """
    storage.ensure_dir(reports_dir)

    # Exports estructurados: un único archivo consolidado, sin los .md por hallazgo.
    if fmt == "json":
        out = reports_dir / "findings.json"
        _write_text(out, report_service.render_json(root_causes))
        logger.info("Export JSON generado: %s", out)
        return [out]
    if fmt == "sarif":
        out = reports_dir / "hexflaw.sarif"
        _write_text(out, report_service.render_sarif(root_causes))
        logger.info("Export SARIF generado: %s", out)
        return [out]

    written: list[Path] = []
    for rc in root_causes:
        exec_path = reports_dir / f"{rc.finding_id}_executive.md"
        tech_path = reports_dir / f"{rc.finding_id}_technical.md"
        _write_text(exec_path, report_service.render_executive(rc))
        _write_text(tech_path, report_service.render_technical(rc))
        written.extend([exec_path, tech_path])
        logger.info("Reportes generados para %s", rc.finding_id)

    consolidated_md = report_service.render_consolidated(root_causes)
    full_md = reports_dir / "full_report.md"
    _write_text(full_md, consolidated_md)
    written.append(full_md)

    if fmt == "pdf":
        pdf_path = _try_render_pdf(consolidated_md, reports_dir / "full_report.pdf")
        if pdf_path is not None:
            written.append(pdf_path)
    return written


def _try_render_pdf(markdown_body: str, out_path: Path) -> Path | None:
    """Renderiza el consolidado a PDF con weasyprint en modo offline.

    Returns:
        La ruta del PDF, o ``None`` si weasyprint no está instalado o falla.
    """
    try:
        from weasyprint import HTML  # type: ignore
    except ImportError:
        logger.warning("weasyprint no instalado; se omite el PDF (usar pip install weasyprint)")
        return None
    try:
        html = report_service.render_html(markdown_body)
        # base_url vacío + HTML autocontenido: sin fetch de recursos externos (T-M6b-2).
        HTML(string=html, base_url="").write_pdf(str(out_path))
    except Exception as exc:  # render del PDF puede fallar por entorno
        logger.error("Fallo al generar PDF: %s", exc)
        return None
    storage._chmod(out_path, storage.FILE_MODE)
    logger.info("PDF consolidado generado: %s", out_path)
    return out_path


def _write_text(path: Path, content: str) -> None:
    """Escribe texto con permisos ``600`` (CLAUDE.md §15, reportes)."""
    path.write_text(content, encoding="utf-8")
    storage._chmod(path, storage.FILE_MODE)

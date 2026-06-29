"""ReportService — render de reportes Markdown seguros (CLAUDE.md §6 M6b, §15).

Garantías de seguridad al renderizar:
- Todo contenido proveniente del código analizado se escapa antes de insertarse
  (T-M6b-1): nunca interpolación cruda.
- Los snippets pasan por secret scanning antes de incluirse (T-M6a-1).
- Disclaimer obligatorio de que el análisis fue generado por LLM.

El render a PDF (weasyprint en modo offline, T-M6b-2) queda enganchable; el
slice produce Markdown.
"""

from __future__ import annotations

import json

from hexflaw import __version__
from hexflaw.core.models import RootCause, Severity
from hexflaw.infrastructure.logging import get_logger
from hexflaw.services.secret_scan import redact_secrets

logger = get_logger(__name__)

LLM_DISCLAIMER = (
    "> ⚠️ Análisis generado por LLM — requiere validación manual antes de "
    "reportar al cliente."
)


def escape_markdown(text: str) -> str:
    """Escapa caracteres especiales de Markdown para insertar texto como datos.

    Args:
        text: Texto potencialmente proveniente del código analizado.

    Returns:
        Texto con los metacaracteres de Markdown neutralizados.
    """
    specials = "\\`*_{}[]()#+-.!|<>"
    out = []
    for ch in text:
        out.append("\\" + ch if ch in specials else ch)
    return "".join(out)


def _safe_code_block(code: str) -> str:
    """Devuelve un bloque de código con secretos redactados y fence seguro."""
    redacted, detected = redact_secrets(code)
    if detected:
        logger.info("Secretos redactados en snippet de reporte: %s", detected)
    # Evita romper el fence si el código contiene ```.
    fence = "```"
    safe = redacted.replace("```", "​`​`​`")
    return f"{fence}\n{safe}\n{fence}"


def render_executive(rc: RootCause) -> str:
    """Renderiza el reporte ejecutivo (sin código, lenguaje de negocio).

    Args:
        rc: Root cause del hallazgo.

    Returns:
        Markdown del reporte ejecutivo.
    """
    return "\n".join(
        [
            f"# Reporte Ejecutivo — {rc.finding_id}",
            "",
            LLM_DISCLAIMER,
            "",
            f"**Severidad:** {rc.severity.value.capitalize()}  ",
            f"**CVSS v3.1:** {rc.cvss_score}",
            "",
            "## Descripción del riesgo",
            "",
            escape_markdown(rc.summary) or "_No disponible._",
            "",
            "## Impacto potencial",
            "",
            escape_markdown(rc.blast_radius) or "_No disponible._",
            "",
            "## Recomendación",
            "",
            escape_markdown(rc.remediation_summary) or "_No disponible._",
            "",
        ]
    )


def render_consolidated(root_causes: list[RootCause]) -> str:
    """Renderiza el reporte consolidado (todos los hallazgos) en Markdown.

    Args:
        root_causes: Root causes a consolidar.

    Returns:
        Markdown con un índice y la sección técnica de cada hallazgo.
    """
    header = [
        "# HexFlaw — Reporte Consolidado",
        "",
        LLM_DISCLAIMER,
        "",
        f"**Hallazgos:** {len(root_causes)}",
        "",
        "## Resumen",
        "",
        "| ID | Tipo | Severidad | CVSS |",
        "|----|------|-----------|------|",
    ]
    for rc in root_causes:
        header.append(
            f"| {rc.finding_id} | {escape_markdown(rc.type)} | "
            f"{rc.severity.value} | {rc.cvss_score} |"
        )
    body = ["", "---", ""]
    for rc in root_causes:
        body.append(render_technical(rc))
        body.append("\n---\n")
    return "\n".join(header + body)


def render_html(markdown_body: str) -> str:
    """Envuelve Markdown ya escapado en un HTML autocontenido para PDF.

    No referencia recursos externos (fuentes/imágenes) — todo inline — para
    evitar exfiltración al renderizar (CLAUDE.md §15, T-M6b-2).

    Args:
        markdown_body: Contenido Markdown (ya escapado en origen).

    Returns:
        Documento HTML completo con estilos embebidos.
    """
    escaped = (
        markdown_body.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<style>body{font-family:sans-serif;font-size:11px;white-space:pre-wrap;}"
        "</style></head><body>" + escaped + "</body></html>"
    )


def render_technical(rc: RootCause) -> str:
    """Renderiza el reporte técnico (causa raíz, snippet, CVSS, remediación).

    Args:
        rc: Root cause del hallazgo.

    Returns:
        Markdown del reporte técnico.
    """
    affected = "\n".join(f"- `{escape_markdown(line)}`" for line in rc.affected_lines)
    return "\n".join(
        [
            f"# Reporte Técnico — {rc.finding_id} ({escape_markdown(rc.type)})",
            "",
            LLM_DISCLAIMER,
            "",
            f"**Severidad:** {rc.severity.value.capitalize()}  ",
            f"**CVSS v3.1:** {rc.cvss_score} `{escape_markdown(rc.cvss_vector)}`  ",
            f"**Confianza del análisis (LLM):** {rc.llm_confidence:.2f}",
            "",
            "## Causa raíz",
            "",
            escape_markdown(rc.root_cause) or "_No disponible._",
            "",
            "## Ubicaciones afectadas",
            "",
            affected or "_No disponible._",
            "",
            "## Código vulnerable",
            "",
            _safe_code_block(rc.vulnerable_code) if rc.vulnerable_code else "_No disponible._",
            "",
            "## Remediación sugerida",
            "",
            _safe_code_block(rc.fixed_code) if rc.fixed_code else "_No disponible._",
            "",
            "## Blast radius",
            "",
            escape_markdown(rc.blast_radius) or "_No disponible._",
            "",
        ]
    )


# --------------------------------------------------------------------------- #
# Export estructurado — JSON e SARIF 2.1.0 (integración CI/CD)
# --------------------------------------------------------------------------- #
#: Severidad de HexFlaw → nivel SARIF (error | warning | note).
_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_TOOL_URI = "https://securehex.cl"


def _primary_location(rc: RootCause) -> tuple[str, int]:
    """Deriva (archivo, línea) primaria de un root cause para SARIF.

    Usa ``affected_files[0]`` como archivo y la primera referencia
    ``archivo:línea`` parseable de ``affected_lines`` como línea. Si no hay
    línea parseable, devuelve 1 (SARIF exige líneas >= 1).
    """
    file = rc.affected_files[0] if rc.affected_files else ""
    line = 1
    for ref in rc.affected_lines:
        _, _, tail = ref.rpartition(":")
        if tail.isdigit():
            line = max(1, int(tail))
            if not file:
                file = ref.rsplit(":", 1)[0]
            break
    return file, line


def _finding_dict(rc: RootCause) -> dict[str, object]:
    """Serializa un root cause a un dict plano (código con secretos redactados)."""
    vuln_code, _ = redact_secrets(rc.vulnerable_code)
    fixed_code, _ = redact_secrets(rc.fixed_code)
    return {
        "id": rc.finding_id,
        "type": rc.type,
        "severity": rc.severity.value,
        "cvss": {"vector": rc.cvss_vector, "score": rc.cvss_score},
        "summary": rc.summary,
        "root_cause": rc.root_cause,
        "affected_files": rc.affected_files,
        "affected_lines": rc.affected_lines,
        "blast_radius": rc.blast_radius,
        "remediation_summary": rc.remediation_summary,
        "vulnerable_code": vuln_code,
        "fixed_code": fixed_code,
        "poc_confidence": rc.poc_confidence.value,
        "llm_confidence": rc.llm_confidence,
    }


def render_json(root_causes: list[RootCause]) -> str:
    """Renderiza los hallazgos como un documento JSON consolidado.

    Apto para integración con Jira / Defect Dojo / pipelines CI/CD. Los snippets
    de código pasan por secret scanning antes de escribirse (CLAUDE.md §15).

    Args:
        root_causes: Root causes producidos por M6a.

    Returns:
        Cadena JSON (UTF-8, indentada).
    """
    doc = {
        "tool": "HexFlaw",
        "version": __version__,
        "findings": [_finding_dict(rc) for rc in root_causes],
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)


def render_sarif(root_causes: list[RootCause]) -> str:
    """Renderiza los hallazgos en SARIF 2.1.0 (GitHub Code Scanning, SonarQube).

    Cada clase de vulnerabilidad se mapea a una rule; cada hallazgo a un result
    con su location física y la severidad CVSS como ``security-severity`` (lo que
    GitHub usa para ordenar). El código incluido va secret-scanned.

    Args:
        root_causes: Root causes producidos por M6a.

    Returns:
        Cadena JSON SARIF 2.1.0 (UTF-8, indentada).
    """
    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []
    for rc in root_causes:
        if rc.type not in rules:
            rules[rc.type] = {
                "id": rc.type,
                "name": rc.type,
                "shortDescription": {"text": rc.type.replace("_", " ").title()},
                "helpUri": _TOOL_URI,
            }
        file, line = _primary_location(rc)
        results.append(
            {
                "ruleId": rc.type,
                "level": _SARIF_LEVEL.get(rc.severity, "warning"),
                "message": {"text": rc.summary or rc.root_cause or rc.type},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": file or "unknown"},
                            "region": {"startLine": line},
                        }
                    }
                ],
                "properties": {
                    "security-severity": f"{rc.cvss_score:.1f}",
                    "cvss-vector": rc.cvss_vector,
                    "finding-id": rc.finding_id,
                },
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "HexFlaw",
                        "informationUri": _TOOL_URI,
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2)

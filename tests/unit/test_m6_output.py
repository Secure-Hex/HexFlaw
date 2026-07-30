"""Tests de M6a/M6b/M6c y del rendering seguro de reportes."""

from __future__ import annotations

from pathlib import Path

from hexflaw.core.models import (
    CodeGraph,
    Finding,
    FindingStatus,
    IngestionResult,
    PoCConfidence,
    RootCause,
    Severity,
    TaintStep,
)
from hexflaw.modules import m1_ingestion, m3_graph, m6a_rootcause, m6b_report, m6c_poc
from hexflaw.services import report_service
from hexflaw.services.language_service import LanguageService
from hexflaw.services.llm_service import LLMResponse, LLMService

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


class RootCauseLLM(LLMService):
    """Devuelve un root cause JSON completo sin llamar a la API."""

    def __init__(self) -> None:
        super().__init__(api_key="fake")

    def analyze_code(self, instruction: str, code: str, **kwargs: object) -> LLMResponse:
        payload = (
            '{"summary": "Un atacante puede ejecutar comandos arbitrarios.", '
            '"root_cause": "Input de argv concatenado en un comando shell.", '
            '"blast_radius": "Compromiso total del host.", '
            '"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", '
            '"cvss_score": 9.8, "severity": "critical", '
            '"remediation_summary": "Usar APIs sin shell.", '
            '"vulnerable_code": "system(cmd);", '
            '"fixed_code": "execvp(args[0], args);", '
            '"poc_confidence": "high_confidence", "llm_confidence": 0.95}'
        )
        return LLMResponse(text=payload, model="fake")


def _confirmed_finding() -> Finding:
    return Finding(
        id="F001",
        type="command_injection",
        file="ping.c",
        line=12,
        function="handle_ping_input",
        confidence=0.9,
        snippet="system(cmd)",
        status=FindingStatus.CONFIRMED,
        severity=Severity.HIGH,
        taint_path=[TaintStep(step=1, file="ping.c", function="main", note="argv")],
    )


def _ingestion_and_graph() -> tuple[IngestionResult, CodeGraph]:
    langs = LanguageService()
    ingestion = m1_ingestion.ingest(FIXTURES / "sample_c", "p", langs)
    graph = m3_graph.build_graph(ingestion, langs)
    return ingestion, graph


def test_m6a_produces_full_root_cause() -> None:
    ingestion, graph = _ingestion_and_graph()
    rc = m6a_rootcause.analyze_root_cause(
        _confirmed_finding(), ingestion, graph, RootCauseLLM()
    )
    assert rc.severity == Severity.CRITICAL
    assert rc.cvss_score == 9.8
    assert rc.poc_confidence == PoCConfidence.HIGH
    assert "ping.c:12" in rc.affected_lines


def test_m6a_fallback_on_llm_failure() -> None:
    ingestion, graph = _ingestion_and_graph()
    # LLM real sin API key → LLMServiceError → fallback determinístico.
    rc = m6a_rootcause.analyze_root_cause(
        _confirmed_finding(), ingestion, graph, LLMService(api_key=None)
    )
    assert rc.finding_id == "F001"
    assert rc.vulnerable_code == "system(cmd)"


def test_m6b_writes_executive_and_technical(tmp_path: Path) -> None:
    rc = RootCause(
        finding_id="F001",
        type="command_injection",
        summary="riesgo",
        root_cause="causa",
        vulnerable_code="system(cmd)",
        fixed_code="execvp(...)",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        affected_lines=["ping.c:12"],
    )
    paths = m6b_report.generate_reports([rc], tmp_path)
    # ejecutivo + técnico + consolidado
    assert len(paths) == 3
    assert (tmp_path / "full_report.md").exists()
    tech = (tmp_path / "F001_technical.md").read_text()
    assert "Causa raíz" in tech
    assert "validación manual" in tech  # disclaimer LLM


def test_m6b_redacts_secrets_in_report(tmp_path: Path) -> None:
    rc = RootCause(
        finding_id="F002",
        type="hardcoded_creds",
        vulnerable_code='password = "supersecretvalue123"',
        severity=Severity.HIGH,
    )
    m6b_report.generate_reports([rc], tmp_path)
    tech = (tmp_path / "F002_technical.md").read_text()
    assert "supersecretvalue123" not in tech
    assert "[REDACTED]" in tech


def test_m6c_generates_poc_with_safe_payload(tmp_path: Path) -> None:
    rc = RootCause(
        finding_id="F001",
        type="command_injection",
        poc_confidence=PoCConfidence.HIGH,
        severity=Severity.CRITICAL,
    )
    dirs = m6c_poc.generate_pocs([rc], tmp_path)
    assert len(dirs) == 1
    poc_dir = dirs[0]
    poc_py = (poc_dir / "poc.py").read_text()
    readme = (poc_dir / "README.md").read_text()
    assert "TARGET_HOST" in poc_py  # solo placeholders
    assert "rm -rf" not in poc_py  # nunca payloads destructivos
    assert "ADVERTENCIA" in readme
    assert "high_confidence" in readme


def test_markdown_escaping_neutralizes_injection() -> None:
    out = report_service.escape_markdown("# pwned [x](http://evil)")
    assert "\\#" in out and "\\[" in out


# --------------------- M6c PoC generado por LLM --------------------- #
class PoCLLM(LLMService):
    """Devuelve un poc.py concreto tipo CLI (subprocess al binario)."""

    def __init__(self) -> None:
        super().__init__(api_key="fake")

    def analyze_code(self, i: str, c: str, **k: object) -> LLMResponse:  # type: ignore[override]
        body = (
            "import subprocess\n"
            "TARGET_BIN = 'TARGET_BIN'\n"
            "def main():\n"
            "    subprocess.run([TARGET_BIN, 'ping', '; id'])\n"
        )
        return LLMResponse(text=body, model="x")


class UnsafePoCLLM(LLMService):
    """Devuelve un PoC destructivo → debe rechazarse y caer al template."""

    def __init__(self) -> None:
        super().__init__(api_key="fake")

    def analyze_code(self, i: str, c: str, **k: object) -> LLMResponse:  # type: ignore[override]
        return LLMResponse(text="import os\nos.system('rm -rf /')\n", model="x")


def _rc() -> RootCause:
    return RootCause(
        finding_id="F001",
        type="command_injection",
        root_cause="argv llega a system() sin sanitizar",
        affected_files=["server.c"],
        vulnerable_code="system(cmd)",
        poc_confidence=PoCConfidence.HIGH,
        severity=Severity.CRITICAL,
    )


def test_poc_llm_generates_target_specific(tmp_path: Path) -> None:
    from hexflaw.modules import m6c_poc

    m6c_poc.generate_pocs([_rc()], tmp_path, llm=PoCLLM())
    poc = (tmp_path / "F001_command_injection" / "poc.py").read_text()
    assert "subprocess.run" in poc  # adaptado a CLI, no a red genérica
    assert "; id" in poc
    assert "generado por LLM" in poc


def test_poc_llm_unsafe_falls_back_to_template(tmp_path: Path) -> None:
    from hexflaw.modules import m6c_poc

    m6c_poc.generate_pocs([_rc()], tmp_path, llm=UnsafePoCLLM())
    poc = (tmp_path / "F001_command_injection" / "poc.py").read_text()
    assert "rm -rf" not in poc          # PoC destructivo rechazado
    assert "TARGET_HOST" in poc          # cayó al template seguro

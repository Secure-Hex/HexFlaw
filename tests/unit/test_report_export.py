"""Export estructurado JSON / SARIF 2.1.0 de los hallazgos (integración CI/CD)."""

from __future__ import annotations

import json

from hexflaw.core.models import PoCConfidence, RootCause, Severity
from hexflaw.services import report_service


def _rc() -> RootCause:
    return RootCause(
        finding_id="9c46-F001",
        type="command_injection",
        summary="Inyección de comandos en el handler de ping.",
        root_cause="argv llega a system() sin sanitizar.",
        affected_files=["src/ping.c"],
        affected_lines=["src/ping.c:47"],
        blast_radius="RCE como root.",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_score=9.8,
        severity=Severity.CRITICAL,
        vulnerable_code='system(cmd);  // password = "hunter2supersecret"',
        fixed_code="execvp(args[0], args);",
        poc_confidence=PoCConfidence.HIGH,
    )


def test_render_json_shape_and_redaction() -> None:
    doc = json.loads(report_service.render_json([_rc()]))
    assert doc["tool"] == "HexFlaw"
    assert len(doc["findings"]) == 1
    f = doc["findings"][0]
    assert f["id"] == "9c46-F001"
    assert f["type"] == "command_injection"
    assert f["severity"] == "critical"
    assert f["cvss"]["score"] == 9.8
    # El secreto del snippet no debe quedar en el export.
    assert "hunter2supersecret" not in json.dumps(doc)
    assert "[REDACTED]" in f["vulnerable_code"]


def test_render_sarif_2_1_0_structure() -> None:
    sarif = json.loads(report_service.render_sarif([_rc()]))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "HexFlaw"
    # Una rule por tipo de vuln.
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == ["command_injection"]
    res = run["results"][0]
    assert res["ruleId"] == "command_injection"
    assert res["level"] == "error"  # critical → error
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/ping.c"
    assert loc["region"]["startLine"] == 47
    assert res["properties"]["security-severity"] == "9.8"
    assert "hunter2supersecret" not in json.dumps(sarif)


def test_sarif_dedups_rules_across_findings() -> None:
    a, b = _rc(), _rc()
    b.finding_id = "9c46-F002"
    sarif = json.loads(report_service.render_sarif([a, b]))
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1  # mismo type → una sola rule
    assert len(sarif["runs"][0]["results"]) == 2


def test_sarif_level_mapping() -> None:
    rc = _rc()
    rc.severity = Severity.MEDIUM
    sarif = json.loads(report_service.render_sarif([rc]))
    assert sarif["runs"][0]["results"][0]["level"] == "warning"
    rc.severity = Severity.LOW
    sarif = json.loads(report_service.render_sarif([rc]))
    assert sarif["runs"][0]["results"][0]["level"] == "note"

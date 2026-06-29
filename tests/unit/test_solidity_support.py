"""Soporte builtin de Solidity (smart contracts)."""

from __future__ import annotations

from pathlib import Path

from hexflaw.core.models import AppType
from hexflaw.modules import m1_ingestion, m3_graph
from hexflaw.services.language_service import LanguageService

_CONTRACT = """pragma solidity ^0.8.0;
contract Vault {
    address owner;
    function withdraw(uint amount) external {
        require(tx.origin == owner);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }
}
"""


def test_solidity_definition_loaded() -> None:
    svc = LanguageService()
    sol = svc.get("solidity")
    assert sol is not None
    assert ".sol" in sol.extensions
    assert "contract" in sol.app_types
    assert "reentrancy" in sol.vuln_profile


def test_solidity_detected_by_extension() -> None:
    svc = LanguageService()
    d = svc.detect_by_extension(Path("Token.sol"))
    assert d is not None and d.id == "solidity"


def test_solidity_ingest_and_sinks(tmp_path: Path) -> None:
    svc = LanguageService()
    (tmp_path / "Vault.sol").write_text(_CONTRACT)
    res = m1_ingestion.ingest(tmp_path, "p", svc, project_root=tmp_path)

    assert res.languages == ["solidity"]
    assert res.app_type == AppType.CONTRACT

    graph = m3_graph.build_graph(res, svc)
    sink_types = {s.sink_type for s in graph.sinks}
    # tx.origin → auth_bypass, .call{ → external_call (no 'unknown').
    assert "auth_bypass" in sink_types
    assert "external_call" in sink_types
    assert graph.entry_points  # withdraw es external → entry point

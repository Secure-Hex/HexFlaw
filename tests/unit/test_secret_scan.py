"""Tests del secret scanning de snippets (CLAUDE.md §15 T-M6a-1)."""

from __future__ import annotations

from hexflaw.services.secret_scan import redact_secrets


def test_redacts_aws_key() -> None:
    text = "key = AKIAIOSFODNN7EXAMPLE"
    out, detected = redact_secrets(text)
    assert "AKIA" not in out
    assert "[REDACTED]" in out
    assert "aws_access_key" in detected


def test_redacts_password_assignment_keeps_key() -> None:
    out, detected = redact_secrets('password = "hunter2supersecret"')
    assert "hunter2supersecret" not in out
    assert "password" in out  # se conserva la clave
    assert "generic_secret_assignment" in detected


def test_redacts_pem_block() -> None:
    pem = "-----BEGIN RSA PRIVATE KEY-----\nABCDEF\n-----END RSA PRIVATE KEY-----"
    out, detected = redact_secrets(pem)
    assert "ABCDEF" not in out
    assert "pem_private_key" in detected


def test_clean_code_untouched() -> None:
    text = "int main() { return 0; }"
    out, detected = redact_secrets(text)
    assert out == text
    assert detected == []

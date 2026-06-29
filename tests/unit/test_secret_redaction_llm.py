"""El código del cliente nunca debe filtrar secretos a la API externa.

CLAUDE.md §10.2 / §15 (T-M6a-1, T-INFRA-2): el secret scanning es obligatorio
ANTES de enviar cualquier chunk a un servicio externo. Como todos los módulos
(M2/M4/M5/M6a/M6c) envían su código por :meth:`LLMService.analyze_code`,
redactar en ese chokepoint cubre el pipeline completo.
"""

from __future__ import annotations

from hexflaw.services.llm_service import LLMService


class _CapturingLLM(LLMService):
    """Captura el ``user_content`` que realmente se enviaría al transporte."""

    def __init__(self) -> None:
        super().__init__(api_key="fake")
        self.sent: str = ""

    def _complete(
        self, system: str, user_content: str, model: str, max_tokens: int
    ) -> tuple[str, int, int]:
        self.sent = user_content
        return ("{}", 10, 10)


def test_secret_redacted_before_api() -> None:
    llm = _CapturingLLM()
    code = (
        'def connect():\n'
        '    aws = "AKIAIOSFODNN7EXAMPLE"\n'
        '    password = "hunter2supersecret"\n'
        '    return aws, password\n'
    )

    llm.analyze_code("analiza", code)

    # El valor del secreto NO debe haber salido hacia la API...
    assert "AKIAIOSFODNN7EXAMPLE" not in llm.sent
    assert "hunter2supersecret" not in llm.sent
    # ...pero el marcador de redacción sí, y la clave se conserva para que el
    # patrón de hardcoded-secret siga siendo detectable por el análisis.
    assert "[REDACTED]" in llm.sent
    assert "password" in llm.sent


def test_redaction_can_be_disabled() -> None:
    llm = _CapturingLLM()
    llm.analyze_code("analiza", 'k = "AKIAIOSFODNN7EXAMPLE"', redact=False)
    assert "AKIAIOSFODNN7EXAMPLE" in llm.sent


def test_clean_code_passes_through_unchanged() -> None:
    llm = _CapturingLLM()
    code = "def add(a, b):\n    return a + b\n"
    llm.analyze_code("analiza", code)
    assert "def add(a, b):" in llm.sent
    assert "[REDACTED]" not in llm.sent

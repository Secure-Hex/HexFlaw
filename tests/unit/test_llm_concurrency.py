"""Tests de concurrencia en M4/M5 y de seguridad de hilos en LLMService.

Lo que se prueba acá no es "va más rápido" sino que **los mecanismos de seguridad
siguen valiendo bajo concurrencia**: el budget no se pasa de largo, el rate limiter
no deja pasar más de lo que dice, y el resultado del análisis no depende de cuántos
hilos haya (mismos hallazgos, mismos IDs, mismo orden).
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from hexflaw.core.models import (
    Finding,
    FindingSet,
    FindingStatus,
    IngestionResult,
    TargetDefinition,
)
from hexflaw.modules import m1_ingestion, m2_target, m3_graph, m4_static, m5_taint
from hexflaw.services import llm_service as llm_module
from hexflaw.services.language_service import LanguageService
from hexflaw.services.llm_service import BudgetExceededError, LLMResponse, LLMService

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


class SlowLLM(LLMService):
    """LLM falso que tarda y registra cuántas llamadas hubo EN VUELO a la vez."""

    def __init__(self, payload: str, delay: float = 0.05, **kw: object) -> None:
        super().__init__(api_key="fake", **kw)  # type: ignore[arg-type]
        self.payload = payload
        self.delay = delay
        self.calls = 0
        self.max_inflight = 0
        self._inflight = 0
        self._mu = threading.Lock()

    def analyze_code(self, instruction: str, code: str, **kwargs: object) -> LLMResponse:
        with self._mu:
            self.calls += 1
            self._inflight += 1
            self.max_inflight = max(self.max_inflight, self._inflight)
        try:
            time.sleep(self.delay)
        finally:
            with self._mu:
                self._inflight -= 1
        return LLMResponse(text=self.payload, model="fake")


_M4_PAYLOAD = (
    '{"findings": [{"type": "command_injection", "file": "ping.c", "line": 12, '
    '"function": "handle_ping_input", "confidence": 0.9, "snippet": "system(cmd)"}]}'
)
_M5_PAYLOAD = '{"status": "confirmed", "severity": "high", "notes": ["n"]}'


def _setup() -> tuple[LanguageService, IngestionResult, TargetDefinition]:
    langs = LanguageService()
    ing = m1_ingestion.ingest(FIXTURES / "sample_c", "p", langs)
    target = m2_target.define_target_directed("ping", ing, langs)
    return langs, ing, target


def _many_chunks(ing: IngestionResult, n: int) -> IngestionResult:
    """Devuelve la ingestión con ``n`` chunks DISTINTOS.

    Duplicar el mismo chunk no sirve: el dedup exacto por hash los colapsa a uno
    y no se generan batches. Cada uno tiene que tener código propio.
    """
    base = ing.chunks[0]
    chunks = [
        base.model_copy(
            update={
                "id": f"c{i}",
                "name": f"handler_{i}",
                "code": f"void handler_{i}(char *a) {{ char b[8]; system(a); }}",
                "hash": f"hash{i:04d}",
            }
        )
        for i in range(n)
    ]
    return ing.model_copy(update={"chunks": chunks})


# ------------------------------ M4 y M5 -------------------------------- #


def test_m4_actually_runs_batches_in_parallel() -> None:
    """Con concurrency > 1 tiene que haber varias llamadas en vuelo a la vez."""
    langs, ing, target = _setup()
    ing = _many_chunks(ing, 40)  # 4 batches de 10

    llm = SlowLLM(_M4_PAYLOAD, delay=0.2)
    m4_static.analyze(ing, target, llm, langs, concurrency=4, near_dedup_threshold=2.0)

    assert llm.calls > 1, "el fixture no generó batches suficientes"
    assert llm.max_inflight > 1, "las llamadas siguieron siendo secuenciales"


def test_m4_result_is_identical_regardless_of_concurrency() -> None:
    """Mismo análisis, distinto paralelismo → mismos hallazgos, IDs y orden.

    Si el resultado dependiera de cuántos hilos hay, el mismo código auditado dos
    veces produciría reportes distintos según la máquina.
    """
    langs, ing, target = _setup()
    ing = _many_chunks(ing, 40)

    serial = m4_static.analyze(
        ing, target, SlowLLM(_M4_PAYLOAD, delay=0), langs,
        concurrency=1, near_dedup_threshold=2.0,
    )
    parallel = m4_static.analyze(
        ing, target, SlowLLM(_M4_PAYLOAD, delay=0), langs,
        concurrency=8, near_dedup_threshold=2.0,
    )

    assert [(f.id, f.file, f.line, f.type) for f in serial.findings] == [
        (f.id, f.file, f.line, f.type) for f in parallel.findings
    ]


def test_m5_runs_in_parallel_and_keeps_order(tmp_path: Path) -> None:
    """M5 confirma en paralelo pero devuelve los hallazgos en el orden de entrada."""
    langs, ing, _ = _setup()
    graph = m3_graph.build_graph(ing, langs)
    prelim = FindingSet(
        project_id="p",
        findings=[
            Finding(
                id=f"F{i:03d}", type="command_injection", file="ping.c", line=12,
                function="handle_ping_input", status=FindingStatus.PRELIMINARY,
            )
            for i in range(1, 9)
        ],
    )
    llm = SlowLLM(_M5_PAYLOAD, delay=0.2)
    out = m5_taint.confirm(prelim, graph, ing, llm, concurrency=4)

    assert llm.max_inflight > 1, "M5 siguió siendo secuencial"
    assert [f.id for f in out.findings] == [f.id for f in prelim.findings]


# --------------------------- budget y pacing ---------------------------- #


class BudgetLLM(SlowLLM):
    """Agota el budget tras ``limit`` llamadas."""

    def __init__(self, payload: str, limit: int) -> None:
        super().__init__(payload, delay=0.02)
        self.limit = limit

    def analyze_code(self, instruction: str, code: str, **kwargs: object) -> LLMResponse:
        with self._mu:
            if self.calls >= self.limit:
                raise BudgetExceededError("budget agotado")
        return super().analyze_code(instruction, code, **kwargs)


def test_budget_stops_queued_work_instead_of_burning_it() -> None:
    """Agotado el budget, las tareas ya encoladas NO deben llamar al LLM.

    `executor.map` encola todas las tareas de una, así que cortar el bucle de
    consumo no alcanza: sin un flag chequeado dentro del worker, el "corte por
    budget" gastaría igual todo lo que quedaba en la cola.
    """
    langs, ing, target = _setup()
    ing = _many_chunks(ing, 200)  # 20 batches

    llm = BudgetLLM(_M4_PAYLOAD, limit=2)
    m4_static.analyze(ing, target, llm, langs, concurrency=4, near_dedup_threshold=2.0)

    # Margen de un ciclo de workers en vuelo cuando salta el corte, pero nunca
    # todos los batches restantes.
    assert llm.calls <= 2 + 4, f"siguió gastando después del corte: {llm.calls} llamadas"


def test_m5_marks_unevaluated_findings_as_needs_review() -> None:
    """Lo que no se llegó a evaluar queda needs_review, nunca descartado.

    Un hallazgo sin mirar no es un hallazgo descartado: marcarlo como
    false_positive sería un falso negativo silencioso.
    """
    langs, ing, _ = _setup()
    graph = m3_graph.build_graph(ing, langs)
    prelim = FindingSet(
        project_id="p",
        findings=[
            Finding(
                id=f"F{i:03d}", type="command_injection", file="ping.c", line=12,
                function="handle_ping_input", status=FindingStatus.PRELIMINARY,
            )
            for i in range(1, 13)
        ],
    )
    out = m5_taint.confirm(prelim, graph, ing, BudgetLLM(_M5_PAYLOAD, limit=2), concurrency=4)

    assert len(out.findings) == len(prelim.findings), "se perdieron hallazgos"
    pendientes = [f for f in out.findings if f.status == FindingStatus.NEEDS_REVIEW]
    assert pendientes, "ninguno quedó marcado para revisar"
    assert all("budget" in (f.review_reason or "").lower() for f in pendientes)


def test_pacing_reserves_its_slot_under_concurrency(monkeypatch: pytest.MonkeyPatch) -> None:
    """El rate limiter no puede dejar pasar más de su techo con hilos en paralelo.

    Si la ventana se anotara DESPUÉS de la llamada en vez de al reservar, N hilos
    concurrentes verían todos la ventana vacía y saldrían juntos — reventando el
    límite que existe justamente para evitar el 429.
    """
    # Ventana corta: la propiedad solo se puede verificar si el límite es
    # VINCULANTE (alguien tiene que esperar), y con los 60 s reales este test
    # costaría un minuto de reloj cada vez que se corre la suite.
    monkeypatch.setattr(llm_module, "_RATE_WINDOW_SECONDS", 0.5)
    svc = LLMService(api_key="fake", rate_limit_tpm=1000)
    barrier = threading.Barrier(4)

    def hit() -> None:
        barrier.wait()  # forzar la máxima simultaneidad posible
        svc._pace("m", 400)

    threads = [threading.Thread(target=hit) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=90)

    # Se mira el pico: con la ventana corta, para cuando terminan ya expiró parte.
    window = svc._windows["m"]
    assert sum(tok for _, tok in window) <= 1000, (
        "la ventana quedó por encima del techo: el pacing dejó pasar de más"
    )


def test_token_accounting_survives_concurrency() -> None:
    """Los contadores de auditoría no pueden perder llamadas por carreras."""
    svc = SlowLLM('{"findings": []}', delay=0)

    class Counting(LLMService):
        def _complete(self, system, user_content, model, max_tokens):  # type: ignore[no-untyped-def]
            return "{}", 10, 5

    real = Counting(api_key="fake", rate_limit_tpm=None)
    threads = [
        threading.Thread(target=lambda: real.analyze_code("i", "c")) for _ in range(50)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    assert real.total_input_tokens == 50 * 10
    assert real.total_output_tokens == 50 * 5
    assert real.model_usage[real.resolve_model(real.default_tier)]["calls"] == 50
    del svc  # solo para que ruff no marque la variable sin usar


@pytest.mark.parametrize("workers", [1, 2, 8])
def test_concurrency_never_loses_a_finding(workers: int) -> None:
    """Sea cual sea el paralelismo, sale un veredicto por hallazgo de entrada."""
    langs, ing, _ = _setup()
    graph = m3_graph.build_graph(ing, langs)
    prelim = FindingSet(
        project_id="p",
        findings=[
            Finding(
                id=f"F{i:03d}", type="command_injection", file="ping.c", line=12,
                function="handle_ping_input", status=FindingStatus.PRELIMINARY,
            )
            for i in range(1, 7)
        ],
    )
    out = m5_taint.confirm(prelim, graph, ing, SlowLLM(_M5_PAYLOAD, delay=0), concurrency=workers)
    assert len(out.findings) == 6

"""M5b — Variant Hunting dirigido por embeddings.

Tras M5, cada hallazgo confirmado/condicional se usa como *semilla*: se buscan
sus vecinos en el espacio de embeddings (similitud coseno sobre el código de los
chunks) y esa nueva superficie se re-analiza **aunque el scope de M4 la hubiera
descartado**. El único criterio de sink es "que exista algún sink controlable",
y lo aplican piezas ya existentes: el pre-filtro capa-1 de M4 (descarta chunks
sin sink) y M5 (confirma que el sink es alcanzable desde input controlable). El
tipo de cada variante lo determina el LLM en M4 — no se fuerza al de la semilla.

Iterativo hasta converger: cada variante confirmada se vuelve semilla. La
convergencia la garantizan un ``seen``-set (nunca se re-siembra un chunk ya
analizado) y topes duros de rondas y de variantes totales.

Este módulo **orquesta**, no reimplementa: reusa ``m4_static.analyze`` y
``m5_taint.confirm`` sin cambios. Es stateless como el resto del pipeline.
"""

from __future__ import annotations

from typing import Callable

from hexflaw.core.model_policy import ModelTier
from hexflaw.core.models import (
    CodeChunk,
    CodeGraph,
    Finding,
    FindingSet,
    FindingStatus,
    IngestionResult,
    TargetDefinition,
)
from hexflaw.infrastructure.analysis_cache import AnalysisCache
from hexflaw.infrastructure.logging import get_logger
from hexflaw.modules import m4_static, m5_taint
from hexflaw.modules.m4_static import _cosine
from hexflaw.services.embedding.base import EmbeddingService
from hexflaw.services.language_service import LanguageService
from hexflaw.services.llm_service import BudgetExceededError, LLMService

logger = get_logger(__name__)

_PROPAGATING = (FindingStatus.CONFIRMED, FindingStatus.CONDITIONAL)


def _finding_chunk(finding: Finding, chunks: list[CodeChunk]) -> CodeChunk | None:
    """Localiza el chunk que contiene un hallazgo (misma heurística que M6c).

    Coincide por archivo y (nombre de función o rango de líneas), igual que
    ``Orchestrator._code_by_finding``.
    """
    for chunk in chunks:
        if chunk.file == finding.file and (
            chunk.name == finding.function
            or chunk.line_start <= finding.line <= chunk.line_end
        ):
            return chunk
    return None


def hunt_variants(
    seed_set: FindingSet,
    ingestion: IngestionResult,
    target: TargetDefinition,
    graph: CodeGraph,
    embedding: EmbeddingService | None,
    llm: LLMService,
    languages: LanguageService,
    cache: AnalysisCache,
    *,
    static_model: ModelTier | None = None,
    taint_model: ModelTier | None = None,
    mode: str = "balanced",
    top_k: int = 10,
    min_similarity: float = 0.78,
    max_variants_total: int = 50,
    max_rounds: int = 5,
    exhaustive: bool = False,
    on_status: Callable[[str], None] | None = None,
) -> FindingSet:
    """Caza variantes de los hallazgos confirmados/condicionales de M5.

    Args:
        seed_set: Hallazgos de M5 (las semillas son sus confirmed/conditional).
        ingestion: Resultado de M1 (chunks completos del codebase).
        target: Definición de M2 (vuln_profile, reusada por la sub-llamada a M4).
        graph: Code graph de M3 (para el taint de M5).
        embedding: Backend de embeddings (ya cacheado). Si es ``None``, no corre.
        llm: Servicio LLM inyectado.
        languages: Servicio de lenguajes (para el pre-filtro de M4).
        cache: Caché de análisis por chunk (abarata vecinos ya vistos).
        static_model: Modelo para la clasificación de M4.
        taint_model: Modelo para la confirmación de M5.
        mode: Modo de análisis (batch size / umbrales de M4).
        top_k: Máximo de vecinos por semilla.
        min_similarity: Umbral de similitud coseno para considerar un vecino.
        max_variants_total: Tope duro de variantes exploradas en total.
        max_rounds: Tope duro de rondas iterativas.
        exhaustive: Debe reflejar el modo con el que corrió M4. Si no se propaga, la
            sub-llamada a M4 cachea bajo un vuln_profile distinto al que usó la
            pasada exhaustive y **no pega un solo hit de caché**: se re-analiza todo
            a precio de Opus, y encima con un prompt más angosto.
        on_status: Callback de sub-fase para observabilidad.

    Returns:
        :class:`FindingSet` con SOLO las variantes nuevas confirmed/conditional.
    """
    notify: Callable[[str], None] = on_status or (lambda _msg: None)
    empty = FindingSet(project_id=seed_set.project_id, findings=[])

    seeds = seed_set.confirmed()  # confirmed + conditional
    chunks = ingestion.chunks
    if not seeds or top_k <= 0 or embedding is None or not chunks:
        return empty

    try:
        vec_list = embedding.embed_batch([c.code for c in chunks])
    except (RuntimeError, ValueError) as exc:
        logger.warning("M5b desactivado: no se pudo embeber el codebase (%s)", exc)
        return empty
    vec_by_id = {c.id: v for c, v in zip(chunks, vec_list)}
    chunk_by_id = {c.id: c for c in chunks}

    # seen: chunks ya materializados como findings originales — nunca se re-siembran.
    seen: set[str] = set()
    for finding in seed_set.findings:
        chunk = _finding_chunk(finding, chunks)
        if chunk is not None:
            seen.add(chunk.id)

    # Frontera inicial: (finding semilla, su chunk).
    frontier: list[tuple[Finding, CodeChunk]] = [
        (f, ch)
        for f in seeds
        if (ch := _finding_chunk(f, chunks)) is not None and ch.id in vec_by_id
    ]

    accumulated: list[Finding] = []
    total_variants = 0
    round_no = 0
    while frontier and round_no < max_rounds and total_variants < max_variants_total:
        round_no += 1
        notify(f"M5b · ronda {round_no}: {len(frontier)} semilla(s)")

        # Candidatos = vecinos coseno de alguna semilla, aún no vistos. Cada
        # candidato recuerda la semilla de mayor similitud (para variant_of).
        seed_by_chunk: dict[str, tuple[Finding, float]] = {}
        for seed_f, seed_ch in frontier:
            svec = vec_by_id[seed_ch.id]
            scored = [
                (c, sim)
                for c in chunks
                if c.id not in seen
                and (sim := _cosine(svec, vec_by_id.get(c.id, []))) >= min_similarity
            ]
            scored.sort(key=lambda pair: pair[1], reverse=True)
            for cand, sim in scored[:top_k]:
                prev = seed_by_chunk.get(cand.id)
                if prev is None or sim > prev[1]:
                    seed_by_chunk[cand.id] = (seed_f, sim)

        if not seed_by_chunk:
            break

        # Respetar el cap global sin truncación silenciosa (CLAUDE.md §15).
        cand_ids = list(seed_by_chunk)
        room = max_variants_total - total_variants
        if len(cand_ids) > room:
            logger.warning(
                "M5b: cap de %d variantes alcanzado; %d candidato(s) sin explorar",
                max_variants_total,
                len(cand_ids) - room,
            )
            cand_ids = cand_ids[:room]
        for cid in cand_ids:
            seen.add(cid)  # marcados aunque M4/M5 los descarten: no reintentar
        cand_chunks = [chunk_by_id[cid] for cid in cand_ids]
        total_variants += len(cand_chunks)

        # M4 (clasifica tipo + filtra por "tiene sink") → M5 (controlabilidad).
        # embedding=None: la vecindad ya la hicimos; M4 solo aplica capa-1 + LLM.
        notify(f"M5b · analizando {len(cand_chunks)} vecino(s) (M4+M5)")
        recorte = ingestion.model_copy(update={"chunks": cand_chunks})
        try:
            prelim = m4_static.analyze(
                recorte,
                target,
                llm,
                languages,
                mode=mode,
                model=static_model,
                embedding=None,
                cache=cache,
                scope_query=None,
                scope_max_chunks=max(len(cand_chunks), 1),
                exhaustive=exhaustive,
            )
            confirmed_set = (
                m5_taint.confirm(
                    prelim, graph, ingestion, llm, model=taint_model, on_status=notify
                )
                if prelim.findings
                else None
            )
        except BudgetExceededError as exc:
            logger.warning("M5b detenido por budget en la ronda %d: %s", round_no, exc)
            notify(f"M5b · budget agotado en ronda {round_no}; se detiene la caza")
            break

        # Solo confirmed/conditional se acumulan y propagan como nuevas semillas.
        # frontier SIEMPRE se reemplaza por las variantes confirmadas de esta ronda
        # (vacío si M4/M5 no confirmaron nada) → convergencia estricta: la caza para
        # cuando una ronda no produce variantes nuevas, no cuando se agotan los vecinos.
        next_frontier: list[tuple[Finding, CodeChunk]] = []
        for variant in confirmed_set.findings if confirmed_set is not None else []:
            if variant.status not in _PROPAGATING:
                continue
            vch = _finding_chunk(variant, chunks)
            if vch is not None and vch.id in seed_by_chunk:
                variant.variant_of = seed_by_chunk[vch.id][0].id
            accumulated.append(variant)
            if vch is not None and vch.id in vec_by_id:
                next_frontier.append((variant, vch))
        frontier = next_frontier

    if round_no >= max_rounds and frontier:
        logger.warning(
            "M5b: tope de %d rondas alcanzado; %d semilla(s) sin expandir",
            max_rounds,
            len(frontier),
        )
    logger.info(
        "M5b: %d variante(s) confirmada(s)/condicional(es) en %d ronda(s)",
        len(accumulated),
        round_no,
    )
    return FindingSet(project_id=seed_set.project_id, findings=accumulated)

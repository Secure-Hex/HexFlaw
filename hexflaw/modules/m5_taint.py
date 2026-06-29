"""M5 — Taint Tracing + Confirmation (CLAUDE.md §6 M5, §15 M5).

Para cada hallazgo preliminar de M4:
1. Localiza el nodo sink en el code graph.
2. Enumera caminos de llamada desde entry points hasta ese sink (backward taint),
   con detección de ciclos y límites de profundidad/cantidad (T-M5-1/T-M5-2).
3. Pide al LLM clasificar el hallazgo como confirmed / conditional /
   false_positive razonando sobre el path, con delimitadores anti-injection.

Si no hay path desde un entry point, el hallazgo se marca ``false_positive``
sin gastar tokens (el sink no es alcanzable desde input controlado).
"""

from __future__ import annotations

import json
from collections import deque
from typing import Callable

from hexflaw.core.models import (
    CodeGraph,
    Finding,
    FindingSet,
    FindingStatus,
    GraphNode,
    IngestionResult,
    Severity,
    TaintStep,
)
from hexflaw.infrastructure.logging import get_logger
from hexflaw.modules.m4_static import _extract_json_object
from hexflaw.services.llm_service import (
    BudgetExceededError,
    LLMService,
    LLMServiceError,
)

logger = get_logger(__name__)

_CONFIRM_INSTRUCTION = (
    "Eres un analista de taint. Te doy un hallazgo preliminar y el camino de "
    "llamadas (call path) desde un entry point hasta un sink. Determina si datos "
    "controlables por el atacante llegan al sink SIN sanitización efectiva.\n"
    "Clasifica como: 'confirmed' (path completo sin sanitización), 'conditional' "
    "(path existe con condiciones satisfacibles) o 'false_positive' (no alcanzable "
    "o sanitizado).\n"
    "Responde SOLO JSON: {\"status\": \"confirmed|conditional|false_positive\", "
    "\"severity\": \"critical|high|medium|low\", \"notes\": [\"paso 1...\", "
    "\"paso 2...\"]}."
)


def confirm(
    preliminary: FindingSet,
    graph: CodeGraph,
    ingestion: IngestionResult,
    llm: LLMService,
    *,
    model: str | None = None,
    on_status: "Callable[[str], None] | None" = None,
) -> FindingSet:
    """Confirma o descarta hallazgos preliminares vía taint tracing.

    Args:
        preliminary: Hallazgos de M4 (status=preliminary).
        graph: Code graph de M3.
        ingestion: Resultado de M1 (para recuperar el código de cada nodo).
        llm: Servicio LLM inyectado.
        model: Override de modelo (M5 justifica Opus, ver §16 estrategia 5).
        on_status: Callback opcional para reportar progreso (observabilidad CLI).

    Returns:
        :class:`FindingSet` con cada hallazgo clasificado y su taint path.
    """
    notify: Callable[[str], None] = on_status or (lambda _msg: None)
    code_by_id = {chunk.id: chunk.code for chunk in ingestion.chunks}
    confirmed: list[Finding] = []
    # Adyacencia precomputada una sola vez: reutilizada en cada finding.
    notify("M5 · construyendo grafo de llamadas")
    adjacency = build_adjacency(graph)
    total = len(preliminary.findings)

    for idx, finding in enumerate(preliminary.findings, start=1):
        notify(f"M5 · confirmando finding {idx}/{total}")
        sink_node = _locate_node(finding, graph)
        path_ids: list[str] = []
        if sink_node is not None:
            paths = _find_paths_to(sink_node.id, graph, adjacency)
            if paths:
                path_ids = paths[0]
        # Siempre se evalúa con el LLM: el grafo heurístico es incompleto, así que
        # "sin path" no implica false_positive — lo decide el análisis del código.
        try:
            updated = _confirm_with_llm(
                finding, path_ids, sink_node, graph, code_by_id, llm, model
            )
        except BudgetExceededError as exc:
            # Budget agotado: a partir de acá toda llamada fallaría igual. En vez de
            # emitir un error por cada finding restante, cortamos limpio y marcamos
            # el actual y los pendientes como needs_review con una razón accionable.
            remaining = preliminary.findings[idx - 1:]
            logger.warning(
                "M5 detenido por budget tras %d/%d findings; %d quedan needs_review: %s",
                idx - 1, total, len(remaining), exc,
            )
            notify(f"M5 · budget agotado en {idx}/{total}; resto queda needs_review")
            reason = (
                "M5 no evaluó: budget de tokens agotado. Subí el budget (--budget / "
                "config token_budget) y re-corré 'hexflaw analyze' (M4 sale de caché) "
                "o 'hexflaw findings recheck' por hallazgo."
            )
            confirmed.extend(
                f.model_copy(
                    update={
                        "status": FindingStatus.NEEDS_REVIEW,
                        "review_reason": reason,
                    }
                )
                for f in remaining
            )
            break
        confirmed.append(updated)

    logger.info(
        "M5: %d confirmados, %d condicionales, %d false positives",
        sum(f.status == FindingStatus.CONFIRMED for f in confirmed),
        sum(f.status == FindingStatus.CONDITIONAL for f in confirmed),
        sum(f.status == FindingStatus.FALSE_POSITIVE for f in confirmed),
    )
    return FindingSet(project_id=preliminary.project_id, findings=confirmed)


def _locate_node(finding: Finding, graph: CodeGraph) -> GraphNode | None:
    """Encuentra el nodo del grafo correspondiente a un hallazgo."""
    if finding.function:
        for node in graph.nodes:
            if node.file == finding.file and node.name == finding.function:
                return node
    # Fallback: por archivo y rango de líneas.
    for node in graph.nodes:
        if node.file == finding.file and node.line_start <= finding.line <= node.line_end:
            return node
    return None


def _find_paths_to(
    target_id: str, graph: CodeGraph, adjacency: dict[str, list[str]] | None = None
) -> list[list[str]]:
    """Encuentra UN camino de llamada (el más corto) entry point → ``target_id``.

    Usa BFS multi-source desde los entry points (O(V+E)) en vez de enumerar todos
    los caminos: la enumeración explota exponencialmente en grafos grandes
    (path explosion, T-M5-2). Para confirmar taint basta con saber si el sink es
    alcanzable y un camino representativo; el más corto es el más directo.

    Detección de ciclos implícita por el ``visited`` del BFS (T-M5-1).

    Args:
        target_id: Nodo sink a alcanzar.
        graph: Code graph de M3.
        adjacency: Lista de adyacencia precomputada (opcional, para reusar entre
            findings y evitar reconstruirla por cada uno).

    Returns:
        ``[[path]]`` con un único camino de ids origen→destino, o ``[]`` si el
        sink no es alcanzable desde ningún entry point.
    """
    if adjacency is None:
        adjacency = build_adjacency(graph)

    entry_set = set(graph.entry_points)
    # Fuentes: entry points distintos del target (buscamos flujo HACIA el sink).
    sources = [e for e in entry_set if e != target_id]

    parent: dict[str, str | None] = {s: None for s in sources}
    queue = deque(sources)
    reached = target_id in entry_set and not sources  # target es el único entry
    while queue:
        node = queue.popleft()
        if node == target_id:
            reached = True
            break
        for nxt in adjacency.get(node, []):
            if nxt not in parent:  # no visitado → corta ciclos
                parent[nxt] = node
                queue.append(nxt)

    if target_id not in parent and not reached:
        # No alcanzable desde otro entry point.
        if target_id in entry_set:
            return [[target_id]]  # el sink es él mismo un entry (input directo)
        return []

    # Reconstruye el camino vía parent pointers.
    path: list[str] = []
    cursor: str | None = target_id
    while cursor is not None:
        path.append(cursor)
        cursor = parent.get(cursor)
    path.reverse()
    return [path]


def build_adjacency(graph: CodeGraph) -> dict[str, list[str]]:
    """Construye la lista de adyacencia (``from`` → [``to``]) del code graph."""
    adjacency: dict[str, list[str]] = {}
    for edge in graph.edges:
        adjacency.setdefault(edge.from_, []).append(edge.to)
    return adjacency


def _confirm_with_llm(
    finding: Finding,
    path: list[str],
    sink_node: GraphNode | None,
    graph: CodeGraph,
    code_by_id: dict[str, str],
    llm: LLMService,
    model: str | None,
) -> Finding:
    """Pide al LLM clasificar el hallazgo.

    Con call path: razona sobre el flujo entry point → sink. Sin path (grafo
    incompleto): evalúa el código de la función directamente (forward taint
    local), sin asumir false_positive.
    """
    path_nodes = [graph.node_by_id(nid) for nid in path]
    path_nodes = [n for n in path_nodes if n is not None]

    if len(path_nodes) >= 2:
        code_blob = "\n\n".join(
            f"### STEP {i + 1}: {n.file}::{n.name}\n{code_by_id.get(n.id, '')}"
            for i, n in enumerate(path_nodes)
        )
        context_note = "Se encontró un call path desde un entry point (ver STEPs)."
    else:
        code = code_by_id.get(sink_node.id, "") if sink_node else ""
        code = (code or finding.snippet)[:8000]
        code_blob = f"### {finding.file}::{finding.function or '?'}\n{code}"
        context_note = (
            "No se halló un call path explícito en el grafo (heurístico e "
            "incompleto: puede faltar resolución cross-file o dynamic dispatch). "
            "Evalúa SOLO con el código si input controlable por el atacante puede "
            "alcanzar el sink. NO asumas false_positive por ausencia de path."
        )
    instruction = (
        f"{_CONFIRM_INSTRUCTION}\n\n{context_note}\n\nHallazgo: {finding.type} en "
        f"{finding.file}:{finding.line} (función {finding.function})."
    )

    try:
        response = llm.analyze_code(
            instruction,
            code_blob,
            model=model,
            trace_label=f"M5 · confirmar {finding.id} ({finding.type})",
        )
    except BudgetExceededError:
        # Budget agotado: lo maneja el loop de confirm() cortando limpio, no como
        # un fallo aislado por finding (si no, se loguearían N errores idénticos).
        raise
    except LLMServiceError as exc:
        # No se pudo evaluar (error de API / rate limit / red transitorio).
        logger.error("[%s] fallo LLM en confirmación: %s", finding.id, exc)
        return finding.model_copy(
            update={
                "status": FindingStatus.NEEDS_REVIEW,
                "review_reason": f"M5 no pudo evaluar: {type(exc).__name__}. "
                "Re-intentá con 'hexflaw findings recheck'.",
            }
        )

    verdict = _parse_verdict(response.text)
    taint_path = _build_taint_path(path_nodes, verdict.get("notes", []))
    mapped = _map_status(verdict.get("status"))
    severity = _map_severity(verdict.get("severity"))

    if mapped is None:
        # El LLM respondió pero su veredicto fue ambiguo / no clasificable.
        return finding.model_copy(
            update={
                "status": FindingStatus.NEEDS_REVIEW,
                "severity": severity,
                "taint_path": taint_path,
                "review_reason": "Veredicto del LLM ambiguo o no concluyente; "
                "requiere revisión manual del código.",
            }
        )

    return finding.model_copy(
        update={
            "status": mapped,
            "severity": severity,
            "taint_path": taint_path,
        }
    )


def _build_taint_path(path_nodes: list[GraphNode], notes: list) -> list[TaintStep]:
    """Combina los nodos del path con las notas del LLM en pasos de taint."""
    steps: list[TaintStep] = []
    for i, node in enumerate(path_nodes):
        note = str(notes[i]) if i < len(notes) else "paso del call path"
        steps.append(
            TaintStep(step=i + 1, file=node.file, function=node.name, note=note[:300])
        )
    return steps


def _parse_verdict(text: str) -> dict:
    """Extrae el veredicto JSON de la respuesta del LLM, tolerante a ruido."""
    candidate = _extract_json_object(text)
    if candidate is None:
        return {}
    try:
        data = json.loads(candidate)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _map_status(value: object) -> FindingStatus | None:
    """Mapea el string de status del LLM a :class:`FindingStatus`.

    Devuelve ``None`` si el valor no corresponde a un veredicto conocido, para
    que el caller lo marque ``needs_review`` (M5 evaluó pero no concluyó).
    """
    mapping = {
        "confirmed": FindingStatus.CONFIRMED,
        "conditional": FindingStatus.CONDITIONAL,
        "false_positive": FindingStatus.FALSE_POSITIVE,
    }
    return mapping.get(str(value).lower())


def _map_severity(value: object) -> Severity | None:
    """Mapea el string de severidad del LLM a :class:`Severity`."""
    try:
        return Severity(str(value).lower())
    except ValueError:
        return None

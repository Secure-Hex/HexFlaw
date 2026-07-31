"""M5 — Taint Tracing + Confirmation (CLAUDE.md §6 M5, §15 M5).

Para cada hallazgo preliminar de M4:

1. Localiza el nodo sink en el code graph.
2. Busca un camino desde un entry point, con detección de ciclos y límites de
   profundidad/cantidad (T-M5-1/T-M5-2). Primero por aristas ``data_flow``
   (:func:`find_data_flow_path`), que prueban que el **dato** llega al sink; si no
   hay, cae al call path, que solo prueba alcanzabilidad.
3. Pide al LLM clasificar el hallazgo como confirmed / conditional /
   false_positive razonando sobre el path, con delimitadores anti-injection. Cada
   salto va anotado con lo que el grafo sabe: qué variables entran, si venían
   sanitizadas y qué condiciones lo guardan.

**La ausencia de path NO implica ``false_positive``.** El grafo es incompleto por
construcción (dispatch dinámico, alias de objetos, lenguajes sin AST), así que un
sink sin camino se manda igual al LLM para que lo evalúe sobre el código. Descartar
sin evaluar produciría falsos negativos silenciosos, que en una herramienta de
seguridad son peores que gastar los tokens.
"""

from __future__ import annotations

import json
import threading
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from hexflaw.core.model_policy import ModelTier
from hexflaw.core.models import (
    CodeGraph,
    EdgeType,
    Evidence,
    EvidenceOrigin,
    Finding,
    FindingSet,
    FindingStatus,
    GraphEdge,
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
    model: ModelTier | None = None,
    concurrency: int = 1,
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

    edge_index = _edge_lookup(graph)
    # Igual que en M4: al agotarse el budget hay que frenar de verdad. El flag se
    # chequea DENTRO del worker, porque las tareas ya encoladas llamarían al LLM
    # aunque dejáramos de consumir resultados.
    stop = threading.Event()
    progress = threading.Lock()
    done = 0

    def confirm_one(finding: Finding) -> Finding | None:
        """Confirma un hallazgo. ``None`` = no se evaluó (budget agotado)."""
        nonlocal done
        if stop.is_set():
            return None
        sink_node = _locate_node(finding, graph)
        path_ids: list[str] = []
        is_data_flow = False
        if sink_node is not None:
            # Se prefiere el camino de data flow: prueba que el DATO llega al sink,
            # no solo que el sink es alcanzable. Si no hay, se cae al call path.
            flow_path = find_data_flow_path(sink_node.id, graph)
            if flow_path:
                path_ids, is_data_flow = flow_path, True
            else:
                paths = _find_paths_to(sink_node.id, graph, adjacency)
                if paths:
                    path_ids = paths[0]
        # Siempre se evalúa con el LLM: el grafo heurístico es incompleto, así que
        # "sin path" no implica false_positive — lo decide el análisis del código.
        try:
            updated = _confirm_with_llm(
                finding,
                path_ids,
                sink_node,
                graph,
                code_by_id,
                llm,
                model,
                edge_index=edge_index,
                is_data_flow=is_data_flow,
            )
        except BudgetExceededError as exc:
            logger.warning("M5 detenido por budget: %s", exc)
            stop.set()
            return None
        with progress:
            done += 1
            notify(f"M5 · confirmando finding {done}/{total}")
        return updated

    # El orden de salida sigue al de entrada (executor.map), así que los hallazgos
    # se reportan siempre en el mismo orden corra con 1 worker o con 8.
    reason = (
        "M5 no evaluó: budget de tokens agotado. Subí el budget (--budget / "
        "config token_budget) y re-corré 'hexflaw analyze' (M4 sale de caché) "
        "o 'hexflaw findings recheck' por hallazgo."
    )
    with ThreadPoolExecutor(max_workers=max(concurrency, 1)) as pool:
        for original, updated in zip(
            preliminary.findings, pool.map(confirm_one, preliminary.findings)
        ):
            if updated is None:
                # No se evaluó: queda needs_review con una razón accionable, nunca
                # descartado — un hallazgo sin mirar no es un hallazgo descartado.
                confirmed.append(
                    original.model_copy(
                        update={
                            "status": FindingStatus.NEEDS_REVIEW,
                            "review_reason": reason,
                        }
                    )
                )
            else:
                confirmed.append(updated)
    if stop.is_set():
        skipped = sum(f.status == FindingStatus.NEEDS_REVIEW for f in confirmed)
        notify(f"M5 · budget agotado; {skipped} quedan needs_review")

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


def build_adjacency(
    graph: CodeGraph, types: tuple[EdgeType, ...] = (EdgeType.CALLS,)
) -> dict[str, list[str]]:
    """Construye la lista de adyacencia (``from`` → [``to``]) del code graph.

    Args:
        graph: Code graph de M3.
        types: Tipos de arista a incluir. Por defecto solo ``calls``: mezclar
            ``data_flow`` acá inventaría caminos de llamada que no existen, porque
            las aristas de retorno van callee→caller.

    Returns:
        La lista de adyacencia restringida a ``types``.
    """
    adjacency: dict[str, list[str]] = {}
    for edge in graph.edges:
        if edge.type in types:
            adjacency.setdefault(edge.from_, []).append(edge.to)
    return adjacency


def find_data_flow_path(target_id: str, graph: CodeGraph) -> list[str]:
    """Camino de **data flow** entry point → ``target_id``, o ``[]`` si no hay.

    A diferencia de :func:`_find_paths_to`, sigue aristas ``data_flow`` en su
    propia dirección: el dato realmente vuelve por el valor de retorno, así que un
    camino ``handler → build → handler → run`` es un flujo legítimo, no un ciclo
    espurio. Encontrarlo es evidencia mucho más fuerte que la mera alcanzabilidad
    de llamada: no solo se puede llegar al sink, además llega el dato.

    Devuelve ``[]`` en grafos sin aristas ``data_flow`` (artefactos viejos), con lo
    que M5 se comporta exactamente como antes.
    """
    adjacency = build_adjacency(graph, (EdgeType.DATA_FLOW,))
    if not adjacency:
        return []

    sources = [e for e in graph.entry_points if e != target_id]
    parent: dict[str, str | None] = {s: None for s in sources}
    queue = deque(sources)
    while queue:
        node = queue.popleft()
        if node == target_id:
            break
        for nxt in adjacency.get(node, []):
            if nxt not in parent:  # visited-set: corta ciclos (T-M5-1)
                parent[nxt] = node
                queue.append(nxt)

    if target_id not in parent:
        return []
    path: list[str] = []
    cursor: str | None = target_id
    while cursor is not None:
        path.append(cursor)
        cursor = parent.get(cursor)
    path.reverse()
    return path


def _edge_lookup(graph: CodeGraph) -> dict[tuple[str, str], list[GraphEdge]]:
    """Índice ``(from, to)`` → aristas, para anotar los pasos de un camino."""
    index: dict[tuple[str, str], list[GraphEdge]] = {}
    for edge in graph.edges:
        index.setdefault((edge.from_, edge.to), []).append(edge)
    return index


def _describe_hop(edges: list[GraphEdge]) -> str:
    """Resume qué pasa en un salto del camino: datos, guardas, sanitización."""
    notes: list[str] = []
    for edge in edges:
        if edge.type == EdgeType.DATA_FLOW and edge.data_vars:
            state = "sanitizado" if edge.sanitized else "sin sanitizar"
            notes.append(f"datos {', '.join(edge.data_vars)} ({state})")
        elif edge.type == EdgeType.CONTROL_FLOW and edge.condition:
            notes.append(f"guardado por {edge.condition}")
    return "; ".join(notes)


def _confirm_with_llm(
    finding: Finding,
    path: list[str],
    sink_node: GraphNode | None,
    graph: CodeGraph,
    code_by_id: dict[str, str],
    llm: LLMService,
    model: ModelTier | None,
    *,
    edge_index: dict[tuple[str, str], list[GraphEdge]] | None = None,
    is_data_flow: bool = False,
) -> Finding:
    """Pide al LLM clasificar el hallazgo.

    Con path: razona sobre el flujo entry point → sink, anotando en cada salto qué
    variables viajan, si pasaron por un sanitizador y qué condiciones lo guardan.
    Sin path (grafo incompleto): evalúa el código de la función directamente
    (forward taint local), sin asumir false_positive.
    """
    resolved = (graph.node_by_id(node_id) for node_id in path)
    path_nodes: list[GraphNode] = [node for node in resolved if node is not None]
    hops = _hop_notes(path_nodes, edge_index or {})

    if len(path_nodes) >= 2:
        code_blob = "\n\n".join(
            f"### STEP {i + 1}: {n.file}::{n.name}"
            + (f"  [{hops[i - 1]}]" if i and i - 1 < len(hops) and hops[i - 1] else "")
            + f"\n{code_by_id.get(n.id, '')}"
            for i, n in enumerate(path_nodes)
        )
        if is_data_flow:
            context_note = (
                "Se encontró un camino de DATA FLOW desde un entry point: el dato "
                "efectivamente viaja hasta el sink (ver STEPs). Los corchetes en cada "
                "STEP indican qué variables llegan, si pasaron por un sanitizador "
                "reconocido, y qué condiciones guardan el paso. Si TODOS los saltos "
                "están sanitizados, es false_positive; si hay guardas satisfacibles "
                "por el atacante, es conditional."
            )
        else:
            context_note = (
                "Se encontró un call path desde un entry point (ver STEPs), pero NO un "
                "camino de data flow: el sink es alcanzable, aunque M3 no pudo probar "
                "que el dato del atacante llegue. Puede ser flujo por atributo/objeto "
                "o dispatch dinámico que el grafo no modela — verificá con el código."
            )
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
    raw_notes = verdict.get("notes", [])
    notes = list(raw_notes) if isinstance(raw_notes, list) else []
    taint_path = _build_taint_path(path_nodes, notes, hops)
    mapped = _map_status(verdict.get("status"))
    severity = _map_severity(verdict.get("severity"))

    evidence = _build_evidence(
        path_nodes,
        graph,
        edge_index or {},
        is_data_flow=is_data_flow,
        llm_concluded=mapped is not None,
    )

    if mapped is None:
        # El LLM respondió pero su veredicto fue ambiguo / no clasificable.
        return finding.model_copy(
            update={
                "status": FindingStatus.NEEDS_REVIEW,
                "severity": severity,
                "taint_path": taint_path,
                "evidence": evidence,
                "review_reason": "Veredicto del LLM ambiguo o no concluyente; "
                "requiere revisión manual del código.",
            }
        )

    return finding.model_copy(
        update={
            "status": mapped,
            "severity": severity,
            "taint_path": taint_path,
            "evidence": evidence,
        }
    )


def _build_evidence(
    path_nodes: list[GraphNode],
    graph: CodeGraph,
    edge_index: dict[tuple[str, str], list[GraphEdge]],
    *,
    is_data_flow: bool,
    llm_concluded: bool,
) -> Evidence:
    """Arma la traza auditable del hallazgo a partir del grafo.

    Lo que va acá es **verificable releyendo el código**: el camino, las variables
    que viajan, los sanitizadores reconocidos y las guardas salen del AST, no del
    modelo. ``origin`` deja explícito cuánto de la conclusión es determinístico,
    para que quien lea el reporte sepa qué revisar a mano y qué no.
    """
    tainted: list[str] = []
    sanitizers: list[str] = []
    guards: list[str] = []
    unsanitized = False
    for index in range(len(path_nodes) - 1):
        pair = (path_nodes[index].id, path_nodes[index + 1].id)
        for edge in edge_index.get(pair, []):
            if edge.type == EdgeType.DATA_FLOW and edge.data_vars:
                if edge.sanitized:
                    sanitizers.extend(edge.data_vars)
                else:
                    tainted.extend(edge.data_vars)
                    unsanitized = True
            elif edge.type == EdgeType.CONTROL_FLOW and edge.condition:
                guards.append(edge.condition)

    sink_node = path_nodes[-1] if path_nodes else None
    sink_types = sorted(
        {s.sink_type for s in graph.sinks if sink_node and s.node_id == sink_node.id}
    )
    origin = EvidenceOrigin.LLM
    if path_nodes:
        origin = EvidenceOrigin.BOTH if llm_concluded else EvidenceOrigin.GRAPH

    return Evidence(
        source=f"{path_nodes[0].file}::{path_nodes[0].name}" if path_nodes else "",
        sink=(
            f"{sink_node.file}::{sink_node.name}"
            + (f" · {', '.join(sink_types)}" if sink_types else "")
            if sink_node
            else ""
        ),
        tainted_vars=sorted(set(tainted)),
        sanitizers=sorted(set(sanitizers)),
        unsanitized=unsanitized,
        guards=guards[:5],
        path=[f"{n.file}::{n.name}" for n in path_nodes],
        path_kind=("data_flow" if is_data_flow else "calls") if path_nodes else "none",
        origin=origin,
    )


def _hop_notes(
    path_nodes: list[GraphNode], edge_index: dict[tuple[str, str], list[GraphEdge]]
) -> list[str]:
    """Descripción del salto i→i+1 para cada par consecutivo del camino."""
    return [
        _describe_hop(edge_index.get((path_nodes[i].id, path_nodes[i + 1].id), []))
        for i in range(len(path_nodes) - 1)
    ]


def _build_taint_path(
    path_nodes: list[GraphNode],
    notes: list[object],
    hops: list[str] | None = None,
) -> list[TaintStep]:
    """Combina los nodos del path con las notas del LLM en pasos de taint.

    Cuando M3 aportó data flow, la nota del paso arranca con el hecho verificable
    del grafo (qué variables entran, si venían sanitizadas) y después la
    interpretación del LLM — así el reporte distingue evidencia de razonamiento.
    """
    steps: list[TaintStep] = []
    for i, node in enumerate(path_nodes):
        llm_note = str(notes[i]) if i < len(notes) else "paso del call path"
        hop = hops[i - 1] if hops and i and i - 1 < len(hops) else ""
        note = f"{hop} — {llm_note}" if hop else llm_note
        steps.append(
            TaintStep(step=i + 1, file=node.file, function=node.name, note=note[:300])
        )
    return steps


def _parse_verdict(text: str) -> dict[str, object]:
    """Extrae el veredicto JSON de la respuesta del LLM, tolerante a ruido."""
    candidate = _extract_json_object(text)
    if candidate is None:
        return {}
    try:
        data = json.loads(candidate)
    except json.JSONDecodeError:
        return {}
    return dict(data) if isinstance(data, dict) else {}


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

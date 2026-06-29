"""M3 — Code Graph Builder (CLAUDE.md §6 M3).

Construye un call graph a partir de los chunks de M1:
- Un nodo por función/clase chunk.
- Una arista ``calls`` A→B si el nombre de B aparece invocado (``B(``) dentro
  del código de A y B es un nodo distinto.
- ``is_entry_point`` por coincidencia con ``entry_point_patterns`` del lenguaje.
- ``is_sink`` por coincidencia con ``sink_patterns`` del lenguaje; se registra
  además en :class:`SinkRef` con su ``sink_type`` inferido.

Heurístico y barato (sin AST completo todavía); suficiente para que M5 razone
sobre caminos. tree-sitter se engancha aquí cuando esté instalado.
"""

from __future__ import annotations

import hashlib
import re

from hexflaw.core.models import (
    CodeGraph,
    EdgeType,
    GraphEdge,
    GraphNode,
    IngestionResult,
    NodeType,
    SinkRef,
)
from hexflaw.infrastructure.logging import get_logger
from hexflaw.services.language_service import LanguageService

logger = get_logger(__name__)

# Mapa sink keyword → sink_type para el campo SinkRef.sink_type.
_SINK_TYPE: dict[str, str] = {
    "system": "command_execution",
    "popen": "command_execution",
    "exec": "command_execution",
    "execve": "command_execution",
    "execl": "command_execution",
    "subprocess": "command_execution",
    "os.system": "command_execution",
    "eval": "code_execution",
    "pickle.loads": "deserialization",
    "yaml.load": "deserialization",
    "strcpy": "memory_write",
    "strcat": "memory_write",
    "sprintf": "memory_write",
    "memcpy": "memory_write",
    "gets": "memory_write",
    "open(": "file_op",
    "fopen": "file_op",
    "query": "sql_query",
    "execute": "sql_query",
    # Solidity / smart contracts
    ".call(": "external_call",
    ".call{": "external_call",
    ".delegatecall(": "delegatecall",
    ".send(": "value_transfer",
    ".transfer(": "value_transfer",
    "selfdestruct": "contract_destruction",
    "suicide(": "contract_destruction",
    "tx.origin": "auth_bypass",
    "block.timestamp": "weak_randomness",
    "blockhash": "weak_randomness",
    "ecrecover": "signature_check",
    "assembly": "inline_assembly",
    "create2": "contract_creation",
}


def build_graph(
    ingestion: IngestionResult, languages_service: LanguageService
) -> CodeGraph:
    """Construye el code graph a partir del resultado de ingestión.

    Args:
        ingestion: Resultado de M1 (chunks + file_map).
        languages_service: Para resolver entry/sink patterns por lenguaje.

    Returns:
        El :class:`CodeGraph` construido.
    """
    nodes: list[GraphNode] = []
    name_to_id: dict[str, str] = {}
    entry_points: list[str] = []
    sinks: list[SinkRef] = []

    for chunk in ingestion.chunks:
        definition = languages_service.get(chunk.language)
        entry_patterns = definition.entry_point_patterns if definition else []
        sink_patterns = definition.sink_patterns if definition else []

        is_entry = any(p in chunk.code for p in entry_patterns)
        matched_sinks = [p for p in sink_patterns if p in chunk.code]

        node = GraphNode(
            id=chunk.id,
            type=NodeType.MODULE if chunk.name == "<module>" else NodeType.FUNCTION,
            name=chunk.name,
            file=chunk.file,
            line_start=chunk.line_start,
            line_end=chunk.line_end,
            signature=_first_line(chunk.code),
            is_entry_point=is_entry,
            is_sink=bool(matched_sinks),
            tags=["user_input"] if is_entry else [],
        )
        nodes.append(node)
        if chunk.name != "<module>":
            name_to_id.setdefault(chunk.name, chunk.id)
        if is_entry:
            entry_points.append(chunk.id)
        for sink_kw in matched_sinks:
            sinks.append(
                SinkRef(
                    node_id=chunk.id,
                    sink_type=_SINK_TYPE.get(sink_kw, "unknown"),
                    function=sink_kw,
                )
            )

    edges = _build_call_edges(ingestion, name_to_id)
    language = ingestion.languages[0] if len(ingestion.languages) == 1 else "mixed"

    logger.info(
        "M3 code graph: %d nodos, %d aristas, %d entry points, %d sinks",
        len(nodes),
        len(edges),
        len(entry_points),
        len(sinks),
    )
    return CodeGraph(
        project_id=ingestion.project_id,
        language=language,
        nodes=nodes,
        edges=edges,
        entry_points=entry_points,
        sinks=sinks,
    )


def source_hash(ingestion: IngestionResult) -> str:
    """Hash agregado y estable del codebase ingerido (clave de caché de M3)."""
    joined = "\n".join(f"{e.path}:{e.hash}" for e in sorted(ingestion.file_map, key=lambda x: x.path))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


# Identificador seguido de '(' → un call-site. Se extrae una vez por chunk.
_CALL_SITE_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")


def _build_call_edges(
    ingestion: IngestionResult, name_to_id: dict[str, str]
) -> list[GraphEdge]:
    """Detecta aristas ``calls`` cruzando call-sites con funciones conocidas.

    Para cada chunk extrae el conjunto de nombres invocados (``name(``) una sola
    vez y lo intersecta con los nombres de función del grafo. Complejidad
    O(total_call_sites), viable en codebases grandes (decenas de miles de chunks),
    a diferencia del enfoque ingenuo O(chunks × funciones).
    """
    known_names = set(name_to_id)
    edges: list[GraphEdge] = []
    seen: set[tuple[str, str]] = set()
    for chunk in ingestion.chunks:
        called = set(_CALL_SITE_RE.findall(chunk.code))
        for callee_name in called & known_names:
            callee_id = name_to_id[callee_name]
            if callee_id == chunk.id:
                continue
            key = (chunk.id, callee_id)
            if key in seen:
                continue
            seen.add(key)
            edges.append(
                GraphEdge(from_=chunk.id, to=callee_id, type=EdgeType.CALLS)
            )
    return edges


def _first_line(code: str) -> str:
    """Primera línea no vacía del código (aproxima la firma)."""
    for line in code.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:200]
    return ""

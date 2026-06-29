"""Chunking semántico por AST con fallback regex (CLAUDE.md §6 M1, §9b fallbacks).

Estrategia:
1. Si hay grammar de tree-sitter para el lenguaje → chunk por función/clase real.
2. Si no → ``regex-based``: heurística por firmas de función (menor precisión).
3. Último recurso → ``llm-only``: el archivo entero como un solo chunk.

El slice vertical implementa (2) y (3); (1) queda enganchable cuando
``tree-sitter`` esté instalado.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from hexflaw.infrastructure.logging import get_logger

logger = get_logger(__name__)

# Heurística de inicio de función para lenguajes tipo C y Python.
_C_FUNC_RE = re.compile(
    r"^[A-Za-z_][\w\s\*]*\b([A-Za-z_]\w*)\s*\([^;]*\)\s*\{", re.MULTILINE
)
_PY_FUNC_RE = re.compile(r"^(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(", re.MULTILINE)
# Go: 'func Name(' y 'func (r *T) Name(' (métodos con receiver).
_GO_FUNC_RE = re.compile(
    r"^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(", re.MULTILINE
)
# JS/TS: declaraciones de función, asignaciones de función/arrow, y métodos de
# clase. El nombre puede caer en cualquiera de los grupos (se toma el primero
# no nulo). Heurístico — tree-sitter da mejor precisión cuando está disponible.
_JSTS_FUNC_RE = re.compile(
    r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\("
    r"|^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
    r"(?:async\s*)?(?:function\b|\([^)]*\)\s*(?::[^=>]+)?=>|[A-Za-z_$][\w$]*\s*=>)"
    r"|^\s{2,}(?:public\s+|private\s+|protected\s+|static\s+|async\s+|get\s+|set\s+)*"
    r"([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*(?::\s*[\w<>\[\].,| ]+)?\s*\{",
    re.MULTILINE,
)
# Palabras clave que NO son nombres de función (evita falsos métodos en JS/TS).
_JSTS_KEYWORDS = frozenset(
    {"if", "for", "while", "switch", "catch", "return", "function", "constructor"}
)


@dataclass
class RawChunk:
    """Chunk crudo antes de convertirse en modelo Pydantic."""

    name: str
    code: str
    line_start: int
    line_end: int


# Tipos de nodo tree-sitter considerados "definiciones" chunkeables (multi-lenguaje).
_DEF_NODE_SUFFIXES = (
    "function_definition",
    "function_declaration",
    "function_item",  # Rust
    "method_definition",
    "method_declaration",
    "class_definition",
    "class_declaration",
    "constructor_declaration",
)

# Mapeo de id de lenguaje HexFlaw → nombre de grammar en tree-sitter-language-pack.
_TS_LANG = {
    "c": "c",
    "cpp": "cpp",
    "c++": "cpp",
    "python": "python",
    "javascript": "javascript",
    "typescript": "typescript",
    "go": "go",
    "rust": "rust",
    "java": "java",
    "php": "php",
    "ruby": "ruby",
    "solidity": "solidity",
}


def chunk_source(code: str, language: str) -> list[RawChunk]:
    """Divide el código fuente en chunks semánticos.

    Estrategia: AST con tree-sitter si la grammar está disponible; si no, regex;
    último recurso, el archivo entero (``llm-only``).

    Args:
        code: Contenido completo del archivo.
        language: Identificador de lenguaje (ej. ``"c"``, ``"python"``).

    Returns:
        Lista de :class:`RawChunk`. Si no se identifican definiciones, devuelve un
        único chunk con el archivo completo.
    """
    chunks = _chunk_with_treesitter(code, language)
    if chunks is None:
        if language == "python":
            chunks = _chunk_by_regex(code, _PY_FUNC_RE, language)
        elif language in ("c", "cpp", "c++"):
            chunks = _chunk_by_regex(code, _C_FUNC_RE, language)
        elif language == "go":
            chunks = _chunk_by_regex(code, _GO_FUNC_RE, language)
        elif language in ("javascript", "typescript"):
            chunks = _chunk_by_regex(code, _JSTS_FUNC_RE, language, skip=_JSTS_KEYWORDS)
        else:
            chunks = []

    if not chunks:
        lines = code.count("\n") + 1
        return [RawChunk(name="<module>", code=code, line_start=1, line_end=lines)]
    return chunks


def _chunk_with_treesitter(code: str, language: str) -> list[RawChunk] | None:
    """Chunking por AST con tree-sitter (CLAUDE.md §6 M1, §9b).

    Returns:
        Lista de chunks por definición, o ``None`` si tree-sitter o la grammar
        no están disponibles (para que el caller use el fallback regex).
    """
    ts_lang = _TS_LANG.get(language)
    if ts_lang is None:
        return None
    try:
        from tree_sitter_language_pack import get_parser  # type: ignore
    except ImportError:
        return None

    # Todo el flujo (parse + traversal) bajo un único guard: si el binding nativo
    # es incompatible o el árbol es patológico (T-M3-1), se cae a regex sin abortar.
    try:
        parser = get_parser(ts_lang)
        source = bytes(code, "utf-8")
        tree = parser.parse(source)
        root = tree.root_node
        chunks: list[RawChunk] = []
        stack = [root]
        depth_guard = 0
        while stack:
            depth_guard += 1
            if depth_guard > 100_000:  # corta árboles patológicos
                logger.warning("AST excede el límite de nodos; truncando chunking")
                break
            node = stack.pop()
            if any(node.type.endswith(suffix) for suffix in _DEF_NODE_SUFFIXES):
                chunks.append(_node_to_chunk(node, source))
                continue  # no descendemos: anidados quedan dentro del chunk padre
            stack.extend(reversed(node.children))
    except Exception as exc:  # binding incompatible / grammar faltante / parse error
        logger.debug("tree-sitter no usable para %s (%s); fallback a regex", language, exc)
        return None

    chunks.sort(key=lambda c: c.line_start)
    return chunks or None


def _node_to_chunk(node: object, source: bytes) -> RawChunk:
    """Convierte un nodo de definición tree-sitter en :class:`RawChunk`."""
    name = _node_name(node, source)
    text = source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")  # type: ignore[attr-defined]
    return RawChunk(
        name=name,
        code=text,
        line_start=node.start_point[0] + 1,  # type: ignore[attr-defined]
        line_end=node.end_point[0] + 1,  # type: ignore[attr-defined]
    )


def _node_name(node: object, source: bytes) -> str:
    """Extrae el nombre de una definición: primer identificador en pre-orden."""
    named = node.child_by_field_name("name")  # type: ignore[attr-defined]
    if named is not None:
        return source[named.start_byte : named.end_byte].decode("utf-8", errors="replace")
    stack = list(node.children)  # type: ignore[attr-defined]
    while stack:
        child = stack.pop(0)
        if child.type in ("identifier", "field_identifier"):
            return source[child.start_byte : child.end_byte].decode("utf-8", errors="replace")
        stack[:0] = child.children
    return "<anonymous>"


def _chunk_by_regex(
    code: str,
    pattern: re.Pattern[str],
    language: str,
    skip: frozenset[str] = frozenset(),
) -> list[RawChunk]:
    """Chunking heurístico por posiciones de firmas de función.

    Cada función abarca desde su firma hasta justo antes de la siguiente
    (o el fin del archivo). Aproximado pero estable y barato.

    Args:
        code: Contenido del archivo.
        pattern: Regex de inicio de función. El nombre se toma del primer grupo
            capturado no nulo (soporta patrones con alternativas).
        language: Identificador de lenguaje (para logging).
        skip: Nombres a ignorar (ej. keywords que parecen métodos en JS/TS).

    Returns:
        Lista de :class:`RawChunk`.
    """
    matched: list[tuple[int, str]] = []  # (offset, name)
    for m in pattern.finditer(code):
        name = next((g for g in m.groups() if g), None)
        if name is None or name in skip:
            continue
        matched.append((m.start(), name))
    if not matched:
        return []

    boundaries = [off for off, _ in matched] + [len(code)]
    chunks: list[RawChunk] = []
    for i, (off, name) in enumerate(matched):
        segment = code[boundaries[i] : boundaries[i + 1]]
        line_start = code.count("\n", 0, off) + 1
        line_end = line_start + segment.count("\n")
        chunks.append(
            RawChunk(
                name=name,
                code=segment.strip("\n"),
                line_start=line_start,
                line_end=line_end,
            )
        )
    logger.debug("chunk_by_regex(%s) -> %d chunks", language, len(chunks))
    return chunks


def chunk_hash(code: str) -> str:
    """SHA-256 del texto de un chunk (clave de caché de análisis, §16 estrategia 3)."""
    return hashlib.sha256(code.encode("utf-8", errors="replace")).hexdigest()

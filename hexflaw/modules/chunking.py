"""Chunking semántico por AST con fallback regex (CLAUDE.md §6 M1, §9b fallbacks).

Estrategia, en orden de precisión:
1. Python → módulo ``ast`` de la stdlib. Exacto y siempre disponible (sin
   dependencias opcionales), y distingue función / método / clase / módulo.
2. Otros lenguajes → grammar de tree-sitter si está instalada.
3. Si no → ``regex-based``: heurística por firmas de función (menor precisión).
4. Último recurso → ``llm-only``: el archivo entero como un solo chunk.

Solo (1) y (2) llenan ``RawChunk.kind``/``qualname``; el fallback regex los deja
en ``None`` y los consumidores (M3) degradan a sus heurísticas.
"""

from __future__ import annotations

import ast
import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from hexflaw.core.models import ChunkKind
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
    #: Naturaleza del símbolo; solo la llenan los chunkers con AST.
    kind: ChunkKind | None = None
    #: Nombre calificado dentro del archivo (ej. ``"Controller.handle"``).
    qualname: str | None = None


# Clasificación de nodos tree-sitter. Se combinan dos mecanismos:
#
# 1. Sets EXACTOS para los nodos cuyo nombre colisionaría por sufijo. El caso que
#    lo motiva: en C, ``storage_class_specifier`` (el token ``static``) termina en
#    ``class_specifier`` y se clasificaba como clase.
# 2. Sufijos, para cubrir grammars no enumeradas acá sin tener que listarlas todas.
#
# Ambos exigen que el nodo sea *named*: los tokens keyword (``class``, ``function``)
# son nodos anónimos con ese mismo nombre y generaban chunks duplicados.
_TS_FUNC_KINDS = frozenset(
    {
        "method",  # Ruby
        "singleton_method",  # Ruby
        "arrow_function",  # JS/TS
        "function_expression",  # JS/TS
        "func_literal",  # Go
        "lambda",
        "modifier_definition",  # Solidity
        "constructor_definition",  # Solidity
    }
)
_TS_CLASS_KINDS = frozenset(
    {
        "class",  # Ruby
        "module",  # Ruby
        "class_specifier",  # C++
        "struct_specifier",  # C/C++
        "union_specifier",  # C/C++
        "impl_item",  # Rust
        "trait_item",  # Rust
        "struct_item",  # Rust
        "enum_item",  # Rust
        "object_declaration",  # Kotlin
    }
)
_TS_FUNC_SUFFIXES = (
    "function_definition",
    "function_declaration",
    "function_item",
    "method_definition",
    "method_declaration",
    "constructor_declaration",
    "local_function_statement",  # C#
)
_TS_CLASS_SUFFIXES = (
    "class_definition",
    "class_declaration",
    "interface_declaration",
    "trait_declaration",
    "enum_declaration",
    "record_declaration",
    "struct_declaration",
    "protocol_declaration",  # Swift
    "contract_declaration",  # Solidity
    "library_declaration",  # Solidity
)

#: Nodos hoja que llevan el nombre de un símbolo. PHP los llama ``name``, bash
#: ``word``, el resto ``*identifier``.
_TS_NAME_KINDS = frozenset({"name", "word", "constant"})

#: Nodos padre que le dan nombre a una función anónima asignada
#: (``const handler = (req) => {...}``).
_TS_NAMED_BY_PARENT = frozenset(
    {"variable_declarator", "assignment_expression", "pair", "field_definition"}
)

# Mapeo de id de lenguaje HexFlaw → nombre de grammar en tree-sitter-language-pack.
# Cubre los 15 lenguajes builtin (CLAUDE.md §9) más los que la pack trae gratis.
_TS_LANG = {
    # Tier 1
    "c": "c",
    "cpp": "cpp",
    "c++": "cpp",
    "python": "python",
    "javascript": "javascript",
    "jsx": "javascript",
    "typescript": "typescript",
    "tsx": "tsx",
    "php": "php",
    "ruby": "ruby",
    "go": "go",
    "rust": "rust",
    "java": "java",
    # Tier 2
    "kotlin": "kotlin",
    "swift": "swift",
    "csharp": "csharp",
    "c#": "csharp",
    "solidity": "solidity",
    "bash": "bash",
    "shell": "bash",
    "sh": "bash",
    # Extras que la grammar pack ya provee
    "scala": "scala",
    "lua": "lua",
    "perl": "perl",
    "elixir": "elixir",
    "dart": "dart",
    "zig": "zig",
    "haskell": "haskell",
    "groovy": "groovy",
    "objc": "objc",
    "objective-c": "objc",
    "r": "r",
    "julia": "julia",
    "ocaml": "ocaml",
    "erlang": "erlang",
    "clojure": "clojure",
    "hcl": "hcl",
    "terraform": "hcl",
    "sql": "sql",
    "dockerfile": "dockerfile",
    "vue": "vue",
    "svelte": "svelte",
}


# --------------------------------------------------------------------------- #
# Adaptador de API de tree-sitter
# --------------------------------------------------------------------------- #
# Hay dos APIs en circulación bajo el mismo nombre de paquete: la de estilo Python
# (``node.type``, ``node.children``, ``parse(bytes)``) y la de estilo Rust
# (``node.kind()``, ``node.child(i)``, ``parse(str)``). El código de abajo funciona
# con las dos. Sin esto, el binding instalado tira TypeError, el ``except Exception``
# se lo come y TODOS los lenguajes caen al fallback regex en silencio.
def _ts_attr(node: object, *names: str) -> Any:
    """Lee el primer atributo existente de ``names``, invocándolo si es método.

    Devuelve ``Any`` a propósito: del otro lado hay una extensión C sin stubs y con
    dos APIs posibles, así que el tipo real solo se conoce en runtime. Los callers
    convierten explícitamente (``int(...)``, ``str(...)``).
    """
    for name in names:
        if not hasattr(node, name):
            continue
        value = getattr(node, name)
        return value() if callable(value) else value
    raise AttributeError(f"nodo tree-sitter sin ninguno de {names}")


def _ts_kind(node: object) -> str:
    """Tipo del nodo (``type`` en la API Python, ``kind`` en la Rust)."""
    return str(_ts_attr(node, "type", "kind"))


def _ts_children(node: object) -> list[object]:
    """Hijos del nodo, con o sin propiedad ``children``."""
    children = getattr(node, "children", None)
    if children is not None and not callable(children):
        return list(children)
    count = int(_ts_attr(node, "child_count"))
    return [node.child(i) for i in range(count)]  # type: ignore[attr-defined]


def _ts_span(node: object) -> tuple[int, int]:
    """Rango de bytes ``(start, end)`` del nodo."""
    return int(_ts_attr(node, "start_byte")), int(_ts_attr(node, "end_byte"))


def _ts_rows(node: object) -> tuple[int, int]:
    """Filas ``(start, end)`` del nodo, 0-based."""
    return _ts_row(_ts_attr(node, "start_point", "start_position")), _ts_row(
        _ts_attr(node, "end_point", "end_position")
    )


def _ts_row(point: object) -> int:
    """Fila de un Point, sea tupla o objeto con ``row``."""
    if isinstance(point, (tuple, list)):
        return int(point[0])
    return int(_ts_attr(point, "row"))  # noqa: RUF100


def _ts_field(node: object, field_name: str) -> object | None:
    """Hijo por nombre de campo, o ``None`` si el nodo no lo tiene."""
    getter = getattr(node, "child_by_field_name", None)
    if getter is None:
        return None
    try:
        child: object | None = getter(field_name)
    except Exception:  # noqa: BLE001 — binding sin ese campo para este nodo
        return None
    return child


def ts_parse(code: str, ts_lang: str) -> object | None:
    """Parsea ``code`` con la grammar ``ts_lang`` y devuelve el nodo raíz.

    Args:
        code: Código fuente completo.
        ts_lang: Nombre de grammar en tree-sitter-language-pack.

    Returns:
        El nodo raíz del AST, o ``None`` si tree-sitter no está instalado, la
        grammar no existe, o el parseo falla.
    """
    try:
        from tree_sitter_language_pack import get_parser
    except ImportError:
        return None
    try:
        parser = get_parser(ts_lang)
        try:
            tree = parser.parse(code)  # API estilo Rust: recibe str
        except TypeError:
            # API estilo Python: recibe bytes (el stub instalado declara str).
            tree = parser.parse(bytes(code, "utf-8"))  # type: ignore[arg-type]
        root: object = _ts_attr(tree, "root_node")
        return root
    except Exception as exc:  # noqa: BLE001 — grammar incompatible / árbol patológico
        logger.debug("tree-sitter no usable para %s (%s)", ts_lang, exc)
        return None


def ts_language_for(language: str) -> str | None:
    """Nombre de grammar tree-sitter para un id de lenguaje HexFlaw, o ``None``."""
    return _TS_LANG.get(language)


#: Prefijo necesario para parsear un chunk aislado. PHP es el caso: sin la etiqueta
#: de apertura, la grammar interpreta todo el fragmento como HTML literal y no
#: encuentra ni una llamada.
_TS_CHUNK_PREFIX = {"php": "<?php\n"}


def ts_chunk_prefix(language: str) -> str:
    """Texto a anteponer para que un chunk aislado parsee en su lenguaje."""
    return _TS_CHUNK_PREFIX.get(language, "")


def _ts_is_named(node: object) -> bool:
    """``True`` si el nodo es *named* (no un token keyword/puntuación)."""
    try:
        return bool(_ts_attr(node, "is_named"))
    except AttributeError:
        return True  # binding sin el atributo: no se filtra


def _ts_is_func(node: object) -> bool:
    """``True`` si el nodo es una función o método con cuerpo propio."""
    if not _ts_is_named(node):
        return False
    kind = _ts_kind(node)
    if kind in _TS_FUNC_KINDS:
        # Las funciones anónimas solo son chunk propio si están asignadas a un
        # nombre; como callback inline son ruido, quedan dentro de su chunk padre.
        if kind in ("arrow_function", "function_expression", "func_literal", "lambda"):
            return _ts_assigned_name(node) is not None
        return True
    return kind.endswith(_TS_FUNC_SUFFIXES)


def _ts_is_class(node: object) -> bool:
    """``True`` si el nodo es una clase o contenedor de métodos."""
    if not _ts_is_named(node):
        return False
    kind = _ts_kind(node)
    return kind in _TS_CLASS_KINDS or kind.endswith(_TS_CLASS_SUFFIXES)


def _ts_assigned_name(node: object) -> object | None:
    """Nodo padre que le da nombre a una función anónima asignada, si existe."""
    parent = getattr(node, "parent", None)
    resolved = parent() if callable(parent) else parent
    if resolved is None:
        return None
    return resolved if _ts_kind(resolved) in _TS_NAMED_BY_PARENT else None


def chunk_source(code: str, language: str) -> list[RawChunk]:
    """Divide el código fuente en chunks semánticos.

    Estrategia: para Python, el ``ast`` de la stdlib (exacto, sin dependencias
    opcionales); para el resto, tree-sitter si la grammar está disponible; si no,
    regex; último recurso, el archivo entero (``llm-only``).

    Args:
        code: Contenido completo del archivo.
        language: Identificador de lenguaje (ej. ``"c"``, ``"python"``).

    Returns:
        Lista de :class:`RawChunk`. Si no se identifican definiciones, devuelve un
        único chunk con el archivo completo.
    """
    chunks = _chunk_python_ast(code) if language == "python" else None
    if chunks is None:
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


#: Nodos ``ast`` que abren un scope propio y por lo tanto un chunk propio.
_PY_DEF_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def _chunk_python_ast(code: str) -> list[RawChunk] | None:
    """Chunking exacto de Python con el módulo ``ast`` de la stdlib.

    Produce un chunk por función, método, clase y (si existe código a nivel de
    módulo) un chunk ``<module>`` con el preludio — imports, constantes y
    llamadas top-level. Ese preludio es lo que después permite a M3 resolver
    alias de import; sin él, los ``import x as y`` no sobreviven a la ingestión.

    Las definiciones anidadas dentro de una función quedan dentro del chunk de
    la función (igual que en el chunker de tree-sitter); las de una clase salen
    como chunks propios de tipo ``method``.

    Args:
        code: Contenido completo del archivo ``.py``.

    Returns:
        Lista de :class:`RawChunk`, o ``None`` si el archivo no parsea (sintaxis
        inválida, o sintaxis de un Python más nuevo que el intérprete) para que
        el caller caiga al fallback regex.
    """
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError) as exc:
        logger.debug("ast.parse falló (%s); fallback regex para python", exc)
        return None

    lines = code.splitlines()
    chunks: list[RawChunk] = []
    _collect_python_defs(tree.body, lines, "", chunks)
    prelude = _python_module_prelude(tree, lines)
    if prelude is not None:
        chunks.append(prelude)
    chunks.sort(key=lambda c: c.line_start)
    return chunks or None


def _collect_python_defs(
    body: list[ast.stmt], lines: list[str], prefix: str, out: list[RawChunk]
) -> None:
    """Acumula en ``out`` un chunk por cada definición de ``body``.

    Args:
        body: Cuerpo de un módulo o de una clase.
        lines: Líneas del archivo (para recortar el texto de cada chunk).
        prefix: Prefijo de qualname (``""`` a nivel de módulo, ``"Clase."`` dentro).
        out: Lista acumuladora, mutada in-place.
    """
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append(
                _py_raw_chunk(
                    node,
                    lines,
                    kind=ChunkKind.METHOD if prefix else ChunkKind.FUNCTION,
                    qualname=f"{prefix}{node.name}",
                )
            )
        elif isinstance(node, ast.ClassDef):
            # El chunk de la clase es su "cáscara": decoradores, cabecera y
            # atributos de clase, sin el cuerpo de sus métodos (que son chunks
            # propios) — así el código no se duplica entre chunks.
            inner = [c for c in node.body if isinstance(c, _PY_DEF_NODES)]
            out.append(
                _py_raw_chunk(
                    node,
                    lines,
                    kind=ChunkKind.CLASS,
                    qualname=f"{prefix}{node.name}",
                    exclude=inner,
                )
            )
            _collect_python_defs(node.body, lines, f"{prefix}{node.name}.", out)


def _py_raw_chunk(
    node: ast.stmt,
    lines: list[str],
    *,
    kind: ChunkKind,
    qualname: str,
    exclude: Sequence[ast.stmt] | None = None,
) -> RawChunk:
    """Construye el :class:`RawChunk` de una definición, salteando sub-rangos.

    Args:
        node: Nodo de definición (``FunctionDef``/``AsyncFunctionDef``/``ClassDef``).
        lines: Líneas del archivo.
        kind: Naturaleza del símbolo.
        qualname: Nombre calificado dentro del archivo.
        exclude: Definiciones internas cuyo texto NO debe entrar en este chunk.

    Returns:
        El chunk con ``name`` desnudo y el rango de líneas real de la definición.
    """
    start = _py_def_start(node)
    end = node.end_lineno or start
    skip = _py_excluded_lines(exclude or [])
    text = "\n".join(lines[i - 1] for i in range(start, end + 1) if i not in skip)
    return RawChunk(
        name=getattr(node, "name", "<anonymous>"),
        code=text.strip("\n"),
        line_start=start,
        line_end=end,
        kind=kind,
        qualname=qualname,
    )


def _python_module_prelude(tree: ast.Module, lines: list[str]) -> RawChunk | None:
    """Chunk ``<module>`` con el código top-level (imports, constantes, llamadas).

    Returns:
        El chunk del preludio, o ``None`` si a nivel de módulo solo hay
        definiciones y (opcionalmente) el docstring — en ese caso no hay nada
        que analizar ni alias que resolver, y un chunk vacío sería solo ruido
        para el prefiltro de M4.
    """
    meaningful = [
        node
        for node in tree.body
        if not isinstance(node, _PY_DEF_NODES) and not _is_module_docstring(node, tree)
    ]
    if not meaningful:
        return None

    start = min(node.lineno for node in meaningful)
    end = max(node.end_lineno or node.lineno for node in meaningful)
    skip = _py_excluded_lines([n for n in tree.body if isinstance(n, _PY_DEF_NODES)])
    text = "\n".join(lines[i - 1] for i in range(start, end + 1) if i not in skip)
    return RawChunk(
        name="<module>",
        code=text.strip("\n"),
        line_start=start,
        line_end=end,
        kind=ChunkKind.MODULE,
    )


def _py_def_start(node: ast.stmt) -> int:
    """Primera línea de una definición, contando sus decoradores."""
    decorators: list[ast.expr] = getattr(node, "decorator_list", [])
    return min([node.lineno, *(decorator.lineno for decorator in decorators)])


def _py_excluded_lines(nodes: Sequence[ast.stmt]) -> set[int]:
    """Conjunto de líneas ocupadas por las definiciones dadas."""
    skip: set[int] = set()
    for node in nodes:
        start = _py_def_start(node)
        skip.update(range(start, (node.end_lineno or start) + 1))
    return skip


def _is_module_docstring(node: ast.stmt, tree: ast.Module) -> bool:
    """``True`` si ``node`` es el docstring del módulo."""
    return (
        bool(tree.body)
        and node is tree.body[0]
        and isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


#: Tope de nodos visitados en el traversal, contra árboles patológicos (T-M3-1).
_TS_NODE_BUDGET = 100_000


def _chunk_with_treesitter(code: str, language: str) -> list[RawChunk] | None:
    """Chunking por AST con tree-sitter (CLAUDE.md §6 M1, §9b).

    Emite un chunk por función, método y clase, más un chunk ``<module>`` con el
    preludio del archivo (imports, globales) cuando hay algo fuera de las
    definiciones. Igual que la ruta de Python, la clase queda como "cáscara" sin el
    cuerpo de sus métodos para no duplicar código entre chunks.

    Args:
        code: Contenido completo del archivo.
        language: Identificador de lenguaje HexFlaw.

    Returns:
        Lista de chunks por definición, o ``None`` si tree-sitter o la grammar
        no están disponibles (para que el caller use el fallback regex).
    """
    ts_lang = ts_language_for(language)
    if ts_lang is None:
        return None
    root = ts_parse(code, ts_lang)
    if root is None:
        return None

    source = code.encode("utf-8")
    lines = code.splitlines()
    chunks: list[RawChunk] = []
    budget = [_TS_NODE_BUDGET]
    try:
        _ts_collect(root, source, lines, "", chunks, budget)
        prelude = _ts_module_prelude(root, lines, budget)
    except Exception as exc:  # noqa: BLE001 — binding incompatible / árbol raro
        logger.debug("traversal tree-sitter falló para %s (%s); fallback regex", language, exc)
        return None
    if prelude is not None:
        chunks.append(prelude)

    chunks.sort(key=lambda c: c.line_start)
    return chunks or None


def _ts_collect(
    node: object,
    source: bytes,
    lines: list[str],
    prefix: str,
    out: list[RawChunk],
    budget: list[int],
) -> None:
    """Acumula chunks por definición descendiendo el árbol tree-sitter.

    Args:
        node: Nodo actual.
        source: Archivo en bytes (los offsets de tree-sitter son de byte).
        lines: Líneas del archivo.
        prefix: Prefijo de qualname (``""`` a nivel de archivo, ``"Clase."`` dentro).
        out: Lista acumuladora, mutada in-place.
        budget: Presupuesto de nodos restante, como celda mutable de un elemento.
    """
    for child in _ts_children(node):
        budget[0] -= 1
        if budget[0] <= 0:
            logger.warning("AST excede el límite de nodos; truncando chunking")
            return
        if _ts_is_func(child):
            name = _ts_name(child, source)
            out.append(
                _ts_raw_chunk(
                    child,
                    source,
                    lines,
                    name=name,
                    kind=ChunkKind.METHOD if prefix else ChunkKind.FUNCTION,
                    qualname=f"{prefix}{name}",
                )
            )
            continue  # no descendemos: los anidados quedan dentro del chunk padre
        if _ts_is_class(child):
            name = _ts_name(child, source)
            inner = _ts_inner_defs(child)
            out.append(
                _ts_raw_chunk(
                    child,
                    source,
                    lines,
                    name=name,
                    kind=ChunkKind.CLASS,
                    qualname=f"{prefix}{name}",
                    exclude=inner,
                )
            )
            _ts_collect(child, source, lines, f"{prefix}{name}.", out, budget)
            continue
        _ts_collect(child, source, lines, prefix, out, budget)


def _ts_inner_defs(node: object) -> list[object]:
    """Definiciones internas de una clase (a cualquier profundidad de su cuerpo).

    Se busca en profundidad porque muchas grammars envuelven el cuerpo en un nodo
    intermedio (``class_body``, ``declaration_list``, ``block``).
    """
    found: list[object] = []
    stack = list(_ts_children(node))
    while stack:
        child = stack.pop()
        if _ts_is_func(child) or _ts_is_class(child):
            found.append(child)
            continue  # no descendemos: su rango ya cubre lo de adentro
        stack.extend(_ts_children(child))
    return found


def _ts_raw_chunk(
    node: object,
    source: bytes,
    lines: list[str],
    *,
    name: str,
    kind: ChunkKind,
    qualname: str,
    exclude: Sequence[object] | None = None,
) -> RawChunk:
    """Construye el :class:`RawChunk` de una definición tree-sitter."""
    start_row, end_row = _ts_rows(node)
    start, end = start_row + 1, end_row + 1
    skip = _ts_excluded_lines(exclude or [])
    if skip:
        text = "\n".join(lines[i - 1] for i in range(start, end + 1) if i not in skip)
    else:
        span_start, span_end = _ts_span(node)
        text = source[span_start:span_end].decode("utf-8", errors="replace")
    return RawChunk(
        name=name,
        code=text.strip("\n"),
        line_start=start,
        line_end=end,
        kind=kind,
        qualname=qualname,
    )


def _ts_excluded_lines(nodes: Sequence[object]) -> set[int]:
    """Líneas ocupadas por los nodos dados (1-based)."""
    skip: set[int] = set()
    for node in nodes:
        start_row, end_row = _ts_rows(node)
        skip.update(range(start_row + 1, end_row + 2))
    return skip


def _ts_module_prelude(
    root: object, lines: list[str], budget: list[int]
) -> RawChunk | None:
    """Chunk ``<module>`` con lo que queda fuera de toda definición top-level.

    En C son los ``#include`` y las globales; en Go/JS/Java los imports. Es lo que
    después le permite a M3 y a M4 ver constantes hardcodeadas y llamadas a nivel
    de archivo. Devuelve ``None`` si no queda nada más que blancos.
    """
    top_defs = [
        child
        for child in _ts_children(root)
        if _ts_is_func(child) or _ts_is_class(child)
    ]
    if not top_defs:
        return None  # el archivo entero ya es "preludio": lo cubre el caller
    skip = _ts_excluded_lines(top_defs)
    kept = [(i, lines[i - 1]) for i in range(1, len(lines) + 1) if i not in skip]
    meaningful = [i for i, text in kept if text.strip()]
    if not meaningful:
        return None
    start, end = meaningful[0], meaningful[-1]
    text = "\n".join(text for i, text in kept if start <= i <= end)
    return RawChunk(
        name="<module>",
        code=text.strip("\n"),
        line_start=start,
        line_end=end,
        kind=ChunkKind.MODULE,
    )


def _ts_name(node: object, source: bytes) -> str:
    """Nombre de una definición.

    Prueba, en orden: el campo ``name``; el campo ``declarator`` (C/C++, donde el
    nombre vive dentro del declarador); el padre que la asigna (``const f = () =>``);
    y como último recurso el primer identificador en pre-orden.
    """
    for field_name in ("name", "declarator"):
        named = _ts_field(node, field_name)
        if named is not None:
            text = _ts_identifier_text(named, source)
            if text:
                return text
    assigner = _ts_assigned_name(node)
    if assigner is not None:
        text = _ts_identifier_text(assigner, source)
        if text:
            return text
    text = _ts_identifier_text(node, source)
    return text or "<anonymous>"


def _ts_identifier_text(node: object, source: bytes) -> str:
    """Texto del primer identificador en pre-orden bajo ``node``."""
    stack = [node]
    while stack:
        current = stack.pop(0)
        kind = _ts_kind(current)
        if kind.endswith("identifier") or kind in _TS_NAME_KINDS:
            start, end = _ts_span(current)
            return source[start:end].decode("utf-8", errors="replace")
        stack[:0] = _ts_children(current)
    return ""


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

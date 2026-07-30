"""M3 — Code Graph Builder (CLAUDE.md §6 M3).

Construye tres tipos de arista sobre los chunks de M1:

- :attr:`EdgeType.CALLS` — A invoca a B.
- :attr:`EdgeType.DATA_FLOW` — datos de A llegan a B: un argumento controlable, o
  el valor de retorno volviendo al caller. Lleva ``data_vars`` (qué variables
  viajan) y ``sanitized`` (si pasaron por un sanitizador reconocido).
- :attr:`EdgeType.CONTROL_FLOW` — llegar a B desde A depende de una condición,
  con el texto de la guarda en ``condition``.

**Alcance honesto de lo que "flujo" significa acá.** El data flow es
*intra-procedural con enlace inter-procedural*: dentro de cada función se propaga
el taint por asignaciones, y entre funciones se conecta por argumentos y retornos.
Es una **sobre-aproximación**: los parámetros de toda función se consideran
controlables, porque quién es realmente alcanzable lo decide la topología del
grafo, no el análisis local. No hay análisis de alias de punteros/objetos, ni de
campos, ni sensibilidad al camino. El control flow tampoco es un CFG de bloques
básicos: no hay nodos por bloque, se anota qué condiciones guardan cada llamada.
Sirve para que M5 distinga ``confirmed`` de ``conditional`` con evidencia en vez
de intuición; no reemplaza un análisis sound.

Tres caminos de construcción, del más preciso al más grueso:

**1. Python — ``ast`` de la stdlib.** Resuelve por estructura sintáctica:

- ``foo()`` → función/clase del mismo archivo; si no está, un símbolo top-level
  con nombre único en todo el proyecto (si hay dos, no se liga: ambiguo).
- ``modulo.foo()`` / ``alias.foo()`` → expande el alias de import y busca el
  símbolo en el archivo que provee ese módulo.
- ``self.foo()`` → método de la misma clase. ``Clase.metodo()`` → ídem.
- Alias: ``import subprocess as sp``, ``from os import system as syscmd``.
- Sinks por **nombre resuelto** de la llamada (``sp.run`` → ``subprocess.run``),
  comparado por segmentos; entry points por nombre real del símbolo y decoradores.
- Taint con sanitizadores (:data:`_PY_SANITIZERS`) y fuentes
  (:data:`_PY_SOURCES`).

**2. Resto de lenguajes — tree-sitter.** Misma forma, resolución más gruesa: se
queda con el último segmento del nombre calificado, resuelve en el archivo y
después por unicidad en el proyecto. El data flow se aproxima por nombre (un
parámetro de la función que aparece entre los argumentos), sin propagación por
asignaciones intermedias ni sanitizadores. Las guardas sí se detectan igual.
No modela imports ni alias por lenguaje.

**3. Fallback regex.** Cuando no hay AST posible: una arista ``calls`` A→B si el
nombre de B aparece invocado (``B(``) en el código de A. Cruza nombres sin
resolver scope; nunca emite aristas de flujo.

Los tres conviven en el mismo grafo, chunk por chunk, y producen el mismo
:class:`CodeGraph` de siempre. Ante ambigüedad no se emite arista: una arista
inventada le hace creer a M5 que existe un camino que no existe.
"""

from __future__ import annotations

import ast
import hashlib
import re
import textwrap
from dataclasses import dataclass, field

from hexflaw.core.models import (
    ChunkKind,
    CodeChunk,
    CodeGraph,
    EdgeType,
    GraphEdge,
    GraphNode,
    IngestionResult,
    NodeType,
    SinkRef,
)
from hexflaw.infrastructure.logging import get_logger
from hexflaw.modules.chunking import (
    _ts_children,
    _ts_field,
    _ts_kind,
    _ts_span,
    ts_chunk_prefix,
    ts_language_for,
    ts_parse,
)
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


#: Naturaleza del chunk (la pone el chunker AST) → tipo de nodo del grafo.
_KIND_TO_NODE: dict[ChunkKind, NodeType] = {
    ChunkKind.FUNCTION: NodeType.FUNCTION,
    ChunkKind.METHOD: NodeType.METHOD,
    ChunkKind.CLASS: NodeType.CLASS,
    ChunkKind.MODULE: NodeType.MODULE,
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
    symbols = _index_ast_symbols(ingestion.chunks)
    ast_facts = _python_facts(ingestion.chunks, symbols.aliases)
    ast_facts.update(_ts_flow_facts(ingestion.chunks))

    nodes: list[GraphNode] = []
    name_to_id: dict[str, str] = {}
    entry_points: list[str] = []
    sinks: list[SinkRef] = []

    for chunk in ingestion.chunks:
        definition = languages_service.get(chunk.language)
        entry_patterns = definition.entry_point_patterns if definition else []
        sink_patterns = definition.sink_patterns if definition else []
        facts = ast_facts.get(chunk.id)

        if facts is not None:
            is_entry = _ast_is_entry_point(chunk, facts, entry_patterns)
            matched_sinks = _ast_matched_sinks(chunk, facts, sink_patterns)
        else:
            is_entry = any(p in chunk.code for p in entry_patterns)
            matched_sinks = [p for p in sink_patterns if p in chunk.code]

        node = GraphNode(
            id=chunk.id,
            type=_node_type(chunk),
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

    # Los nodos MODULE van al final: su rango de líneas abarca todo el archivo y
    # M5 (_locate_node) cae al match por rango cuando no hay match por nombre —
    # si el módulo fuera primero, se comería los findings de sus propias funciones.
    nodes.sort(key=lambda n: n.type == NodeType.MODULE)

    fallback_chunks = [c for c in ingestion.chunks if c.id not in ast_facts]
    by_language: dict[str, int] = {}
    for chunk in ingestion.chunks:
        if chunk.id in ast_facts:
            by_language[chunk.language] = by_language.get(chunk.language, 0) + 1
    logger.info(
        "M3: %d chunks resueltos por AST (%s), %d por fallback regex",
        len(ast_facts),
        ", ".join(f"{lang}:{n}" for lang, n in sorted(by_language.items())) or "ninguno",
        len(fallback_chunks),
    )
    edges = _dedup_edges(
        _build_ast_flow_edges(ingestion.chunks, ast_facts, symbols)
        + _build_call_edges(fallback_chunks, name_to_id)
    )
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
    chunks: list[CodeChunk], name_to_id: dict[str, str]
) -> list[GraphEdge]:
    """Detecta aristas ``calls`` cruzando call-sites con funciones conocidas.

    Fallback general para lenguajes sin ruta AST (y para Python que no parsea).
    Para cada chunk extrae el conjunto de nombres invocados (``name(``) una sola
    vez y lo intersecta con los nombres de función del grafo. Complejidad
    O(total_call_sites), viable en codebases grandes (decenas de miles de chunks),
    a diferencia del enfoque ingenuo O(chunks × funciones).

    No resuelve scope, alias ni imports: si dos archivos definen ``handler``,
    todas las llamadas a ``handler(`` se ligan al primero indexado.

    Args:
        chunks: Chunks a procesar como origen de llamadas.
        name_to_id: Nombre de símbolo → id de nodo (primero indexado gana).

    Returns:
        Aristas ``calls`` detectadas, sin duplicados.
    """
    known_names = set(name_to_id)
    edges: list[GraphEdge] = []
    seen: set[tuple[str, str]] = set()
    for chunk in chunks:
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


def _dedup_edges(edges: list[GraphEdge]) -> list[GraphEdge]:
    """Elimina aristas repetidas preservando el orden de aparición."""
    seen: set[tuple[str, str, EdgeType]] = set()
    unique: list[GraphEdge] = []
    for edge in edges:
        key = (edge.from_, edge.to, edge.type)
        if key in seen:
            continue
        seen.add(key)
        unique.append(edge)
    return unique


def _node_type(chunk: CodeChunk) -> NodeType:
    """Tipo de nodo del chunk: por ``kind`` si el chunker usó AST, si no heurístico."""
    if chunk.kind is not None:
        return _KIND_TO_NODE.get(chunk.kind, NodeType.FUNCTION)
    return NodeType.MODULE if chunk.name == "<module>" else NodeType.FUNCTION


# --------------------------------------------------------------------------- #
# Ruta Python — resolución de llamadas por AST (stdlib ``ast``)
# --------------------------------------------------------------------------- #
#: Llamadas cuyo resultado se considera dato controlable por el atacante. Semilla
#: de taint para el código a nivel de módulo, donde no hay parámetros.
_PY_SOURCES: tuple[str, ...] = (
    "input",
    "sys.argv",
    "sys.stdin",
    "os.environ",
    "os.getenv",
)

#: Llamadas que neutralizan el dato que reciben. Heurística deliberadamente corta:
#: solo lo indiscutible. Un dato que pasa por acá deja de estar tainted y la arista
#: queda marcada ``sanitized`` para que M5 lo sepa en vez de adivinarlo.
_PY_SANITIZERS: tuple[str, ...] = (
    "shlex.quote",
    "shlex.join",
    "html.escape",
    "urllib.parse.quote",
    "urllib.parse.quote_plus",
    "re.escape",
    "int",
    "float",
    "bool",
    "os.path.basename",
)

#: Largo máximo del texto de una condición en ``GraphEdge.condition``.
_CONDITION_MAX = 160


@dataclass
class _PyCall:
    """Una llamada concreta encontrada en un chunk, con su contexto de flujo."""

    #: Nombre punteado tal como está escrito (``sp.run``, ``self.execute``).
    name: str
    #: El mismo nombre con el alias de import expandido (``subprocess.run``).
    resolved: str
    #: Variables tainted que se pasan como argumento (data flow hacia el callee).
    data_vars: list[str] = field(default_factory=list)
    #: Condiciones que hay que satisfacer para llegar a esta llamada.
    guards: list[str] = field(default_factory=list)
    #: Variable que recibe el resultado (data flow de vuelta), o ``"<return>"``.
    returns_to: str | None = None
    #: ``True`` si algún argumento pasó por un sanitizador reconocido.
    sanitized: bool = False


@dataclass
class _PyChunkFacts:
    """Lo que el AST sabe de un chunk de Python."""

    #: Llamadas del chunk con su contexto de flujo.
    calls: list[_PyCall] = field(default_factory=list)
    #: Nombres punteados de los decoradores del símbolo (``app.route``).
    decorators: list[str] = field(default_factory=list)
    #: ``True`` solo cuando los nombres de llamada vienen con el alias de import ya
    #: expandido (ruta Python). Con eso se puede exigir que un patrón de sink que
    #: nombra una llamada matchee CONTRA la llamada resuelta y descartar el
    #: substring. Sin expansión de alias (ruta tree-sitter) esa exigencia solo
    #: perdería recall: ``tx.origin`` es una lectura de atributo, no una llamada, y
    #: desaparecería del grafo.
    precise_calls: bool = False

    @property
    def resolved_calls(self) -> list[str]:
        """Nombres resueltos de todas las llamadas (para el match de sinks)."""
        return [call.resolved for call in self.calls]


@dataclass
class _PySymbols:
    """Índice de símbolos Python del proyecto, por archivo."""

    #: (archivo, función top-level) → id de nodo.
    functions: dict[tuple[str, str], str] = field(default_factory=dict)
    #: (archivo, qualname de clase) → id de nodo.
    classes: dict[tuple[str, str], str] = field(default_factory=dict)
    #: (archivo, qualname de clase, método) → id de nodo.
    methods: dict[tuple[str, str, str], str] = field(default_factory=dict)
    #: archivo → {nombre local de import: dotted name real}.
    aliases: dict[str, dict[str, str]] = field(default_factory=dict)
    #: módulo punteado → archivo que lo provee (``""`` si es ambiguo). Solo Python.
    file_of_module: dict[str, str] = field(default_factory=dict)
    #: (lenguaje, símbolo top-level) → ids que lo definen. La clave incluye el
    #: lenguaje para que un ``handler`` de Go no se ligue a uno de PHP en un repo
    #: políglota.
    defs_by_name: dict[tuple[str, str], set[str]] = field(default_factory=dict)


def _python_facts(
    chunks: list[CodeChunk], aliases_by_file: dict[str, dict[str, str]]
) -> dict[str, _PyChunkFacts]:
    """Parsea cada chunk de Python y extrae sus llamadas y decoradores.

    Solo entran los chunks que M1 produjo con AST (``kind`` presente) y que
    vuelven a parsear por separado. Un chunk que no parsea queda fuera y su
    dueño cae al fallback regex — nunca se aborta el grafo por un archivo raro.

    Args:
        chunks: Todos los chunks de la ingestión.
        aliases_by_file: Alias de import por archivo (de :class:`_PySymbols`).

    Returns:
        ``{chunk_id: facts}`` solo para los chunks con ruta AST disponible.
    """
    trees: dict[str, tuple[CodeChunk, ast.Module]] = {}
    for chunk in chunks:
        if chunk.language != "python" or chunk.kind is None:
            continue
        tree = _parse_chunk(chunk)
        if tree is not None:
            trees[chunk.id] = (chunk, tree)

    # Pasada 1 — resumen de taint por clase. Guardar un dato controlable en un
    # campo (``self.cmd = user``) y usarlo en OTRO método es un patrón habitual, y
    # cada método es un chunk distinto: sin este resumen el flujo se corta ahí.
    attributes_by_class: dict[tuple[str, str], set[str]] = {}
    for chunk, tree in trees.values():
        owner = _owner_class(chunk)
        if owner is None:
            continue
        visitor = _PyFlowVisitor(aliases_by_file.get(chunk.file, {}))
        visitor.run(tree)
        fields = {name for name in visitor.tainted if _is_self_attribute(name)}
        if fields:
            attributes_by_class.setdefault((chunk.file, owner), set()).update(fields)

    # Pasada 2 — se re-analiza cada método sembrando los campos que cualquier
    # método de su clase contamina.
    facts: dict[str, _PyChunkFacts] = {}
    for chunk, tree in trees.values():
        owner = _owner_class(chunk)
        seed = attributes_by_class.get((chunk.file, owner or ""), set())
        visitor = _PyFlowVisitor(aliases_by_file.get(chunk.file, {}), seed_tainted=seed)
        visitor.run(tree)
        facts[chunk.id] = _PyChunkFacts(
            calls=visitor.calls,
            decorators=_chunk_decorators(tree),
            precise_calls=True,
        )
    return facts


def _is_self_attribute(name: str) -> bool:
    """``True`` si ``name`` es un campo de instancia (``self.x`` / ``cls.x``)."""
    return name.startswith(("self.", "cls."))


@dataclass
class _TaintState:
    """Estado de taint en un punto del programa."""

    tainted: set[str] = field(default_factory=set)
    sanitized: set[str] = field(default_factory=set)

    def copy(self) -> _TaintState:
        """Copia independiente, para analizar una rama sin contaminar las otras."""
        return _TaintState(tainted=set(self.tainted), sanitized=set(self.sanitized))


def _merge_states(states: list[_TaintState]) -> _TaintState:
    """Une los estados de varias ramas mutuamente excluyentes.

    Una variable queda **tainted si lo está en CUALQUIER rama** (unión) y
    **sanitized solo si lo está en TODAS** (intersección). Es la única fusión
    segura para SAST: sanitizar dentro de un ``if`` no sanitiza el camino del
    ``else``, y tratarlo al revés produce falsos negativos — que en una
    herramienta de seguridad son mucho peores que un falso positivo.
    """
    merged = _TaintState()
    for state in states:
        merged.tainted |= state.tainted
    common = [state.sanitized for state in states]
    merged.sanitized = set.intersection(*common) if common else set()
    merged.sanitized -= merged.tainted  # tainted por algún camino gana
    return merged


class _PyFlowVisitor(ast.NodeVisitor):
    """Recorre un chunk de Python registrando llamadas, taint y guardas.

    El análisis es **intra-procedural y sobre-aproximado a propósito**:

    - Los parámetros de cada función se consideran controlables por el atacante.
      Es la aproximación correcta para SAST: si la función es alcanzable desde un
      entry point, sus parámetros lo son. Quién es realmente alcanzable lo decide
      el grafo (M5), no este visitor.
    - El taint se propaga por asignación cuando la expresión fuente menciona una
      variable tainted, y se corta cuando pasa por un sanitizador de
      :data:`_PY_SANITIZERS`.
    - Es **sensible a ramas**: cada rama de un ``if``/``try``/``match`` se analiza
      sobre una copia del estado y después se fusionan con :func:`_merge_states`.
      Sin esto, ``if cond: x = quote(x)`` seguido de ``sink(x)`` marcaba el flujo
      como sanitizado e ignoraba el camino del ``else`` — un falso negativo.
    - Sigue atributos de un nivel (``self.cmd``), no alias de objetos arbitrarios.
    - No hay sensibilidad al camino completo (no se evalúan condiciones), ni
      análisis inter-procedural de valores. No pretende ser sound.
    """

    def __init__(
        self, aliases: dict[str, str], *, seed_tainted: set[str] | None = None
    ) -> None:
        self.aliases = aliases
        self.calls: list[_PyCall] = []
        self._state = _TaintState(tainted=set(seed_tainted or ()))
        self._guards: list[str] = []
        self._flows_to: str | None = None

    @property
    def tainted(self) -> set[str]:
        """Variables actualmente controlables por el atacante."""
        return self._state.tainted

    @property
    def sanitized(self) -> set[str]:
        """Variables que pasaron por un sanitizador en TODOS los caminos."""
        return self._state.sanitized

    def run(self, tree: ast.Module) -> None:
        """Analiza el chunk: siembra los parámetros y recorre el cuerpo."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._state.tainted.update(_param_names(node))
        self.generic_visit(tree)

    # ------------------------- ramas y guardas ---------------------------- #
    def _visit_branches(
        self, branches: list[tuple[list[ast.stmt], str]], *, optional: bool
    ) -> None:
        """Analiza ramas excluyentes por separado y fusiona el estado resultante.

        Args:
            branches: Pares ``(cuerpo, guarda)``. La guarda se apila mientras se
                recorre ese cuerpo, para anotar las llamadas de adentro.
            optional: ``True`` si el flujo puede saltear todas las ramas (un ``if``
                sin ``else``, un loop que corre cero veces). En ese caso el estado
                previo entra también a la fusión.
        """
        before = self._state
        results: list[_TaintState] = [before.copy()] if optional else []
        for body, guard in branches:
            self._state = before.copy()
            self._guards.append(_condition_text(guard))
            for statement in body:
                self.visit(statement)
            self._guards.pop()
            results.append(self._state)
        self._state = _merge_states(results) if results else before

    def visit_If(self, node: ast.If) -> None:
        test = ast.unparse(node.test)
        branches = [(node.body, f"if {test}")]
        if node.orelse:
            branches.append((node.orelse, f"not ({test})"))
        self._visit_branches(branches, optional=not node.orelse)

    def visit_While(self, node: ast.While) -> None:
        # El cuerpo puede correr cero veces → el estado previo también cuenta.
        self._visit_branches(
            [(node.body, f"while {ast.unparse(node.test)}")], optional=True
        )

    def visit_For(self, node: ast.For) -> None:
        # Iterar sobre un dato tainted contamina la variable de iteración.
        if self._names_in(node.iter) & self.tainted:
            self._state.tainted.update(_target_names(node.target))
        self._visit_branches(
            [(node.body, f"for {ast.unparse(node.target)} in ...")], optional=True
        )

    def visit_Try(self, node: ast.Try) -> None:
        branches: list[tuple[list[ast.stmt], str]] = [(node.body, "try")]
        for handler in node.handlers:
            branches.append((handler.body, "except"))
        if node.orelse:
            branches.append((node.orelse, "try/else"))
        self._visit_branches(branches, optional=False)
        # 'finally' corre siempre, en secuencia sobre el estado ya fusionado.
        for statement in node.finalbody:
            self.visit(statement)

    def visit_Match(self, node: ast.Match) -> None:
        branches = [
            (case.body, f"case {ast.unparse(case.pattern)}") for case in node.cases
        ]
        self._visit_branches(branches, optional=True)

    # ------------------------------ data flow ----------------------------- #
    def visit_Assign(self, node: ast.Assign) -> None:
        targets = [name for t in node.targets for name in _target_names(t)]
        self._visit_value(node.value, targets)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._visit_value(node.value, _target_names(node.target))

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        # 'cmd += user_input' contamina cmd sin dejar de contar lo que ya tenía.
        targets = _target_names(node.target)
        if self._names_in(node.value) & self.tainted:
            self._state.tainted.update(targets)
        self._visit_value(node.value, targets)

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None:
            self._flows_to, previous = "<return>", self._flows_to
            self.generic_visit(node)
            self._flows_to = previous

    def _visit_value(self, value: ast.expr, targets: list[str]) -> None:
        """Visita el lado derecho de una asignación y propaga el taint."""
        self._flows_to, previous = (targets[0] if targets else None), self._flows_to
        self.visit(value)
        self._flows_to = previous

        if self._matches(value, _PY_SANITIZERS):
            # Sanitizado: deja de estar tainted, y se recuerda para marcar la arista.
            self._state.sanitized.update(targets)
            self._state.tainted.difference_update(targets)
        elif self._names_in(value) & self.tainted or self._matches(value, _PY_SOURCES):
            self._state.tainted.update(targets)
            self._state.sanitized.difference_update(targets)

    def visit_Call(self, node: ast.Call) -> None:
        name = _python_call_name(node.func)
        if name is not None:
            # El data flow se registra también cuando el dato viene sanitizado: que
            # M5 vea "llega pero pasó por shlex.quote" es más útil que no ver nada.
            # 'sanitized' solo es True si NINGÚN argumento llega sin sanitizar.
            #
            # Se evalúa argumento por argumento porque la sanitización inline
            # (``run(shlex.quote(x))``) es más común que la asignada, y mirando el
            # conjunto de nombres de toda la llamada se perdía.
            tainted_args: set[str] = set()
            sanitized_args: set[str] = set()
            for argument in (*node.args, *(kw.value for kw in node.keywords)):
                names = self._names_in(argument)
                if self._matches(argument, _PY_SANITIZERS):
                    sanitized_args |= names & (self.tainted | self.sanitized)
                else:
                    tainted_args |= names & self.tainted
                    sanitized_args |= names & self.sanitized
            self.calls.append(
                _PyCall(
                    name=name,
                    resolved=_expand_alias(name, self.aliases),
                    data_vars=sorted(tainted_args | sanitized_args),
                    guards=list(self._guards),
                    returns_to=self._flows_to,
                    sanitized=bool(sanitized_args) and not tainted_args,
                )
            )
        self.generic_visit(node)  # llamadas anidadas en los argumentos

    # ------------------------------ helpers ------------------------------- #
    def _names_in(self, expr: ast.expr) -> set[str]:
        """Nombres de variable que aparecen en ``expr``.

        Incluye los accesos a atributo como nombre punteado (``self.cmd``) además
        de la base (``self``), para poder seguir taint guardado en un campo. No es
        análisis de alias: ``otro = self; otro.cmd`` no se sigue.
        """
        names: set[str] = set()
        for node in ast.walk(expr):
            if isinstance(node, ast.Name):
                names.add(node.id)
            elif isinstance(node, ast.Attribute):
                dotted = _python_call_name(node)
                if dotted is not None:
                    names.add(dotted)
        return names

    def _matches(self, expr: ast.expr, patterns: tuple[str, ...]) -> bool:
        """``True`` si ``expr`` llama o lee alguno de los ``patterns`` dados."""
        for node in ast.walk(expr):
            candidate: ast.expr | None = None
            if isinstance(node, ast.Call):
                candidate = node.func
            elif isinstance(node, ast.Attribute):
                candidate = node
            if candidate is None:
                continue
            name = _python_call_name(candidate)
            if name is None:
                continue
            resolved = _expand_alias(name, self.aliases)
            if any(_segments_match(pattern, resolved) for pattern in patterns):
                return True
        return False


def _param_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """Nombres de los parámetros de una función, sin ``self``/``cls``."""
    spec = node.args
    names = [
        arg.arg
        for arg in (*spec.posonlyargs, *spec.args, *spec.kwonlyargs)
        if arg.arg not in ("self", "cls")
    ]
    if spec.vararg is not None:
        names.append(spec.vararg.arg)
    if spec.kwarg is not None:
        names.append(spec.kwarg.arg)
    return names


def _target_names(target: ast.expr) -> list[str]:
    """Nombres asignados por un target.

    Soporta tuplas/listas (``a, b = ...``) y atributos de un nivel
    (``self.cmd = ...`` → ``"self.cmd"``), que es como se guarda taint en un campo.
    """
    if isinstance(target, ast.Attribute):
        dotted = _python_call_name(target)
        return [dotted] if dotted is not None else []
    if isinstance(target, (ast.Tuple, ast.List)):
        return [name for element in target.elts for name in _target_names(element)]
    if isinstance(target, ast.Name):
        return [target.id]
    return [node.id for node in ast.walk(target) if isinstance(node, ast.Name)]


def _condition_text(condition: str) -> str:
    """Normaliza y acorta el texto de una guarda para el artefacto."""
    flat = " ".join(condition.split())
    return flat[:_CONDITION_MAX]


def _parse_chunk(chunk: CodeChunk) -> ast.Module | None:
    """Parsea el código de un chunk aislado, o ``None`` si no es parseable.

    Los métodos vienen indentados (son un fragmento del cuerpo de su clase), así
    que se dedentan antes de parsear. Un chunk de clase cuyo cuerpo son solo
    métodos queda en ``class X:`` sin cuerpo y no parsea — es esperado y cae al
    fallback.
    """
    try:
        return ast.parse(textwrap.dedent(chunk.code))
    except (SyntaxError, ValueError, RecursionError) as exc:
        logger.debug("chunk %s no parsea como Python (%s); fallback regex", chunk.id, exc)
        return None


def _python_import_aliases(code: str) -> dict[str, str]:
    """Mapea cada nombre importado a su dotted name real.

    ``import os`` → ``{"os": "os"}``;
    ``import subprocess as sp`` → ``{"sp": "subprocess"}``;
    ``from os import system as syscmd`` → ``{"syscmd": "os.system"}``.

    Los imports relativos (``from . import x``) se ignoran: no se pueden mapear a
    un dotted name absoluto sin conocer el paquete raíz del proyecto.

    Args:
        code: Código del chunk ``<module>`` (el preludio del archivo).

    Returns:
        ``{nombre local: dotted name}``. Vacío si el preludio no parsea.
    """
    try:
        tree = ast.parse(textwrap.dedent(code))
    except (SyntaxError, ValueError, RecursionError):
        return {}

    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    # 'import os.path' liga el nombre 'os', no 'os.path'.
                    head = alias.name.split(".")[0]
                    aliases[head] = head
        elif isinstance(node, ast.ImportFrom) and not node.level:
            module = node.module or ""
            for alias in node.names:
                local = alias.asname or alias.name
                aliases[local] = f"{module}.{alias.name}" if module else alias.name
    return aliases


def _python_call_name(func: ast.expr) -> str | None:
    """Nombre punteado del invocado en un ``ast.Call``.

    ``foo()`` → ``"foo"``; ``sp.run()`` → ``"sp.run"``; ``self.x()`` → ``"self.x"``.

    Returns:
        El nombre punteado, o ``None`` si la llamada es sobre un valor computado
        (``get_handler()()``, ``objs[0].run()``): no es resoluble estáticamente.
    """
    parts: list[str] = []
    node: ast.expr = func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def _expand_alias(name: str, aliases: dict[str, str]) -> str:
    """Reemplaza el primer segmento de ``name`` por su dotted name real."""
    head, _, rest = name.partition(".")
    target = aliases.get(head)
    if target is None:
        return name
    return f"{target}.{rest}" if rest else target


def _chunk_decorators(tree: ast.Module) -> list[str]:
    """Nombres punteados de los decoradores de la definición top-level del chunk."""
    if not tree.body:
        return []
    node = tree.body[0]
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return []
    names: list[str] = []
    for decorator in node.decorator_list:
        expr = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = _python_call_name(expr)
        if name is not None:
            names.append(name)
    return names


def _index_ast_symbols(chunks: list[CodeChunk]) -> _PySymbols:
    """Indexa funciones, clases, métodos, alias y módulos de todo chunk con AST.

    Cubre los dos caminos (Python por ``ast``, el resto por tree-sitter): un chunk
    entra al índice en cuanto trae ``kind``, sin importar el lenguaje.
    """
    symbols = _PySymbols()
    for chunk in chunks:
        if chunk.kind is None:
            continue
        qualname = chunk.qualname or chunk.name
        if chunk.kind == ChunkKind.MODULE:
            if chunk.language == "python":
                symbols.aliases[chunk.file] = _python_import_aliases(chunk.code)
            continue
        if chunk.kind == ChunkKind.FUNCTION:
            symbols.functions[(chunk.file, chunk.name)] = chunk.id
        elif chunk.kind == ChunkKind.CLASS:
            symbols.classes[(chunk.file, qualname)] = chunk.id
            symbols.classes.setdefault((chunk.file, chunk.name), chunk.id)
        elif chunk.kind == ChunkKind.METHOD and "." in qualname:
            owner, method = qualname.rsplit(".", 1)
            symbols.methods[(chunk.file, owner, method)] = chunk.id
        # Solo los símbolos top-level compiten por el nombre desnudo a nivel
        # proyecto; los métodos se resuelven siempre vía su clase.
        if chunk.kind in (ChunkKind.FUNCTION, ChunkKind.CLASS) and "." not in qualname:
            key = (chunk.language, chunk.name)
            symbols.defs_by_name.setdefault(key, set()).add(chunk.id)

    _index_python_modules(chunks, symbols)
    return symbols


def _index_python_modules(chunks: list[CodeChunk], symbols: _PySymbols) -> None:
    """Mapea nombres de módulo (y sus sufijos) al archivo que los provee.

    Registra ``pkg/sub/mod.py`` como ``pkg.sub.mod``, ``sub.mod`` y ``mod``, para
    que resuelvan tanto ``import pkg.sub.mod`` como ``from pkg.sub import mod``.
    Si dos archivos reclaman el mismo nombre, se marca ambiguo (``""``) y ninguna
    llamada se liga por esa vía.
    """
    for file in {c.file for c in chunks if c.language == "python"}:
        dotted = _module_name(file)
        segments = dotted.split(".")
        for i in range(len(segments)):
            key = ".".join(segments[i:])
            current = symbols.file_of_module.get(key)
            if current is None:
                symbols.file_of_module[key] = file
            elif current != file:
                symbols.file_of_module[key] = ""  # ambiguo


def _module_name(file: str) -> str:
    """Nombre de módulo punteado de una ruta de archivo Python."""
    path = file[:-3] if file.endswith(".py") else file
    if path.endswith("/__init__"):
        path = path[: -len("/__init__")]
    return path.replace("/", ".")


def _build_ast_flow_edges(
    chunks: list[CodeChunk],
    facts: dict[str, _PyChunkFacts],
    symbols: _PySymbols,
) -> list[GraphEdge]:
    """Aristas resueltas por AST: ``calls`` + ``data_flow`` + ``control_flow``.

    Solo emite una arista cuando la llamada se resuelve con confianza razonable
    (ver :func:`_resolve_python_call` y :func:`_resolve_ts_call`); una llamada
    ambigua no produce arista.

    Args:
        chunks: Todos los chunks de la ingestión.
        facts: Llamadas por chunk, de :func:`_python_facts` / :func:`_ts_flow_facts`.
        symbols: Índice de símbolos del proyecto.

    Returns:
        Aristas fusionadas por ``(from, to, type)`` y sin auto-aristas.
    """
    builder = _EdgeBuilder()
    for chunk in chunks:
        chunk_facts = facts.get(chunk.id)
        if chunk_facts is None:
            continue
        owner = _owner_class(chunk)
        for call in chunk_facts.calls:
            if chunk.language == "python":
                target = _resolve_python_call(call.name, chunk.file, owner, symbols)
            else:
                target = _resolve_ts_call(
                    call.name, chunk.file, owner, chunk.language, symbols
                )
            if target is None or target == chunk.id:
                continue
            builder.add(chunk.id, target, EdgeType.CALLS)
            if call.data_vars:
                # El dato del caller entra al callee por argumento.
                builder.add(
                    chunk.id,
                    target,
                    EdgeType.DATA_FLOW,
                    data_vars=call.data_vars,
                    sanitized=call.sanitized,
                )
            if call.returns_to is not None:
                # Y vuelve: el valor de retorno del callee alimenta al caller.
                builder.add(
                    target, chunk.id, EdgeType.DATA_FLOW, data_vars=[call.returns_to]
                )
            if call.guards:
                builder.add(
                    chunk.id,
                    target,
                    EdgeType.CONTROL_FLOW,
                    condition=" & ".join(call.guards),
                )
    return builder.build()


class _EdgeBuilder:
    """Acumula aristas fusionando ``data_vars`` y condiciones por (from, to, type).

    Sin esto, dos llamadas al mismo callee con variables distintas colapsarían en
    la primera y se perdería la mitad del data flow.
    """

    def __init__(self) -> None:
        self._edges: dict[tuple[str, str, EdgeType], GraphEdge] = {}

    def add(
        self,
        source: str,
        target: str,
        edge_type: EdgeType,
        *,
        data_vars: list[str] | None = None,
        condition: str = "",
        sanitized: bool = False,
    ) -> None:
        """Agrega o fusiona una arista."""
        key = (source, target, edge_type)
        existing = self._edges.get(key)
        if existing is None:
            self._edges[key] = GraphEdge(
                from_=source,
                to=target,
                type=edge_type,
                data_vars=sorted(set(data_vars or [])),
                condition=condition,
                sanitized=sanitized,
            )
            return
        if data_vars:
            existing.data_vars = sorted({*existing.data_vars, *data_vars})
        if condition and condition not in existing.condition:
            # Dos call sites al mismo callee bajo guardas distintas: alcanza con una.
            existing.condition = (
                f"{existing.condition} | {condition}" if existing.condition else condition
            )
        # Una sola ruta sin sanitizar alcanza para que la arista NO sea sanitizada.
        existing.sanitized = existing.sanitized and sanitized

    def build(self) -> list[GraphEdge]:
        """Devuelve las aristas acumuladas."""
        return list(self._edges.values())


def _owner_class(chunk: CodeChunk) -> str | None:
    """Qualname de la clase que contiene al chunk, o ``None`` si no es un método."""
    if chunk.kind != ChunkKind.METHOD or not chunk.qualname:
        return None
    owner, _, _ = chunk.qualname.rpartition(".")
    return owner or None


def _resolve_python_call(
    raw: str, file: str, owner: str | None, symbols: _PySymbols
) -> str | None:
    """Resuelve una llamada Python al id del nodo invocado.

    Args:
        raw: Nombre punteado tal como está escrito (``sp.run``, ``self.execute``).
        file: Archivo donde ocurre la llamada.
        owner: Qualname de la clase contenedora, si la llamada está en un método.
        symbols: Índice de símbolos del proyecto.

    Returns:
        El id del nodo invocado, o ``None`` si no se puede resolver con confianza
        (llamada a stdlib/terceros, nombre ambiguo entre archivos, dispatch
        dinámico). ``None`` es la respuesta correcta ante la duda: una arista
        inventada le hace creer a M5 que existe un camino que no existe.
    """
    parts = raw.split(".")
    # self.foo() / cls.foo() → método de la misma clase.
    if len(parts) == 2 and parts[0] in ("self", "cls") and owner:
        return symbols.methods.get((file, owner, parts[1]))

    expanded = _expand_alias(raw, symbols.aliases.get(file, {})).split(".")
    if len(expanded) == 1:
        name = expanded[0]
        local = symbols.functions.get((file, name)) or symbols.classes.get((file, name))
        if local is not None:
            return local
        # Sin definición local ni import explícito: solo se liga si el nombre es
        # único en todo el proyecto. Si dos archivos lo definen, es ambiguo.
        candidates = symbols.defs_by_name.get(("python", name), set())
        return next(iter(candidates)) if len(candidates) == 1 else None

    symbol = expanded[-1]
    module = ".".join(expanded[:-1])
    target_file = symbols.file_of_module.get(module)
    if target_file:
        hit = symbols.functions.get((target_file, symbol)) or symbols.classes.get(
            (target_file, symbol)
        )
        if hit is not None:
            return hit
    # Clase.metodo() en el mismo archivo.
    return symbols.methods.get((file, module, symbol))


# --------------------------------------------------------------------------- #
# Ruta multi-lenguaje — resolución de llamadas y flujo por tree-sitter
# --------------------------------------------------------------------------- #
#: Nodos de llamada, relevados de las grammars reales (no inferidos): C/C++/Go/JS/TS/
#: Rust usan ``call_expression``, Java ``method_invocation``, PHP
#: ``function_call_expression``, Ruby ``call``, C# ``invocation_expression``.
_TS_CALL_KINDS = frozenset(
    {
        "call_expression",
        "call",
        "function_call_expression",
        "method_invocation",
        "invocation_expression",
        "method_call",
        "command",  # bash
        "macro_invocation",  # Rust
    }
)

#: Fragmentos de nombre de nodo que indican que lo de adentro está condicionado.
_TS_GUARD_MARKERS = (
    "if_statement",
    "if_expression",
    "if_modifier",
    "unless",
    "elsif",
    "else_clause",
    "while_statement",
    "while_expression",
    "for_statement",
    "for_expression",
    "switch_statement",
    "switch_expression",
    "case_statement",
    "when_clause",
    "try_statement",
    "catch_clause",
    "rescue",
    "conditional_expression",
    "ternary_expression",
    "guard_statement",  # Swift
)

#: Nodos que reciben el resultado de una llamada (data flow de vuelta al caller).
_TS_ASSIGN_KINDS = frozenset(
    {
        "assignment_expression",
        "assignment",
        "variable_declarator",
        "short_var_declaration",
        "let_declaration",
        "local_variable_declaration",
        "init_declarator",
        "return_statement",
    }
)

#: Separadores de nombre calificado según lenguaje (``a.b``, ``a::b``, ``a->b``).
_QUALIFIER_SPLIT = re.compile(r"::|->|\.")


def _ts_flow_facts(chunks: list[CodeChunk]) -> dict[str, _PyChunkFacts]:
    """Llamadas, guardas y data flow de los chunks no-Python, vía tree-sitter.

    Es la versión genérica y más gruesa de :func:`_python_facts`:

    - el data flow se aproxima por nombre — un parámetro de la función que aparece
      entre los argumentos de la llamada cuenta como dato que viaja;
    - no hay propagación por asignaciones intermedias ni sanitizadores (eso hoy
      solo existe en la ruta de Python);
    - las guardas sí se detectan igual de bien, por ancestro condicional.

    Args:
        chunks: Todos los chunks de la ingestión.

    Returns:
        ``{chunk_id: facts}`` para los chunks con grammar disponible que parsean.
    """
    facts: dict[str, _PyChunkFacts] = {}
    for chunk in chunks:
        if chunk.language == "python" or chunk.kind is None:
            continue
        ts_lang = ts_language_for(chunk.language)
        if ts_lang is None:
            continue
        # El chunk se parsea aislado, así que necesita el prefijo de apertura del
        # lenguaje cuando lo tiene (PHP sin '<?php' se lee como HTML).
        text = ts_chunk_prefix(chunk.language) + chunk.code
        root = ts_parse(text, ts_lang)
        if root is None:
            continue
        source = text.encode("utf-8")
        try:
            params = _ts_param_names(root, source)
            calls = _ts_collect_calls(root, source, params)
        except Exception as exc:  # noqa: BLE001 — grammar rara / árbol incompleto
            logger.debug("flujo tree-sitter falló en %s (%s)", chunk.id, exc)
            continue
        facts[chunk.id] = _PyChunkFacts(
            calls=calls, decorators=_ts_decorator_names(root, source)
        )
    return facts


def _ts_collect_calls(
    root: object, source: bytes, params: set[str]
) -> list[_PyCall]:
    """Recorre el árbol acumulando las llamadas con su contexto de flujo."""
    calls: list[_PyCall] = []

    def walk(node: object, guards: tuple[str, ...]) -> None:
        kind = _ts_kind(node)
        if kind in _TS_CALL_KINDS:
            name = _ts_callee_name(node, source)
            if name:
                arguments = _ts_argument_names(node, source)
                shared = sorted(arguments & params)
                calls.append(
                    _PyCall(
                        name=name,
                        resolved=name,
                        data_vars=shared,
                        guards=list(guards),
                        returns_to=_ts_result_target(node, source),
                    )
                )
        if kind.endswith(_TS_GUARD_MARKERS):
            guards = (*guards, _condition_text(_ts_condition_text(node, source, kind)))
        for child in _ts_children(node):
            walk(child, guards)

    walk(root, ())
    return calls


#: Nodos que contienen los argumentos de una llamada, no el invocado.
_TS_ARGUMENT_KINDS = ("argument", "call_suffix", "value_arguments")


def _ts_callee_name(node: object, source: bytes) -> str:
    """Nombre del invocado en un nodo de llamada.

    Primero por campo (``function``/``name``/``method``), que es como lo exponen
    C, Go, Java, PHP, Ruby, JS/TS, Rust y C#. Kotlin y Swift no exponen ninguno:
    ahí el invocado es el primer hijo nombrado y los argumentos van en un
    ``call_suffix`` aparte, así que se cae a ese fallback.
    """
    for field_name in ("function", "name", "method", "constructor"):
        target = _ts_field(node, field_name)
        if target is not None:
            return _ts_text(target, source).strip()
    for child in _ts_children(node):
        kind = _ts_kind(child)
        if any(marker in kind for marker in _TS_ARGUMENT_KINDS):
            continue
        text = _ts_text(child, source).strip()
        if text and (text[0].isalpha() or text[0] == "_"):
            return text
    return ""


def _ts_param_names(root: object, source: bytes) -> set[str]:
    """Identificadores de los parámetros de la definición del chunk.

    El campo ``parameters`` cubre C, Go, Java, PHP, Ruby, JS/TS, Rust y C#, pero no
    es universal: Kotlin usa un nodo ``function_value_parameters`` y Swift nodos
    ``parameter`` sueltos, ninguno expuesto como campo. Por eso se buscan además
    los nodos cuyo tipo menciona ``parameter``.

    Los nombres de tipo se excluyen: en ``(String c)`` o ``(amt: Int)`` el
    identificador del tipo no es un dato que viaje, y tomarlo generaría aristas
    ``data_flow`` inventadas.
    """
    names: set[str] = set()
    stack = [root]
    while stack:
        node = stack.pop()
        parameters = _ts_field(node, "parameters")
        if parameters is not None:
            names |= _ts_identifiers(parameters, source, skip_types=True)
            continue  # no se baja más: los params de defs anidadas no son de este scope
        if "parameter" in _ts_kind(node):
            names |= _ts_identifiers(node, source, skip_types=True)
            continue
        stack.extend(_ts_children(node))
    return names


def _ts_argument_names(node: object, source: bytes) -> set[str]:
    """Identificadores que aparecen en los argumentos de una llamada.

    Por campo cuando la grammar lo expone; si no, por el nodo hijo que contiene los
    argumentos (``call_suffix`` en Kotlin/Swift, ``value_arguments``).
    """
    for field_name in ("arguments", "argument_list"):
        arguments = _ts_field(node, field_name)
        if arguments is not None:
            return _ts_identifiers(arguments, source)
    names: set[str] = set()
    for child in _ts_children(node):
        if any(marker in _ts_kind(child) for marker in _TS_ARGUMENT_KINDS):
            names |= _ts_identifiers(child, source)
    return names


def _ts_identifiers(
    node: object, source: bytes, *, skip_types: bool = False
) -> set[str]:
    """Todos los identificadores bajo un nodo.

    Args:
        node: Nodo raíz de la búsqueda.
        source: Archivo en bytes.
        skip_types: Si ``True``, ignora los nodos de tipo (``type_identifier``,
            ``user_type``, ``primitive_type``). Necesario al leer parámetros: el
            nombre del tipo no es un dato que viaje.

    Returns:
        Los identificadores encontrados, sin el ``$`` de PHP.
    """
    found: set[str] = set()
    stack = [node]
    while stack:
        current = stack.pop()
        kind = _ts_kind(current)
        if skip_types and "type" in kind:
            continue
        if kind.endswith("identifier") or kind in ("name", "variable_name", "word"):
            found.add(_ts_text(current, source).lstrip("$"))
            continue
        stack.extend(_ts_children(current))
    return found


def _ts_result_target(node: object, source: bytes) -> str | None:
    """Nombre que recibe el resultado de la llamada, si se asigna o se retorna."""
    parent = getattr(node, "parent", None)
    resolved = parent() if callable(parent) else parent
    if resolved is None:
        return None
    kind = _ts_kind(resolved)
    if kind == "return_statement":
        return "<return>"
    if kind not in _TS_ASSIGN_KINDS:
        return None
    names = sorted(_ts_identifiers(resolved, source))
    return names[0] if names else None


def _ts_condition_text(node: object, source: bytes, kind: str) -> str:
    """Texto de la condición de un nodo de control, o su tipo si no lo expone."""
    for field_name in ("condition", "test"):
        condition = _ts_field(node, field_name)
        if condition is not None:
            return f"{kind.split('_')[0]} {_ts_text(condition, source)}"
    return kind.replace("_", " ")


def _ts_decorator_names(root: object, source: bytes) -> list[str]:
    """Anotaciones/atributos de la definición (``@GetMapping``, ``[HttpGet]``)."""
    names: list[str] = []
    for child in _ts_children(root):
        for node in (child, *_ts_children(child)):
            kind = _ts_kind(node)
            if "annotation" in kind or "attribute" in kind:
                text = _ts_text(node, source).strip()
                if text:
                    names.append(text.lstrip("@[").rstrip("]"))
    return names


def _ts_text(node: object, source: bytes) -> str:
    """Texto fuente de un nodo."""
    start, end = _ts_span(node)
    return source[start:end].decode("utf-8", errors="replace")


def _resolve_ts_call(
    raw: str, file: str, owner: str | None, language: str, symbols: _PySymbols
) -> str | None:
    """Resuelve una llamada no-Python al id del nodo invocado.

    Más gruesa que la de Python a propósito: se queda con el último segmento del
    nombre calificado (``exec.Command`` → ``Command``, ``Foo::bar`` → ``bar``) y
    resuelve primero en el archivo, después por unicidad en el proyecto. No modela
    imports ni alias por lenguaje, así que ante duda no liga.
    """
    segments = [part for part in _QUALIFIER_SPLIT.split(raw) if part]
    if not segments:
        return None
    symbol = segments[-1]

    if owner is not None:
        method = symbols.methods.get((file, owner, symbol))
        if method is not None:
            return method
    local = symbols.functions.get((file, symbol)) or symbols.classes.get((file, symbol))
    if local is not None:
        return local
    if len(segments) >= 2:
        # ``Clase.metodo()`` dentro del mismo archivo.
        method = symbols.methods.get((file, segments[-2], symbol))
        if method is not None:
            return method
    candidates = symbols.defs_by_name.get((language, symbol), set())
    return next(iter(candidates)) if len(candidates) == 1 else None


def _ast_matched_sinks(
    chunk: CodeChunk, facts: _PyChunkFacts, sink_patterns: list[str]
) -> list[str]:
    """Sinks del chunk, resueltos por AST cuando el patrón nombra una llamada.

    Un patrón que nombra una llamada (``os.system``, ``eval``, ``open(``) se
    compara **por segmentos** contra el nombre resuelto de las llamadas reales del
    chunk. Eso gana precisión en las dos direcciones:

    - encuentra lo que el substring no ve: ``sp.run(...)`` con patrón
      ``subprocess``, ``syscmd(...)`` con patrón ``os.system``;
    - descarta lo que el substring marcaba de más: ``exec`` ya no matchea
      ``self.execute(...)``, ``open(`` ya no matchea ``sp.Popen(...)``, y un
      ``import subprocess`` a secas ya no convierte al módulo en sink.

    Los patrones que no nombran una llamada (``request.``) siguen resolviéndose por
    substring sobre el texto.

    Esta poda solo se aplica cuando ``facts.precise_calls`` — o sea en la ruta de
    Python, donde el nombre de la llamada viene con el alias expandido. En la ruta
    tree-sitter se **suma** al substring en vez de reemplazarlo: sin expansión de
    alias, exigir match contra la llamada perdería sinks que no son llamadas (el
    ``tx.origin`` de Solidity es una lectura de atributo).
    """
    matched: list[str] = []
    for pattern in sink_patterns:
        core = _call_pattern_core(pattern)
        by_call = core is not None and any(
            _segments_match(core, name) for name in facts.resolved_calls
        )
        if by_call:
            matched.append(pattern)
        elif (core is None or not facts.precise_calls) and pattern in chunk.code:
            matched.append(pattern)
    return matched


def _call_pattern_core(pattern: str) -> str | None:
    """Nombre punteado de un patrón de sink que nombra una llamada.

    ``"open("`` → ``"open"``; ``"os.system"`` → ``"os.system"``; ``"request."`` →
    ``None`` (no es un nombre de llamada, se resuelve por substring).
    """
    core = pattern[:-1] if pattern.endswith("(") else pattern
    if core and all(segment.isidentifier() for segment in core.split(".")):
        return core
    return None


def _segments_match(pattern_core: str, resolved: str) -> bool:
    """``True`` si ``pattern_core`` aparece como run de segmentos en ``resolved``.

    ``"subprocess"`` matchea ``"subprocess.run"`` pero ``"exec"`` no matchea
    ``"self.execute"``: la comparación es por segmento completo, no por substring.
    """
    want = pattern_core.split(".")
    have = resolved.split(".")
    return any(
        have[i : i + len(want)] == want for i in range(len(have) - len(want) + 1)
    )


def _ast_is_entry_point(
    chunk: CodeChunk, facts: _PyChunkFacts, entry_patterns: list[str]
) -> bool:
    """Decide si el chunk es entry point usando el AST.

    Interpreta los patrones del lenguaje según su forma, en vez de buscarlos como
    substring en todo el chunk:

    - ``"def handle"`` → contra el nombre real del símbolo (prefijo), así un
      generador de código que menciona ``def handle`` en un string no cuenta.
    - ``"@app.route"`` → contra los decoradores reales del símbolo.
    - cualquier otro (``"request."``) → substring, como antes.
    """
    for pattern in entry_patterns:
        if pattern.startswith("def "):
            if chunk.name.startswith(pattern[4:]):
                return True
        elif pattern.startswith("@"):
            if any(d.startswith(pattern[1:]) for d in facts.decorators):
                return True
        elif pattern in chunk.code:
            return True
    return False


def _first_line(code: str) -> str:
    """Primera línea no vacía del código (aproxima la firma)."""
    for line in code.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:200]
    return ""

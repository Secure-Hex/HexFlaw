"""M4 — Static Analysis (CLAUDE.md §6 M4, §16 estrategias 1/2/4).

Mayor consumidor de tokens del pipeline. Aplica optimizaciones desde el día 1:
- Pre-filtrado keyword (capa 1, costo cero): descarta chunks sin ningún sink
  relevante al vuln_profile antes de gastar tokens.
- Batching: agrupa varios chunks por llamada al LLM.
- Delimitadores anti-prompt-injection vía :class:`LLMService` (T-M4-1).

El filtro por embeddings (capa 2) y el caché por hash de chunk quedan
enganchables; sus puntos de extensión están señalados.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterator
from typing import Any, Callable

from hexflaw.core.models import (
    CodeChunk,
    CodeGraph,
    EdgeType,
    Finding,
    FindingSet,
    FindingStatus,
    IngestionResult,
    TargetDefinition,
)
from hexflaw.infrastructure.analysis_cache import AnalysisCache
from hexflaw.infrastructure.logging import get_logger
from hexflaw.services.embedding.base import EmbeddingService
from hexflaw.services.language_service import LanguageService
from hexflaw.services.llm_service import (
    BudgetExceededError,
    LLMService,
    LLMServiceError,
)

logger = get_logger(__name__)

# Mapa de tipo de vuln → keywords/sinks indicativos (refuerza los del lenguaje).
# Cubre idioms multi-lenguaje (Python, PHP, C, Node/JS/TS, Go, Java) porque el
# filtro de capa 1 es substring case-insensitive: un keyword PHP/Python que no
# matchea Node colapsa el scope en codebases JS/TS (visto en Dockge).
_VULN_KEYWORDS: dict[str, tuple[str, ...]] = {
    "command_injection": (
        "system", "popen", "exec", "subprocess", "shell", "os.system",
        "spawn", "execfile", "execsync", "child_process", "proc_open",
        "pcntl_exec", "passthru", "shell_exec", "eval(", "pty",
    ),
    "sql_injection": (
        "execute", "query", "select", "cursor", "sql", "db_fetch", "db_execute",
        ".raw(", "knex", "prepare", "mysqli", "pg_query",
    ),
    "buffer_overflow": ("strcpy", "strcat", "sprintf", "gets", "memcpy"),
    "format_string": ("printf", "fprintf", "snprintf"),
    "path_traversal": (
        "open(", "fopen", "readfile", "writefile", "createreadstream",
        "sendfile", "unlink", "path.join", "fs.", "realpath", "../",
        "include", "require(", "file_get_contents", "move_uploaded",
    ),
    "deserialization": (
        "pickle", "yaml.load", "unserialize", "marshal", "node-serialize",
        "objectinputstream", "readobject", "json.parse",
    ),
    "ssrf": (
        "requests.get", "urlopen", "curl", "fetch(", "axios", ".get(",
        "request(", "openconnection", "httpurlconnection", "resttemplate",
        "webclient", "http.get", "got(",
    ),
    "xss": (
        "innerhtml", "v-html", "dangerouslysetinnerhtml", "document.write",
        "echo", "print(", "render", "html(", "|safe", "|raw",
    ),
}

_BATCH_SIZES = {"thorough": 5, "balanced": 10, "economy": 20}

#: En modo --exhaustive el prompt no se limita al vuln_profile: le pide al LLM que
#: busque CUALQUIER clase de vulnerabilidad (con ejemplos representativos para
#: anclar la cobertura, incluidas las 11 categorías del OWASP Benchmark).
_EXHAUSTIVE_VULNS = (
    "CUALQUIER clase de vulnerabilidad de seguridad, sin limitarte a una lista "
    "(ej.: command/SQL/LDAP/XPath injection, XSS, path traversal, weak crypto, "
    "weak hash, insecure randomness, insecure cookies, trust boundary violation, "
    "deserialization, SSRF, XXE, open redirect, buffer/integer overflow, etc.)"
)
#: Marcador de vuln_profile para la caché en modo exhaustive (separa sus entradas
#: de las corridas normales, que analizan menos clases sobre el mismo chunk).
_EXHAUSTIVE_CACHE_PROFILE = ["__exhaustive__"]

#: Umbral de similitud coseno para near-dup en M4. Un valor > 1.0 desactiva el
#: near-dup dedup (ningún par lo supera) — necesario en codebases con código
#: legítimamente repetido pero de distinto comportamiento de seguridad (endpoints
#: donde unos sanitizan y otros no, benchmarks tipo OWASP). El dedup exacto por
#: hash sigue activo siempre.
_DEDUP_THRESHOLD = 0.95

_FINDINGS_INSTRUCTION = (
    "Analiza el siguiente código en busca ÚNICAMENTE de estas clases de "
    "vulnerabilidad: {vulns}. Para cada función sospechosa devuelve un objeto. "
    "Responde SOLO con JSON válido, sin texto adicional, con esta forma:\n"
    '{{"findings": [{{"type": "<clase>", "file": "<archivo>", "line": <int>, '
    '"function": "<nombre>", "confidence": <0..1>, "snippet": "<línea vulnerable>", '
    '"rationale": "<breve>"}}]}}\n'
    "Si no hay vulnerabilidades, devuelve {{\"findings\": []}}.\n"
    "Cada chunk viene precedido por una cabecera '### FILE: <archivo> FUNC: <nombre>'."
)


def analyze(
    ingestion: IngestionResult,
    target: TargetDefinition,
    llm: LLMService,
    languages_service: LanguageService,
    *,
    mode: str = "balanced",
    model: str | None = None,
    embedding: EmbeddingService | None = None,
    cache: AnalysisCache | None = None,
    scope_query: str | None = None,
    scope_max_chunks: int = 200,
    scope_boost_paths: list[str] | None = None,
    near_dedup_threshold: float = _DEDUP_THRESHOLD,
    exhaustive: bool = False,
    graph: CodeGraph | None = None,
    sink_rescue_hops: int = 2,
    semantic_rescue_threshold: float = 0.22,
    semantic_rescue_max: int = 25,
    on_status: "Callable[[str], None] | None" = None,
    coverage: dict[str, Any] | None = None,
) -> FindingSet:
    """Ejecuta el análisis estático preliminar sobre el scope del target.

    Args:
        ingestion: Resultado de M1 (chunks).
        target: Resultado de M2 (vuln_profile y superficie de ataque).
        llm: Servicio LLM inyectado.
        languages_service: Para resolver sinks por lenguaje.
        mode: Modo de análisis (controla batch size y umbral de embeddings).
        model: Override de modelo para las llamadas.
        embedding: Backend de embeddings para los filtros por similitud (opcional).
        cache: Caché de análisis por hash de chunk (opcional).
        scope_query: Descripción del target. Si se provee junto con ``embedding``,
            acota el análisis a los chunks semánticamente más cercanos a esa
            funcionalidad (CLAUDE.md §6 M2: el target define el scope real).
        scope_max_chunks: Tope de chunks tras el scoping por target.
        graph: Code graph de M3. Si se provee, el prefiltro rescata los chunks que
            **alcanzan un sink por el grafo de llamadas** aunque no tengan ninguna
            keyword. Es lo que salva el patrón más común de falso negativo: el
            proyecto envuelve el sink en un helper propio, y la función que recibe
            el input del usuario no menciona ninguna keyword conocida.
        sink_rescue_hops: Saltos máximos hasta un sink para rescatar un chunk.
            0 desactiva el rescate.
        semantic_rescue_threshold: Similitud coseno mínima para rescatar un chunk
            que ninguna keyword vio. Alto a propósito: es el rescate más difuso.
        semantic_rescue_max: Tope duro de chunks rescatados por similitud. 0 lo
            desactiva.
        on_status: Callback opcional para reportar sub-fases (observabilidad CLI).

    Returns:
        :class:`FindingSet` con hallazgos preliminares (status=preliminary).
    """
    notify: Callable[[str], None] = on_status or (lambda _msg: None)
    chosen_model = model or llm.default_model
    # Modo exhaustive: se analiza TODO el codebase, sin filtro de sinks por keyword
    # (ni siquiera los chunks sin sink conocido se descartan) — máxima cobertura.
    if exhaustive:
        relevant = list(ingestion.chunks)
        logger.info("M4 exhaustive: %d chunks (sin prefiltro de sinks)", len(relevant))
    else:
        relevant = _prefilter(
            ingestion, target, languages_service, graph, sink_rescue_hops
        )
        # Última red: chunks que ninguna keyword vio y que tampoco llaman a un sink
        # conocido, pero que se PARECEN a uno. Va al final porque es el rescate más
        # difuso: sin una razón auditable, solo un score.
        kept_ids = {c.id for c in relevant}
        relevant += _semantic_rescue(
            [c for c in ingestion.chunks if c.id not in kept_ids],
            target,
            embedding,
            threshold=semantic_rescue_threshold,
            max_rescued=semantic_rescue_max,
        )
        logger.info(
            "M4 capa 1 (keyword): %d/%d chunks", len(relevant), len(ingestion.chunks)
        )
    # Los chunks bajo --path saltan el filtro keyword: la intención explícita del
    # usuario manda sobre la heurística de sinks (que no conoce wrappers propios
    # del proyecto, ej. gitcmd.NewCommand en vez de exec.Command).
    if scope_boost_paths:
        seen = {c.id for c in relevant}
        extra = [
            c
            for c in ingestion.chunks
            if c.id not in seen and any(p in c.file for p in scope_boost_paths)
        ]
        if extra:
            relevant = relevant + extra
            logger.info("M4: +%d chunks del path (bypass keyword filter)", len(extra))
    # Capa 2 — ranking semántico por embeddings (no umbral). Acota a los
    # scope_max_chunks más relevantes al target SIN descartar sinks que capa 1
    # ya identificó. Usar umbral aquí causaba falsos negativos (ocultaba vulns
    # reales); el ranking top-N preserva recall, que es lo que importa en SAST.
    if embedding is not None and not exhaustive:
        query = scope_query or " ".join(target.vuln_profile) or "security vulnerability"
        notify(f"M4 · ranking semántico (embeddings, {len(relevant)} chunks)")
        relevant = _scope_filter(
            relevant, query, embedding, scope_max_chunks, scope_boost_paths
        )
        logger.info("M4 ranking semántico: %d chunks", len(relevant))

    # Deduplicación (CLAUDE.md §15 T-M4-3, §16): nunca analizar el mismo código
    # dos veces. Exacta por hash (gratis) + near-dup por coseno > 0.95. Los chunks
    # bajo --path nunca se descartan (intención explícita del usuario).
    before_dedup = len(relevant)
    relevant = _dedup_chunks(
        relevant, embedding, keep_paths=scope_boost_paths, threshold=near_dedup_threshold
    )
    if coverage is not None:
        coverage["deduped"] = before_dedup - len(relevant)

    # Exhaustive: el prompt busca cualquier clase (no solo el vuln_profile) y la
    # caché usa un perfil marcador para no colisionar con corridas normales.
    prompt_vulns = _EXHAUSTIVE_VULNS if exhaustive else (
        ", ".join(target.vuln_profile) or "all"
    )
    cache_profile = _EXHAUSTIVE_CACHE_PROFILE if exhaustive else target.vuln_profile

    # Caché por hash de chunk: separa hits de los que requieren LLM (estrategia 3).
    findings: list[Finding] = []
    counter = 1
    to_analyze: list[CodeChunk] = []
    for chunk in relevant:
        cached = _cache_get(cache, chunk, chosen_model, cache_profile)
        if cached is not None:
            for raw in cached:
                findings.append(_to_finding(raw, counter, [chunk]))
                counter += 1
        else:
            to_analyze.append(chunk)

    batch_size = _BATCH_SIZES.get(mode, 10)
    total_batches = (len(to_analyze) + batch_size - 1) // batch_size
    if cache is not None and len(to_analyze) < len(relevant):
        logger.info("M4 caché: %d chunks reutilizados", len(relevant) - len(to_analyze))
    for batch_idx, batch in enumerate(_batches(to_analyze, batch_size), start=1):
        notify(f"M4 · análisis LLM · batch {batch_idx}/{total_batches}")
        prompt = _FINDINGS_INSTRUCTION.format(vulns=prompt_vulns)
        code_blob = "\n\n".join(
            f"### FILE: {c.file} FUNC: {c.name}\n{c.code}" for c in batch
        )
        try:
            response = llm.analyze_code(
                prompt,
                code_blob,
                model=chosen_model,
                trace_label=f"M4 · análisis batch {batch_idx}/{total_batches}",
            )
        except BudgetExceededError as exc:
            logger.warning("M4 detenido por budget: %s", exc)
            break  # no seguir gastando tokens
        except LLMServiceError as exc:
            logger.error("Fallo LLM en batch (se omite): %s", exc)
            continue

        raw_findings = _parse_findings(response.text)
        _cache_store(cache, batch, raw_findings, chosen_model, cache_profile)
        for raw in raw_findings:
            findings.append(_to_finding(raw, counter, batch))
            counter += 1

    if cache is not None:
        cache.flush()
        logger.info("M4 caché: %d hits", cache.hits)
    logger.info("M4 produjo %d hallazgos preliminares", len(findings))

    if coverage is not None:
        files_with_findings = {f.file for f in findings}
        coverage["scoped"] = len(relevant)
        coverage["analyzed_llm"] = len(to_analyze)
        coverage["from_cache"] = len(relevant) - len(to_analyze)
        if scope_boost_paths:
            path_chunks = [
                c for c in relevant if any(p in c.file for p in scope_boost_paths)
            ]
            # Funciones del path analizadas y sin hallazgos (auditadas → limpias).
            coverage["path_analyzed"] = [
                f"{c.file}::{c.name}" for c in path_chunks
            ]
            coverage["path_clean"] = [
                f"{c.file}::{c.name}"
                for c in path_chunks
                if c.file not in files_with_findings
            ]
    return FindingSet(project_id=ingestion.project_id, findings=findings)


#: Consulta semántica por clase de vulnerabilidad, expresada como **ejemplos de
#: código** y no como descripción en prosa.
#:
#: La diferencia no es estilística, está medida. Con descripciones en prosa la
#: separación entre código peligroso e inerte era de +0.007 (un ``formatear(nombre)``
#: inocente puntuaba 0.349 y una escritura de archivo 0.356 — indistinguibles). Con
#: ejemplos de código la separación sube a +0.150. El modelo de embeddings está
#: entrenado sobre código, así que comparar código contra código conserva mucha más
#: señal que comparar código contra una frase en español.
_VULN_QUERIES: dict[str, str] = {
    "command_injection": (
        "subprocess.run(cmd, shell=True)\n"
        "os.system(command)\n"
        "os.execv(path, args)\n"
        "Runtime.getRuntime().exec(cmd)"
    ),
    "sql_injection": (
        'cursor.execute("SELECT * FROM t WHERE x = " + value)\n'
        "statement.executeQuery(query)\n"
        "db.raw(sql)"
    ),
    "path_traversal": (
        'open(path, "w").write(data)\n'
        "shutil.copy(src, dst)\n"
        "os.remove(path)\n"
        "fs.readFile(filename)"
    ),
    "deserialization": (
        "pickle.loads(data)\nyaml.load(stream)\nObjectInputStream(input).readObject()"
    ),
    "ssrf": (
        "requests.get(url)\n"
        "urllib.request.urlopen(url)\n"
        "socket.connect((host, port))\n"
        "http.Get(endpoint)"
    ),
    "xss": (
        "element.innerHTML = value\n"
        "response.write(html)\n"
        "render_template_string(template)"
    ),
    "buffer_overflow": (
        "strcpy(dest, src);\nmemcpy(buf, data, len);\nsprintf(buf, fmt, arg);"
    ),
    "format_string": "printf(user_input);\nfprintf(f, fmt);\nsnprintf(b, n, fmt);",
}


def _semantic_rescue(
    dropped: list[CodeChunk],
    target: TargetDefinition,
    embedding: EmbeddingService | None,
    *,
    threshold: float,
    max_rescued: int,
) -> list[CodeChunk]:
    """Rescata chunks que ninguna keyword vio pero que *se parecen* a un sink.

    Es la última red del prefiltro, y cubre el hueco que las otras dos no pueden:
    un sink que no está en ningún catálogo, en un chunk que tampoco llama a nada
    catalogado. Ahí no hay keyword que matchee ni arista que seguir; lo único que
    queda es la semántica del código.

    A diferencia del rescate por grafo, este es **difuso**: no hay una razón
    auditable como "llama a run_cmd", solo un score de similitud. Por eso va
    último, con umbral alto y tope duro — se prefiere perder algún rescate a
    inundar el scope de chunks que solo se parecen de lejos.

    Args:
        dropped: Chunks descartados por las capas anteriores.
        target: Definición de M2 (de su ``vuln_profile`` sale la consulta).
        embedding: Backend de embeddings. Si es ``None``, no se rescata nada.
        threshold: Similitud coseno mínima para rescatar.
        max_rescued: Tope duro de chunks rescatados.

    Returns:
        Los chunks rescatados, de mayor a menor similitud.
    """
    if embedding is None or not dropped or max_rescued <= 0:
        return []
    queries = [_VULN_QUERIES[v] for v in target.vuln_profile if v in _VULN_QUERIES]
    if not queries:
        return []

    try:
        query_vecs = embedding.embed_batch(queries)
        chunk_vecs = embedding.embed_batch([c.code for c in dropped])
    except (RuntimeError, ValueError) as exc:
        logger.warning("Rescate semántico omitido (%s)", exc)
        return []

    scored: list[tuple[float, CodeChunk]] = []
    for chunk, vector in zip(dropped, chunk_vecs):
        # Se toma la mejor coincidencia entre las clases del perfil: un chunk que
        # se parece mucho a UNA de ellas alcanza para mirarlo.
        best = max(_cosine(query, vector) for query in query_vecs)
        if best >= threshold:
            scored.append((best, chunk))

    scored.sort(key=lambda pair: pair[0], reverse=True)
    rescued = [chunk for _, chunk in scored[:max_rescued]]
    if rescued:
        logger.info(
            "M4 capa 1: %d chunk(s) rescatados por similitud semántica "
            "(score >= %.2f, tope %d): %s",
            len(rescued),
            threshold,
            max_rescued,
            ", ".join(f"{c.file}::{c.name}" for c in rescued[:5])
            + (" …" if len(rescued) > 5 else ""),
        )
    return rescued


def _scope_filter(
    chunks: list[CodeChunk],
    scope_query: str,
    embedding: EmbeddingService,
    max_chunks: int,
    boost_paths: list[str] | None = None,
    path_boost: float = 1.0,
) -> list[CodeChunk]:
    """Acota los chunks a la funcionalidad del target por ranking de similitud.

    Embebe la descripción del target y conserva los ``max_chunks`` chunks con
    mayor score (ranking, no umbral absoluto — robusto entre modelos).

    ``boost_paths`` actúa como un *plus*, no como filtro duro: los chunks cuyo
    archivo coincide con alguno de esos paths reciben un bonus al score, así
    suben al tope — pero los chunks que el propio sistema considera muy
    relevantes (alta similitud semántica) fuera del path siguen entrando si
    queda capacidad. El usuario apunta sin perder lo que el sistema detecta.

    Args:
        chunks: Chunks supervivientes de capa 1.
        scope_query: Descripción del target.
        embedding: Backend de embeddings.
        max_chunks: Cantidad máxima de chunks a conservar.
        boost_paths: Substrings de ruta a priorizar (de ``--path``).
        path_boost: Bonus de score sumado a los chunks que coinciden con un path.

    Returns:
        Los chunks mejor rankeados (a lo sumo ``max_chunks``).
    """
    boost_paths = boost_paths or []
    if len(chunks) <= max_chunks and not boost_paths:
        return chunks
    try:
        query_vec = embedding.embed(scope_query)
        chunk_vecs = embedding.embed_batch([c.code for c in chunks])
    except (RuntimeError, ValueError) as exc:
        logger.warning("Scoping por target omitido (%s)", exc)
        return chunks

    def score(chunk: CodeChunk, vec: list[float]) -> float:
        base = _cosine(query_vec, vec)
        if boost_paths and any(p in chunk.file for p in boost_paths):
            return base + path_boost  # plus por coincidir con el path apuntado
        return base

    scored = sorted(
        zip(chunks, chunk_vecs), key=lambda pair: score(*pair), reverse=True
    )
    kept = [chunk for chunk, _ in scored[:max_chunks]]
    if boost_paths:
        matched = sum(1 for c in kept if any(p in c.file for p in boost_paths))
        logger.info(
            "M4 scope: %d/%d chunks del path apuntado (resto: picks del sistema)",
            matched,
            len(kept),
        )
    return kept


def _dedup_chunks(
    chunks: list[CodeChunk],
    embedding: EmbeddingService | None,
    *,
    keep_paths: list[str] | None = None,
    threshold: float = _DEDUP_THRESHOLD,
) -> list[CodeChunk]:
    """Elimina chunks duplicados/near-duplicados antes del LLM (T-M4-3, §16).

    Dos capas: (1) dedup exacta por hash de chunk (costo cero); (2) near-dup por
    similitud coseno > ``threshold`` (solo si hay backend de embeddings). Los
    chunks cuyo archivo coincide con ``keep_paths`` (``--path``) nunca se
    descartan. No hay truncación silenciosa: lo eliminado se loguea.

    Args:
        chunks: Chunks candidatos (post-scope).
        embedding: Backend de embeddings, o ``None`` (solo dedup exacta).
        keep_paths: Substrings de ruta que nunca se deduplican.
        threshold: Umbral coseno para near-dup.

    Returns:
        Los chunks únicos, preservando el orden de entrada.
    """
    keep_paths = keep_paths or []

    def is_protected(chunk: CodeChunk) -> bool:
        return any(p in chunk.file for p in keep_paths)

    # Capa 1 — dedup exacta por hash (gratis). Protegidos siempre pasan.
    seen_hashes: set[str] = set()
    unique: list[CodeChunk] = []
    for chunk in chunks:
        if not is_protected(chunk) and chunk.hash in seen_hashes:
            continue
        seen_hashes.add(chunk.hash)
        unique.append(chunk)
    exact_dropped = len(chunks) - len(unique)

    # Capa 2 — near-dup por coseno (requiere embeddings).
    if embedding is None or len(unique) < 2:
        if exact_dropped:
            logger.info("M4 dedup: -%d chunks idénticos (hash)", exact_dropped)
        return unique

    try:
        vecs = embedding.embed_batch([c.code for c in unique])
    except (RuntimeError, ValueError) as exc:
        logger.warning("Dedup near-dup omitida (%s)", exc)
        return unique

    kept: list[CodeChunk] = []
    kept_vecs: list[list[float]] = []
    near_dropped = 0
    for chunk, vec in zip(unique, vecs):
        if not is_protected(chunk) and any(
            _cosine(vec, kv) > threshold for kv in kept_vecs
        ):
            near_dropped += 1
            continue
        kept.append(chunk)
        kept_vecs.append(vec)

    if exact_dropped or near_dropped:
        logger.info(
            "M4 dedup: -%d idénticos (hash), -%d near-dup (coseno>%.2f); %d → %d",
            exact_dropped, near_dropped, threshold, len(chunks), len(kept),
        )
    return kept


def _cache_get(
    cache: AnalysisCache | None, chunk: CodeChunk, model: str, vuln_profile: list[str]
) -> list[dict[str, Any]] | None:
    """Recupera findings cacheados para un chunk, si hay caché."""
    if cache is None:
        return None
    return cache.get(AnalysisCache.make_key(chunk.hash, model, vuln_profile))


def _cache_store(
    cache: AnalysisCache | None,
    batch: list[CodeChunk],
    raw_findings: list[dict[str, Any]],
    model: str,
    vuln_profile: list[str],
) -> None:
    """Atribuye cada finding a su chunk (por archivo + línea) y lo cachea.

    Cada chunk del batch obtiene una entrada de caché (lista vacía si no tuvo
    findings), de modo que un hit posterior reproduzca exactamente el resultado.
    """
    if cache is None:
        return
    attributed: dict[str, list[dict[str, Any]]] = {c.id: [] for c in batch}
    for raw in raw_findings:
        chunk = _attribute_chunk(raw, batch)
        if chunk is not None:
            attributed[chunk.id].append(raw)
    for chunk in batch:
        key = AnalysisCache.make_key(chunk.hash, model, vuln_profile)
        cache.set(key, attributed[chunk.id])


def _attribute_chunk(raw: dict[str, Any], batch: list[CodeChunk]) -> CodeChunk | None:
    """Encuentra el chunk del batch al que pertenece un finding del LLM."""
    file = str(raw.get("file", ""))
    try:
        line = int(raw.get("line", 0))
    except (TypeError, ValueError):
        line = 0
    same_file = [c for c in batch if c.file == file]
    for chunk in same_file:
        if chunk.line_start <= line <= chunk.line_end:
            return chunk
    if same_file:
        return same_file[0]
    return batch[0] if batch else None


def _cosine(a: list[float], b: list[float]) -> float:
    """Similitud coseno entre dos vectores (0 si alguno es nulo)."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


def _profile_keywords(
    target: TargetDefinition,
    languages_service: LanguageService,
    ingestion_langs: list[str] | None,
) -> set[str]:
    """Reúne keywords/sinks indicativos del vuln_profile y los lenguajes.

    Args:
        target: Definición de target (vuln_profile).
        languages_service: Para resolver sink_patterns por lenguaje.
        ingestion_langs: Lenguajes presentes; ``None`` usa los del target.

    Returns:
        Conjunto de keywords en minúsculas.
    """
    keywords: set[str] = set()
    for vuln in target.vuln_profile:
        keywords.update(_VULN_KEYWORDS.get(vuln, ()))
    langs = ingestion_langs if ingestion_langs is not None else []
    for lang_id in langs:
        definition = languages_service.get(lang_id)
        if definition:
            keywords.update(definition.sink_patterns)
    return {k.lower() for k in keywords}


def _prefilter(
    ingestion: IngestionResult,
    target: TargetDefinition,
    languages_service: LanguageService,
    graph: CodeGraph | None = None,
    sink_rescue_hops: int = 2,
    semantic_rescue_threshold: float = 0.22,
    semantic_rescue_max: int = 25,
) -> list[CodeChunk]:
    """Capa 1 — filtro keyword (costo cero) sobre el vuln_profile activo.

    Mantiene solo chunks que contienen al menos un sink/keyword indicativo de
    alguna vuln del perfil. Esto es lo que evita gastar tokens en código inerte.
    """
    keywords = _profile_keywords(target, languages_service, ingestion.languages)
    if not keywords:
        return list(ingestion.chunks)  # sin perfil: no filtramos

    # Fail-open por-lenguaje: un lenguaje SIN sink_patterns curados no tiene
    # cobertura de keywords confiable; filtrarlo arriesga falsos negativos
    # silenciosos (idioms desconocidos). Para esos lenguajes NO filtramos —
    # se analizan todos sus chunks. Mejor pagar tokens que perder una vuln.
    uncovered: set[str] = set()
    for lang in ingestion.languages:
        definition = languages_service.get(lang)
        if definition is None or not definition.sink_patterns:
            uncovered.add(lang)
    if uncovered:
        logger.warning(
            "Lenguajes sin sink_patterns curados (fail-open, se analizan completos): "
            "%s. Generá sinks con 'hexflaw languages learn <lang>' para filtrar y "
            "ahorrar tokens.",
            ", ".join(sorted(uncovered)),
        )

    by_keyword = [
        chunk
        for chunk in ingestion.chunks
        if chunk.language in uncovered
        or any(k in chunk.code.lower() for k in keywords)
    ]
    if graph is None or sink_rescue_hops <= 0:
        return by_keyword

    kept = {chunk.id for chunk in by_keyword}
    reaching = _nodes_reaching_sink(graph, sink_rescue_hops)
    rescued = [c for c in ingestion.chunks if c.id not in kept and c.id in reaching]
    if rescued:
        logger.info(
            "M4 capa 1: %d chunk(s) rescatados por el grafo (alcanzan un sink en "
            "<=%d salto(s) sin tener keywords): %s",
            len(rescued),
            sink_rescue_hops,
            ", ".join(f"{c.file}::{c.name}" for c in rescued[:5])
            + (" …" if len(rescued) > 5 else ""),
        )
    return by_keyword + rescued


def _nodes_reaching_sink(graph: CodeGraph, hops: int) -> set[str]:
    """Ids que alcanzan algún nodo sink en ``hops`` saltos o menos.

    Se resuelve con **un BFS inverso desde los sinks** sobre las aristas ``calls``
    invertidas: O(V+E) una sola vez, en vez de un recorrido por chunk. Los sinks
    mismos quedan incluidos, pero ya los retiene el filtro por keyword.

    Solo se siguen aristas ``calls``, porque la relación que responde "quién puede
    alimentar este sink" es la de llamada. Las ``data_flow`` hacia adelante
    duplican a las ``calls`` y las de retorno apuntan al revés; medido, incluirlas
    no cambia el conjunto resultante, así que se usa la relación más simple.
    """
    callers: dict[str, list[str]] = {}
    for edge in graph.edges:
        if edge.type == EdgeType.CALLS:
            callers.setdefault(edge.to, []).append(edge.from_)

    frontier = {s.node_id for s in graph.sinks}
    reaching = set(frontier)
    for _ in range(hops):
        nxt = {
            caller
            for node in frontier
            for caller in callers.get(node, [])
            if caller not in reaching
        }
        if not nxt:
            break
        reaching |= nxt
        frontier = nxt
    return reaching


def _batches(items: list[CodeChunk], size: int) -> Iterator[list[CodeChunk]]:
    """Particiona ``items`` en lotes de tamaño ``size``."""
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _parse_findings(text: str) -> list[dict[str, Any]]:
    """Extrae el array de findings de la respuesta del LLM de forma robusta.

    Tolera que el modelo envuelva el JSON en fences o agregue texto alrededor.

    Args:
        text: Respuesta cruda del LLM.

    Returns:
        Lista de dicts de findings (vacía si no se puede parsear).
    """
    candidate = _extract_json_object(text)
    if candidate is None:
        logger.warning("Respuesta LLM sin JSON parseable; 0 findings de este batch")
        return []
    try:
        data = json.loads(candidate)
    except json.JSONDecodeError as exc:
        logger.warning("JSON de findings inválido: %s", exc)
        return []
    findings = data.get("findings", []) if isinstance(data, dict) else []
    return [f for f in findings if isinstance(f, dict)]


def _extract_json_object(text: str) -> str | None:
    """Devuelve el primer objeto JSON balanceado encontrado en ``text``."""
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence:
        return fence.group(1)
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _to_finding(raw: dict[str, Any], index: int, batch: list[CodeChunk]) -> Finding:
    """Convierte un dict crudo del LLM en un :class:`Finding` validado.

    Completa ``file``/``function`` desde el batch si el modelo los omitió o
    alucinó, anclando el hallazgo a un chunk real cuando es posible.
    """
    file = str(raw.get("file", "")) or (batch[0].file if batch else "")
    function = raw.get("function")
    line = raw.get("line", 0)
    try:
        line = int(line)
    except (TypeError, ValueError):
        line = 0
    confidence = raw.get("confidence", 0.0)
    try:
        confidence = max(0.0, min(1.0, float(confidence)))
    except (TypeError, ValueError):
        confidence = 0.0

    return Finding(
        id=f"F{index:03d}",
        type=str(raw.get("type", "unknown")),
        file=file,
        line=line,
        function=str(function) if function else None,
        confidence=confidence,
        snippet=str(raw.get("snippet", ""))[:500],
        status=FindingStatus.PRELIMINARY,
        rationale=str(raw.get("rationale", ""))[:500],
    )

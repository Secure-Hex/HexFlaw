"""Pipeline Orchestrator (CLAUDE.md §4, §14).

Construye los servicios a partir de la configuración resuelta e inyecta los
backends en los módulos. Es el único lugar que instancia backends concretos —
los módulos los reciben ya construidos y permanecen agnósticos.

Agnóstico a la interfaz: la CLI y la futura Web API lo invocan igual.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hexflaw.core.model_policy import Task, choose_model
from hexflaw.core.models import (
    AnalysisMode,
    CodeGraph,
    Finding,
    FindingSet,
    IngestionResult,
    RootCause,
    TargetDefinition,
)
from hexflaw.core.project import Project
from hexflaw.infrastructure import runs, storage
from hexflaw.infrastructure.analysis_cache import AnalysisCache
from hexflaw.infrastructure.config import Config
from hexflaw.infrastructure.logging import get_logger
from hexflaw.modules import (
    m1_ingestion,
    m2_target,
    m3_graph,
    m4_static,
    m5_taint,
    m5b_variants,
    m6a_rootcause,
    m6b_report,
    m6c_poc,
    source_resolver,
)
from hexflaw.services import framework_service, sink_learner
from hexflaw.services.embedding import EmbeddingService, get_embedding_service
from hexflaw.services.embedding.caching import CachingEmbeddingService
from hexflaw.services.graph_service import GraphService
from hexflaw.services.language_service import LanguageService
from hexflaw.services.llm_service import build_llm_service

logger = get_logger(__name__)


def _merge_variants(base: FindingSet, variants: FindingSet) -> FindingSet:
    """Fusiona las variantes de M5b, descartando duplicados de M4/M5.

    Una variante se descarta si su ``(file, line, type)`` ya existe en ``base``
    (M4 ya lo había encontrado por su cuenta), para no duplicar hallazgos.
    """
    if not variants.findings:
        return base
    known = {(f.file, f.line, f.type) for f in base.findings}
    fresh = [
        v for v in variants.findings if (v.file, v.line, v.type) not in known
    ]
    if len(fresh) < len(variants.findings):
        logger.info(
            "M5b: %d variante(s) ya cubiertas por M4/M5, descartadas",
            len(variants.findings) - len(fresh),
        )
    base.findings.extend(fresh)
    return base


class Orchestrator:
    """Coordina el pipeline para un proyecto y configuración dados."""

    def __init__(self, project: Project, config: Config) -> None:
        """Inicializa el orchestrator y construye los servicios.

        Args:
            project: Proyecto activo (raíz + metadata).
            config: Configuración efectiva ya resuelta por la jerarquía.
        """
        self.project = project
        self.config = config
        # Observabilidad en vivo: timeline de fases con su duración, fase actual
        # (con inicio monotónico para calcular elapsed) y detalle de sub-fase.
        self._timeline: list[tuple[str, float]] = []
        self._phase = ""
        self._phase_start = time.monotonic()
        self._detail = ""
        #: Cobertura del último M4 (chunks en scope, analizados, del path, limpios).
        self.last_coverage: dict[str, Any] = {}
        #: ID del último run de análisis archivado.
        self.last_run_id: str | None = None
        #: TargetDefinition del último run (modo M2 + target confirmado), para que
        #: la capa de presentación muestre en qué modo trabajó M2 y qué se analizó.
        self.last_target: TargetDefinition | None = None
        #: Frameworks detectados en el último run (Flask, Spring, Rails, ...).
        self.last_frameworks: list[framework_service.FrameworkDefinition] = []
        self.languages = LanguageService()
        self.graphs = GraphService(project.hexflaw_dir)
        self.llm = build_llm_service(config)

    def _begin_phase(self, name: str) -> None:
        """Cierra la fase actual (registrando su duración) e inicia ``name``."""
        now = time.monotonic()
        if self._phase:
            self._timeline.append((self._phase, now - self._phase_start))
        self._phase = name
        self._phase_start = now
        self._detail = ""

    def _set_detail(self, message: str) -> None:
        """Callback de sub-fase: actualiza el detalle sin reiniciar el cronómetro."""
        self._detail = message

    # --- accesores de observabilidad leídos por el panel en vivo de la CLI ---
    @property
    def current_phase(self) -> str:
        """Nombre de la fase en curso."""
        return self._phase

    @property
    def current_elapsed(self) -> float:
        """Segundos transcurridos en la fase actual."""
        return time.monotonic() - self._phase_start

    @property
    def detail(self) -> str:
        """Detalle de la sub-fase en curso (texto libre)."""
        return self._detail

    def timeline(self) -> list[tuple[str, float]]:
        """Fases ya completadas con su duración en segundos."""
        return list(self._timeline)

    def _embedding(self) -> EmbeddingService:
        """Resuelve e instancia el backend de embeddings según config."""
        backend = self.config.get("embedding_backend", "local-cpu")
        return get_embedding_service(backend, self.config.values)

    def _embedding_safe(self) -> EmbeddingService | None:
        """Como :meth:`_embedding` pero devuelve ``None`` si no se puede construir.

        El filtro capa 2 es una optimización opcional: si el backend configurado
        no se puede instanciar (ej. falta API key), se omite sin abortar M4.
        """
        try:
            return self._embedding()
        except ValueError as exc:
            logger.warning("Filtro por embeddings deshabilitado: %s", exc)
            return None

    def _embedding_cached(self) -> EmbeddingService | None:
        """Backend de embeddings envuelto en caché de vectores por hash de chunk."""
        inner = self._embedding_safe()
        if inner is None:
            return None
        return CachingEmbeddingService(
            inner, self.project.hexflaw_dir / "cache" / "embedding_cache.json"
        )

    def run_ingest(
        self, source_path: Path | str, *, incremental: bool = False
    ) -> IngestionResult:
        """Ejecuta M1 — Ingestion y persiste sus artefactos.

        Args:
            source_path: Directorio, ``.zip``, URL git o URL http(s) a ingerir.
                Las fuentes no-directorio se materializan en un sandbox temporal
                seguro (zip-slip/symlink/hooks safe) que se elimina al terminar.
            incremental: Si ``True``, reutiliza chunks de archivos sin cambios.

        Returns:
            El resultado de la ingestión.
        """
        self._begin_phase("M1 · ingestion")
        # Cargar el índice previo SIEMPRE (no solo en incremental): permite tanto
        # acumular (incremental) como detectar/avisar archivos que se caen del
        # índice cuando se reingresa un sub-path (footgun de pérdida silenciosa).
        prior = self._load_ingestion_optional()
        with self._ingest_lock(), source_resolver.resolved_source(source_path) as local_dir:
            # Para fuentes materializadas (zip/git/url) el sandbox temporal es la
            # raíz: los paths quedan relativos a su estructura interna, estable
            # entre ingests. Para un directorio local seguimos usando project.root.
            is_local_dir = Path(str(source_path)).expanduser() == local_dir
            result = m1_ingestion.ingest(
                local_dir,
                self.project.metadata.project_id,
                self.languages,
                max_file_bytes=self.config.get("max_file_bytes", 10 * 1024 * 1024),
                max_project_bytes=self.config.get(
                    "max_project_bytes", 2 * 1024 * 1024 * 1024
                ),
                prior=prior,
                project_root=self.project.root if is_local_dir else None,
                incremental=incremental,
            )
            self._persist_ingestion(result)
            self._update_metadata_from_ingestion(result)
        return result

    @contextmanager
    def _ingest_lock(self) -> Iterator[None]:
        """Lock file durante la ingestión (CLAUDE.md §15, T-INFRA-4)."""
        lock = self.project.hexflaw_dir / "ingest.lock"
        if lock.exists():
            logger.warning(
                "Existe %s: posible ingest en curso o interrumpido previamente.", lock
            )
        storage.ensure_dir(self.project.hexflaw_dir)
        lock.write_text("locked", encoding="utf-8")
        try:
            yield
        finally:
            lock.unlink(missing_ok=True)

    def run_pipeline(
        self, source_path: Path | str, target_text: str | None, *, report_format: str = "markdown"
    ) -> dict[str, object]:
        """Pipeline completo: ingest → analyze → report + poc (comando ``run``).

        Args:
            source_path: Directorio, ``.zip``, URL git o URL http(s) a analizar.
            target_text: Funcionalidad a analizar, o ``None`` para discovery.
            report_format: Formato de reporte final.

        Returns:
            Mapa con ``findings`` y las rutas de outputs.
        """
        self.run_ingest(source_path)
        findings = self.run_analyze(target_text)
        outputs = self.run_output(
            do_report=True, do_poc=True, report_format=report_format
        )
        return {"findings": findings, **outputs}

    def run_analyze(
        self, target_text: str | None, *, boost_paths: list[str] | None = None
    ) -> FindingSet:
        """Ejecuta M2 → M5 sobre la ingestión persistida.

        Args:
            target_text: Funcionalidad a analizar (directed) o ``None`` (discovery).
            boost_paths: Substrings de ruta a priorizar en el scope (``--path``).
                Es un *plus*, no un filtro duro: prioriza esos paths sin descartar
                lo que el sistema detecte como relevante fuera de ellos.

        Returns:
            El conjunto de hallazgos confirmados, ya persistido.

        Raises:
            FileNotFoundError: Si no existe artefacto de ingestión previo.
        """
        ingestion = self._load_ingestion()
        mode_str = self.config.get("analysis_mode", "balanced")
        mode = AnalysisMode(mode_str)
        # Modo exhaustive (--exhaustive): analiza TODO el codebase sin recortes
        # (sin prefiltro de sinks, sin límite de scope, sin dedup near) y con Opus
        # en todas las tareas. Máxima cobertura y capacidad, sin importar el costo.
        exhaustive = self.config.get("exhaustive", False)
        concurrency = int(self.config.get("llm_concurrency", 1) or 1)

        # Run ID al inicio: su slug prefija los IDs de findings para que sean únicos
        # entre runs (buscables cross-run), y el run en vivo muestra el mismo ID que
        # luego queda archivado.
        run_id = runs.new_run_id()
        run_slug = run_id.rsplit("-", 1)[-1]
        self.last_run_id = run_id

        # M2 — Target Definition: discovery si no se especificó target, si no directed.
        if target_text:
            self._begin_phase("M2 · target (directed)")
            target = m2_target.define_target_directed(
                target_text, ingestion, self.languages
            )
        else:
            self._begin_phase("M2 · target (discovery)")
            target = m2_target.define_target_discovery(
                ingestion,
                self.llm,
                self.languages,
                model=choose_model(Task.TARGET_DISCOVERY, mode, exhaustive=exhaustive),
            )

        # Exponer a la capa de presentación en qué modo trabajó M2 y qué target
        # quedó (el del usuario en directed; el que descubrió el modelo en discovery).
        self.last_target = target
        self._set_detail(
            f"M2 {target.mode}: {target.target_confirmed}"
        )

        # M3 — Code Graph (caché por hash del codebase; se regenera si cambió).
        # Aprendizaje automático de sinks, ANTES de M3: los sinks los usan tanto el
        # grafo (marcar nodos) como el prefiltro de M4. Solo corre para lenguajes sin
        # cobertura curada, que son los que hoy hacen fail-open y se analizan enteros.
        if self.config.get("auto_learn_sinks", True):
            overlay = sink_learner.auto_learn(
                ingestion,
                self.llm,
                self.languages,
                self.project.hexflaw_dir,
                model=choose_model(Task.STATIC_SIMPLE, mode, exhaustive=exhaustive),
            )
            if overlay:
                self.languages.apply_overlay(overlay)

        # Framework awareness — ANTES de M3, por el mismo motivo que el auto-learn:
        # sus patrones deciden qué nodo es entry point y cuál es sink. Saber que el
        # repo es Django convierte un `def get(self, request)` de método cualquiera
        # en la puerta por la que entra el atacante.
        self.last_frameworks = framework_service.detect(ingestion.chunks)
        if self.last_frameworks:
            fw_sinks, fw_entries = framework_service.overlays(self.last_frameworks)
            self.languages.apply_overlay(fw_sinks, fw_entries)
            self._set_detail(
                "Frameworks: " + ", ".join(f.name for f in self.last_frameworks)
            )

        self._begin_phase("M3 · code graph")
        graph = self._build_or_load_graph(ingestion)

        # M4 — Static Analysis (capa 1+2 + caché por chunk + caché de embeddings).
        # Corre bajo una reserva de budget para no agotar el techo y dejar a M5 sin
        # presupuesto para confirmar (si M4 consume todo, los findings quedan en
        # needs_review y el run no produce nada accionable).
        self._begin_phase("M4 · static analysis")
        embedding = self._embedding_cached()
        self.last_coverage = {}
        with self.llm.reserve_budget(self.config.get("m5_budget_reserve", 0.30)):
            preliminary = m4_static.analyze(
                ingestion,
                target,
                self.llm,
                self.languages,
                mode=mode_str,
                model=choose_model(Task.STATIC_SIMPLE, mode, exhaustive=exhaustive),
                concurrency=concurrency,
                embedding=embedding,
                cache=AnalysisCache(self.project.hexflaw_dir),
                scope_query=target.target_confirmed,
                scope_max_chunks=self.config.get("scope_max_chunks", 200),
                scope_boost_paths=boost_paths,
                near_dedup_threshold=self.config.get("m4_near_dedup_threshold", 0.95),
                exhaustive=exhaustive,
                # M3 ya corrió: el grafo permite rescatar del prefiltro los chunks
                # que llaman a un sink sin mencionar ninguna keyword.
                graph=graph,
                sink_rescue_hops=self.config.get("m4_sink_rescue_hops", 2),
                semantic_rescue_threshold=self.config.get(
                    "m4_semantic_rescue_threshold", 0.22
                ),
                semantic_rescue_max=self.config.get("m4_semantic_rescue_max", 25),
                semantic_rescue_fraction=self.config.get(
                    "m4_semantic_rescue_fraction", 0.10
                ),
                on_status=self._set_detail,
                coverage=self.last_coverage,
            )
        if isinstance(embedding, CachingEmbeddingService):
            embedding.flush()

        # M5 — Taint Tracing + Confirmation.
        self._begin_phase("M5 · taint + confirmation")
        findings = m5_taint.confirm(
            preliminary,
            graph,
            ingestion,
            self.llm,
            model=choose_model(Task.TAINT, mode, exhaustive=exhaustive),
            concurrency=concurrency,
            on_status=self._set_detail,
        )

        # M5b — Variant hunting: usa los confirmados de M5 como semilla y caza
        # sus vecinos en el espacio de embeddings, re-analizándolos aunque el
        # scope de M4 los hubiera descartado. Off en economy (ahorra tokens).
        # Con --exhaustive, M4 ya analizó TODOS los chunks del codebase: los vecinos
        # que M5b cazaría ya fueron cubiertos, así que solo re-pagaría Opus sobre
        # código ya analizado. Se apaga con log explícito, no en silencio.
        if exhaustive and self.config.get("variant_hunting", True):
            logger.info(
                "M5b omitido: --exhaustive ya analizó el codebase completo, "
                "cazar variantes solo re-pagaría los mismos chunks"
            )
        if (
            self.config.get("variant_hunting", True)
            and not exhaustive
            and mode != AnalysisMode.ECONOMY
            and embedding is not None
        ):
            self._begin_phase("M5b · variant hunting")
            variants = m5b_variants.hunt_variants(
                findings,
                ingestion,
                target,
                graph,
                embedding,
                self.llm,
                self.languages,
                AnalysisCache(self.project.hexflaw_dir),
                static_model=choose_model(Task.STATIC_SIMPLE, mode, exhaustive=exhaustive),
                taint_model=choose_model(Task.TAINT, mode, exhaustive=exhaustive),
                mode=mode_str,
                top_k=self.config.get("variant_top_k", 10),
                min_similarity=self.config.get("variant_min_similarity", 0.78),
                max_variants_total=self.config.get("variant_max_total", 50),
                max_rounds=self.config.get("variant_max_rounds", 5),
                exhaustive=exhaustive,
                on_status=self._set_detail,
            )
            findings = _merge_variants(findings, variants)
        self._begin_phase("done")

        # IDs únicos cross-run: prefijar con el slug del run para que no colisionen
        # entre análisis y se puedan buscar en todos los runs sin ambigüedad.
        for f in findings.findings:
            if not f.id.startswith(f"{run_slug}-"):
                f.id = f"{run_slug}-{f.id}"
        # Metadata del run embebida en el set: con qué target se obtuvieron (clave
        # para retomar el proyecto y saber qué se analizó), y en qué modo.
        findings.run_id = run_id
        findings.target = target.target_confirmed
        findings.target_mode = target.mode

        # findings.json = copia "latest"; además se archiva el run completo.
        storage.write_json(
            self.project.findings_path, findings.model_dump(mode="json")
        )
        self._archive_run(run_id, findings, target, boost_paths, mode_str)
        logger.info(
            "Análisis completo. Tokens: in=%d out=%d",
            self.llm.total_input_tokens,
            self.llm.total_output_tokens,
        )
        return findings

    def _archive_run(
        self,
        run_id: str,
        findings: FindingSet,
        target: TargetDefinition,
        boost_paths: list[str] | None,
        mode: str,
    ) -> str:
        """Archiva el análisis como un run con ID (historial, no sobrescribe).

        Guarda el target REAL (``target_confirmed``) y su modo, de modo que el
        historial muestre con qué se obtuvo cada run incluso en discovery (donde el
        usuario no escribió ningún target).
        """
        by_status: dict[str, int] = {}
        for f in findings.findings:
            by_status[f.status.value] = by_status.get(f.status.value, 0) + 1
        self.last_run_id = run_id
        runs.RunStore(self.project.hexflaw_dir).save_run(
            run_id,
            findings,
            {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "target": target.target_confirmed,
                "target_mode": target.mode,
                "paths": boost_paths or [],
                "mode": mode,
                "total": len(findings.findings),
                "by_status": by_status,
            },
        )
        return run_id

    def recheck_finding(self, finding_id: str) -> Finding:
        """Re-ejecuta la confirmación de M5 sobre un único hallazgo.

        Útil para hallazgos ``needs_review`` (M5 no concluyó) o ``preliminary``:
        re-consulta al LLM con el código/path y actualiza el veredicto, sin
        re-analizar todo el codebase.

        Args:
            finding_id: ID del hallazgo a re-evaluar.

        Returns:
            El hallazgo con su veredicto actualizado.

        Raises:
            FileNotFoundError: Si no hay findings previos.
            ValueError: Si el ID no existe.
        """
        findings = self._load_findings()
        target = next(
            (f for f in findings.findings if f.id.lower() == finding_id.lower()), None
        )
        if target is None:
            raise ValueError(f"No existe el hallazgo '{finding_id}'.")

        ingestion = self._load_ingestion()
        graph = self._build_or_load_graph(ingestion)
        mode = AnalysisMode(self.config.get("analysis_mode", "balanced"))
        self._begin_phase(f"M5 · re-check {target.id}")
        single = FindingSet(project_id=findings.project_id, findings=[target])
        result = m5_taint.confirm(
            single,
            graph,
            ingestion,
            self.llm,
            model=choose_model(Task.TAINT, mode),
            on_status=self._set_detail,
        )
        self._begin_phase("done")
        updated = result.findings[0]

        merged = [updated if f.id == target.id else f for f in findings.findings]
        new_set = FindingSet(project_id=findings.project_id, findings=merged)
        storage.write_json(self.project.findings_path, new_set.model_dump(mode="json"))
        return updated

    def run_output(
        self, *, do_report: bool, do_poc: bool, report_format: str = "markdown"
    ) -> dict[str, list[Path]]:
        """Ejecuta M6a y luego M6b y/o M6c (en paralelo si ambos) (CLAUDE.md §14).

        Args:
            do_report: Si se deben generar reportes (M6b).
            do_poc: Si se deben generar PoCs (M6c).
            report_format: Formato de reporte (``markdown`` | ``pdf`` | ``json`` | ``sarif``).

        Returns:
            Mapa con las rutas escritas por clave ``"reports"`` / ``"pocs"``.

        Raises:
            FileNotFoundError: Si no hay findings previos (correr ``analyze``).
        """
        findings = self._load_findings()
        confirmed = findings.confirmed()
        if not confirmed:
            logger.info("No hay hallazgos confirmados; nada que reportar.")
            return {"reports": [], "pocs": []}

        ingestion = self._load_ingestion()
        graph = self._build_or_load_graph(ingestion)
        self._begin_phase("M6a · root cause")
        root_causes = self._ensure_root_causes(confirmed, ingestion, graph)

        self._begin_phase("M6b/M6c · reportes + PoC")
        mode = AnalysisMode(self.config.get("analysis_mode", "balanced"))
        code_by_finding = self._code_by_finding(confirmed, ingestion)
        results: dict[str, list[Path]] = {"reports": [], "pocs": []}
        # M6b ∥ M6c — independientes una vez que M6a finaliza.
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = {}
            if do_report:
                futures["reports"] = pool.submit(
                    m6b_report.generate_reports,
                    root_causes,
                    self.project.hexflaw_dir / "reports",
                    fmt=report_format,
                )
            if do_poc:
                futures["pocs"] = pool.submit(
                    m6c_poc.generate_pocs,
                    root_causes,
                    self.project.hexflaw_dir / "poc",
                    llm=self.llm,
                    model=choose_model(Task.POC, mode),
                    code_by_finding=code_by_finding,
                )
            for key, future in futures.items():
                results[key] = future.result()
        return results

    def _code_by_finding(
        self, findings: list[Finding], ingestion: IngestionResult
    ) -> dict[str, str]:
        """Mapea finding_id → código de su función (contexto para M6c)."""
        by_loc: dict[str, str] = {}
        for f in findings:
            for chunk in ingestion.chunks:
                if chunk.file == f.file and (
                    chunk.name == f.function
                    or chunk.line_start <= f.line <= chunk.line_end
                ):
                    by_loc[f.id] = chunk.code
                    break
        return by_loc

    def _ensure_root_causes(
        self, confirmed: list[Finding], ingestion: IngestionResult, graph: CodeGraph
    ) -> list[RootCause]:
        """Ejecuta M6a por hallazgo, con caché en ``.hexflaw/findings/``."""
        findings_dir = storage.ensure_dir(self.project.hexflaw_dir / "findings")
        mode = AnalysisMode(self.config.get("analysis_mode", "balanced"))
        root_causes: list[RootCause] = []
        for finding in confirmed:
            cache_path = findings_dir / f"{finding.id}_{finding.type}.json"
            if cache_path.exists():
                root_causes.append(RootCause.model_validate(storage.read_json(cache_path)))
                continue
            rc = m6a_rootcause.analyze_root_cause(
                finding, ingestion, graph, self.llm, mode=mode
            )
            storage.write_json(cache_path, rc.model_dump(mode="json"))
            root_causes.append(rc)
        return root_causes

    def _load_findings(self) -> FindingSet:
        """Carga ``findings.json`` producido por ``analyze``."""
        if not self.project.findings_path.exists():
            raise FileNotFoundError(
                "No hay hallazgos. Ejecuta 'hexflaw analyze' primero."
            )
        return FindingSet.model_validate(storage.read_json(self.project.findings_path))

    def _build_or_load_graph(self, ingestion: IngestionResult) -> CodeGraph:
        """Carga el code graph cacheado si es válido; si no, ejecuta M3."""
        digest = m3_graph.source_hash(ingestion)
        cached = self.graphs.load_if_valid(digest)
        if cached is not None:
            return cached
        taint = {
            language: framework_service.taint_patterns(self.last_frameworks, language)
            for language in ingestion.languages
        }
        graph = m3_graph.build_graph(ingestion, self.languages, taint)
        self.graphs.save(graph, digest)
        return graph

    # ----------------------------- persistencia ---------------------------- #
    def _persist_ingestion(self, result: IngestionResult) -> None:
        """Persiste chunks y file_hashes en ``.hexflaw/``."""
        storage.write_json(self.project.chunks_path, result.model_dump(mode="json"))
        hashes = {entry.path: entry.hash for entry in result.file_map}
        storage.write_json(self.project.file_hashes_path, hashes)

    def _update_metadata_from_ingestion(self, result: IngestionResult) -> None:
        """Refleja lenguajes y app_type detectados en la metadata del proyecto."""
        meta = self.project.metadata
        meta.languages = result.languages
        meta.app_type = result.app_type
        meta.updated_at = datetime.now(timezone.utc)
        self.project.save_metadata()

    def _load_ingestion(self) -> IngestionResult:
        """Carga el artefacto de ingestión persistido."""
        if not self.project.chunks_path.exists():
            raise FileNotFoundError(
                "No hay datos de ingestión. Ejecuta 'hexflaw ingest <ruta>' primero."
            )
        return IngestionResult.model_validate(storage.read_json(self.project.chunks_path))

    def _load_ingestion_optional(self) -> IngestionResult | None:
        """Carga la ingestión previa si existe; ``None`` en caso contrario."""
        try:
            return self._load_ingestion()
        except (FileNotFoundError, ValueError):
            return None

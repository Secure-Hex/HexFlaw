"""Contratos de interfaz entre módulos del pipeline.

Todos los módulos intercambian datos exclusivamente a través de estos modelos
Pydantic — nunca dicts crudos (ver CLAUDE.md §13, §14). Cada modelo es el
contrato versionado de un punto del pipeline descrito en CLAUDE.md §5/§6.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    """Devuelve el instante actual en UTC (timezone-aware)."""
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Enums compartidos
# --------------------------------------------------------------------------- #
class AppType(str, Enum):
    """Tipo de aplicación detectado en el codebase analizado."""

    WEB = "web"
    BINARY = "binary"
    FIRMWARE = "firmware"
    MOBILE = "mobile"
    CONTRACT = "contract"
    UNKNOWN = "unknown"


class AnalysisMode(str, Enum):
    """Modo de análisis costo/profundidad (CLAUDE.md §16, estrategia 6)."""

    THOROUGH = "thorough"
    BALANCED = "balanced"
    ECONOMY = "economy"


class FindingStatus(str, Enum):
    """Estado de un hallazgo a lo largo del pipeline (M4 → M5)."""

    PRELIMINARY = "preliminary"  # salida de M4, aún no evaluado por M5
    CONFIRMED = "confirmed"
    CONDITIONAL = "conditional"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"  # M5 lo evaluó pero no concluyó (ver review_reason)


class Severity(str, Enum):
    """Severidad de negocio de un hallazgo confirmado (M6b)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# --------------------------------------------------------------------------- #
# M1 — Ingestion
# --------------------------------------------------------------------------- #
class FileEntry(BaseModel):
    """Una entrada del mapa de archivos producido por M1."""

    path: str = Field(..., description="Ruta relativa a la raíz del codebase.")
    language: str = Field(..., description="Identificador de lenguaje (ej. 'c', 'python').")
    hash: str = Field(..., description="SHA-256 del contenido del archivo.")
    size_bytes: int = Field(..., ge=0)


class ChunkKind(str, Enum):
    """Naturaleza del símbolo que representa un chunk (lo llena el chunker AST)."""

    FUNCTION = "function"
    METHOD = "method"
    CLASS = "class"
    MODULE = "module"


class CodeChunk(BaseModel):
    """Unidad semántica de código (una función/clase) lista para indexar/analizar."""

    id: str = Field(..., description="Identificador estable del chunk.")
    file: str = Field(..., description="Ruta relativa del archivo de origen.")
    language: str
    name: str = Field(..., description="Nombre del símbolo (función/clase) o '<module>'.")
    code: str = Field(..., description="Texto del chunk.")
    line_start: int = Field(..., ge=1)
    line_end: int = Field(..., ge=1)
    hash: str = Field(..., description="SHA-256 del texto del chunk (clave de caché).")
    #: Naturaleza del símbolo. Solo la llenan los chunkers con AST; ``None`` en
    #: chunks producidos por el fallback regex y en artefactos pre-feature.
    kind: ChunkKind | None = None
    #: Nombre calificado dentro del archivo (ej. ``"Controller.handle"``). ``name``
    #: sigue siendo el símbolo desnudo para no romper el matching de M4/M5.
    qualname: str | None = None


class IngestionResult(BaseModel):
    """Salida de M1 — Ingestion (CLAUDE.md §6, M1)."""

    project_id: str
    languages: list[str] = Field(default_factory=list)
    app_type: AppType = AppType.UNKNOWN
    file_map: list[FileEntry] = Field(default_factory=list)
    chunks: list[CodeChunk] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=_utcnow)
    skipped: list[str] = Field(
        default_factory=list,
        description="Rutas saltadas por seguridad (symlinks, fuera de sandbox, oversize).",
    )
    dropped_from_prior: list[str] = Field(
        default_factory=list,
        exclude=True,
        description="Archivos que estaban en el índice previo y este ingest dejó "
        "fuera (re-ingest de un path más angosto). Transiente, no se persiste.",
    )


# --------------------------------------------------------------------------- #
# M3 — Code Graph Builder
# --------------------------------------------------------------------------- #
class NodeType(str, Enum):
    """Tipo de nodo en el code graph."""

    FUNCTION = "function"
    CLASS = "class"
    METHOD = "method"
    VARIABLE = "variable"
    CONSTANT = "constant"
    MODULE = "module"


class EdgeType(str, Enum):
    """Tipo de arista en el code graph."""

    CALLS = "calls"
    #: Datos de A alcanzan a B: argumento tainted en la llamada, o valor de retorno.
    DATA_FLOW = "data_flow"
    #: Alcanzar B desde A depende de una condición (la llamada está guardada).
    CONTROL_FLOW = "control_flow"


class GraphNode(BaseModel):
    """Nodo del code graph (función/clase/etc.)."""

    id: str
    type: NodeType = NodeType.FUNCTION
    name: str
    file: str
    line_start: int = Field(..., ge=1)
    line_end: int = Field(..., ge=1)
    signature: str = ""
    is_entry_point: bool = False
    is_sink: bool = False
    tags: list[str] = Field(default_factory=list)


class GraphEdge(BaseModel):
    """Arista dirigida entre dos nodos del code graph."""

    from_: str = Field(..., alias="from")
    to: str
    type: EdgeType = EdgeType.CALLS
    #: Variables cuyo dato viaja por esta arista (solo ``data_flow``).
    data_vars: list[str] = Field(default_factory=list)
    #: Condición que guarda la llamada (solo ``control_flow``), ej. ``if user.is_admin``.
    condition: str = Field(
        "", description="Texto de la guarda del call site; vacío si es incondicional."
    )
    #: ``True`` si el dato pasa por un sanitizador reconocido antes de llegar a ``to``.
    sanitized: bool = False

    model_config = {"populate_by_name": True}


class SinkRef(BaseModel):
    """Referencia a un sink peligroso identificado en el grafo."""

    node_id: str
    sink_type: str = Field(..., description="ej. 'command_execution', 'file_write'.")
    function: str


#: Versión del artefacto M3. **Subirla cuando cambie el formato del grafo o la
#: semántica con la que se construye**, no solo cuando se agregue un campo.
#:
#: El caché de ``code_graph.json`` se valida por hash del código fuente: si el
#: código no cambió, se reutiliza el grafo. Sin esta versión, un proyecto ya
#: analizado seguiría usando un grafo construido con el algoritmo viejo — sin
#: aristas ``data_flow``/``control_flow``, por ejemplo — y M5 razonaría sobre un
#: grafo peor sin que nada lo indique. Es un falso negativo silencioso.
#:
#: Historial:
#:   1 — call graph heurístico por regex, solo aristas ``calls``.
#:   2 — resolución por AST (Python ``ast`` + tree-sitter), nodos con
#:       function/method/class/module, y aristas ``data_flow``/``control_flow``
#:       con ``data_vars``, ``condition`` y ``sanitized``.
GRAPH_SCHEMA_VERSION = 2


class CodeGraph(BaseModel):
    """Artefacto M3 — el más crítico del pipeline (CLAUDE.md §6 M3, §14)."""

    project_id: str
    generated_at: datetime = Field(default_factory=_utcnow)
    language: str = "mixed"
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    entry_points: list[str] = Field(default_factory=list)
    sinks: list[SinkRef] = Field(default_factory=list)

    def node_by_id(self, node_id: str) -> GraphNode | None:
        """Devuelve el nodo con el ``id`` dado, o ``None``."""
        return next((n for n in self.nodes if n.id == node_id), None)


# --------------------------------------------------------------------------- #
# M2 — Target Definition
# --------------------------------------------------------------------------- #
class EntryPoint(BaseModel):
    """Punto de entrada de datos controlables por el atacante."""

    file: str
    function: str
    type: str = Field(..., description="Naturaleza del input, ej. 'user_input', 'network'.")


class TargetDefinition(BaseModel):
    """Salida de M2 — Target Definition (CLAUDE.md §6, M2)."""

    target_confirmed: str
    attack_surface: list[str] = Field(default_factory=list)
    vuln_profile: list[str] = Field(default_factory=list)
    entry_points: list[EntryPoint] = Field(default_factory=list)
    mode: str = Field("directed", description="'discovery' | 'directed'.")


# --------------------------------------------------------------------------- #
# M4 — Static Analysis / M5 — Taint
# --------------------------------------------------------------------------- #
class TaintStep(BaseModel):
    """Un paso en el taint path de un hallazgo (M5)."""

    step: int = Field(..., ge=1)
    file: str
    function: str
    note: str


class Finding(BaseModel):
    """Hallazgo de vulnerabilidad. Evoluciona de preliminary (M4) a confirmed (M5)."""

    id: str
    type: str = Field(..., description="Clase de vulnerabilidad, ej. 'command_injection'.")
    file: str
    line: int = Field(..., ge=0)
    function: str | None = None
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    snippet: str = ""
    status: FindingStatus = FindingStatus.PRELIMINARY
    severity: Severity | None = None
    taint_path: list[TaintStep] = Field(default_factory=list)
    rationale: str = Field("", description="Justificación breve del LLM (no para cliente).")
    review_reason: str = Field(
        "", description="Por qué M5 no concluyó (estado needs_review)."
    )
    #: Id del hallazgo semilla que originó esta variante (M5b); None si no lo es.
    variant_of: str | None = None


class FindingSet(BaseModel):
    """Conjunto consolidado de hallazgos persistido en ``.hexflaw/findings.json``."""

    project_id: str
    findings: list[Finding] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=_utcnow)
    #: Run que produjo estos hallazgos (None en sets viejos/pre-feature).
    run_id: str | None = None
    #: Target con el que se obtuvieron (para retomar el proyecto y saber qué se
    #: analizó). En directed = el del usuario; en discovery = el que halló el modelo.
    target: str | None = None
    #: Modo de M2 que produjo el target: "directed" | "discovery".
    target_mode: str | None = None

    def confirmed(self) -> list[Finding]:
        """Devuelve solo los hallazgos confirmados o condicionales (reportables)."""
        return [
            f
            for f in self.findings
            if f.status in (FindingStatus.CONFIRMED, FindingStatus.CONDITIONAL)
        ]


# --------------------------------------------------------------------------- #
# M6a — Root Cause Analysis
# --------------------------------------------------------------------------- #
class PoCConfidence(str, Enum):
    """Nivel de confianza del PoC generado (CLAUDE.md §6 M6c)."""

    HIGH = "high_confidence"
    MEDIUM = "medium_confidence"
    MANUAL = "requires_manual_tuning"


class RootCause(BaseModel):
    """Análisis de causa raíz de un hallazgo confirmado (CLAUDE.md §6 M6a).

    Es el input compartido de M6b (reportes) y M6c (PoC).
    """

    finding_id: str
    type: str
    summary: str = Field("", description="Descripción de negocio, sin código (ejecutivo).")
    root_cause: str = Field("", description="Por qué existe la vuln, no solo el síntoma.")
    affected_files: list[str] = Field(default_factory=list)
    affected_lines: list[str] = Field(
        default_factory=list, description="Referencias 'archivo:línea'."
    )
    blast_radius: str = ""
    cvss_vector: str = Field("", description="Vector string CVSS v3.1.")
    cvss_score: float = Field(0.0, ge=0.0, le=10.0)
    severity: Severity = Severity.MEDIUM
    remediation_summary: str = Field("", description="Acción recomendada no técnica.")
    vulnerable_code: str = ""
    fixed_code: str = ""
    poc_confidence: PoCConfidence = PoCConfidence.MANUAL
    llm_confidence: float = Field(0.0, ge=0.0, le=1.0)


# --------------------------------------------------------------------------- #
# M0 — System Profiling
# --------------------------------------------------------------------------- #
class SystemProfile(BaseModel):
    """Perfil de hardware y recomendación de backend (CLAUDE.md §6 M0).

    Persistido en ``~/.hexflaw/system_profile.json``.
    """

    cpu_model: str = "unknown"
    cpu_cores: int = 0
    cpu_freq_mhz: float | None = None
    ram_total_gb: float = 0.0
    gpu_detected: bool = False
    gpu_type: str | None = None
    ollama_available: bool = False
    internet: bool = False
    benchmarks: dict[str, float] = Field(
        default_factory=dict, description="backend_id -> ms por embedding (menor es mejor)."
    )
    recommended_backend: str = "local-cpu"
    recommendation_reason: str = ""
    generated_at: datetime = Field(default_factory=_utcnow)


# --------------------------------------------------------------------------- #
# Metadata del proyecto
# --------------------------------------------------------------------------- #
class ProjectMetadata(BaseModel):
    """Contenido de ``.hexflaw/metadata.json`` (CLAUDE.md §8)."""

    project_id: str
    name: str
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    languages: list[str] = Field(default_factory=list)
    app_type: AppType = AppType.UNKNOWN

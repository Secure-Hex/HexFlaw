"""Gestor de jerarquía de configuración (CLAUDE.md §7, §8).

Precedencia (mayor gana):

    Override en comando > config.json local (.hexflaw/) > config.json global
    (~/.hexflaw/) > defaults del sistema

La config global contiene **únicamente** preferencias del sistema (embedding
backend, API keys, system profile). Nunca datos de proyecto.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hexflaw.infrastructure import secrets_store, storage
from hexflaw.infrastructure.logging import get_logger

logger = get_logger(__name__)

DEFAULT_CONFIG: dict[str, Any] = {
    "embedding_backend": "local-cpu",
    # Backend del LLM: "api" (Anthropic API, default), "openai" (API de OpenAI) o
    # "agent" (agente en el loop por cola de archivos: HexFlaw parkea el prompt en
    # disco y un agente externo —Claude Code, Codex, etc.— lo responde; cero tokens
    # de API; ver 'hexflaw agent'). Para "openai" se mapean los tiers
    # haiku/sonnet/opus a estos modelos (ajustables a tu catálogo de OpenAI):
    "llm_backend": "api",
    "openai_model_cheap": "gpt-4o-mini",  # tier 'haiku' (screening/simple)
    "openai_model_mid": "gpt-4o",  # tier 'sonnet' (análisis estándar)
    "openai_model_deep": "gpt-4o",  # tier 'opus' (taint/razonamiento profundo)
    # Backend "agent" (cola de archivos). queue_dir None => ~/.hexflaw/agent_queue.
    "agent_queue_dir": None,
    "agent_poll_timeout": 1800,  # s máximos esperando la respuesta del agente
    "agent_poll_interval": 1.0,  # s entre sondeos de la respuesta
    "analysis_mode": "balanced",
    # Techo de tokens por análisis (CLAUDE.md §16, estrategia 7). Es un ceiling, no
    # un target: solo frena si el run lo alcanza. 500k no alcanzaba para M4+M5 en
    # scopes de ~200 chunks (M4 agotaba el budget y M5 no llegaba a confirmar).
    "token_budget": 1_500_000,
    "max_file_bytes": 10 * 1024 * 1024,  # 10MB (CLAUDE.md §15, M1)
    "max_project_bytes": 2 * 1024 * 1024 * 1024,  # 2GB
    "model": "claude-sonnet-4-6",
    # Rate limiting interno (CLAUDE.md §16, §15 T-M4-2). El org real observado es
    # tier-1 = 50k input TPM por modelo (429 de Anthropic), así que 40k deja margen.
    # Subir solo si confirmás un tier mayor en console.anthropic.com/settings/limits.
    "rate_limit_tokens_per_min": 40_000,
    "max_retries": 4,
    # Fracción del token_budget que M4 reserva para que M5 (confirmación) siempre
    # tenga presupuesto. Sin esto, M4 puede agotar el techo y dejar 0 confirmados.
    "m5_budget_reserve": 0.30,
    # Tope de chunks a analizar tras acotar por el target (M4 scope). Evita barrer
    # codebases enormes cuando se da un --target específico.
    "scope_max_chunks": 200,
    # Modelo del backend local-cpu. Default: modelo nativo de sentence-transformers
    # entrenado para code search (CodeSearchNet), sin trust_remote_code por seguridad.
    "local_embedding_model": "flax-sentence-embeddings/st-codesearch-distilroberta-base",
    "local_embedding_trust_remote_code": False,
    # --- M4: dedup near-duplicados -------------------------------------- #
    # Umbral de similitud coseno para descartar un chunk como near-duplicado. Un
    # valor > 1.0 lo desactiva (ningún par lo supera): necesario en codebases con
    # código legítimamente repetido pero de distinto comportamiento de seguridad
    # (endpoints donde unos sanitizan y otros no, suites tipo OWASP Benchmark).
    # El dedup exacto por hash sigue activo siempre.
    "m4_near_dedup_threshold": 0.95,
    # Saltos máximos hasta un sink para que el prefiltro de M4 rescate un chunk que
    # no tiene ninguna keyword. Cubre el caso del helper propio: la función que
    # recibe el input del usuario no dice "subprocess", pero llama a la que sí.
    # 0 desactiva el rescate; subirlo agranda el scope (y el costo en tokens).
    "m4_sink_rescue_hops": 2,
    # Aprender sinks por LLM de los lenguajes del proyecto que no tienen cobertura
    # curada. Es una optimización, no un gasto: esos lenguajes hoy hacen fail-open
    # (se analizan enteros para no perder vulns), así que una llamada única sale
    # mucho más barata que ese fail-open en cada corrida. Lo aprendido queda en el
    # .hexflaw/ del proyecto, nunca en el custom global.
    "auto_learn_sinks": True,
    # Rescate semántico: chunks que ninguna keyword vio y que tampoco llaman a un
    # sink conocido, pero que SE PARECEN a uno. Es la última red del prefiltro y la
    # más difusa: no deja una razón auditable, solo un score.
    #
    # El umbral está MEDIDO, no elegido a ojo: con el modelo por defecto, el código
    # peligroso puntúa >= 0.29 y el inerte <= 0.14 comparando contra ejemplos de
    # código. 0.22 cae en ese hueco. Calibrado sobre pocas muestras, así que si ves
    # rescates de más subilo, y si se pierden hallazgos bajalo. El tope acota el
    # costo: los chunks se ordenan por score y solo entran los mejores.
    "m4_semantic_rescue_threshold": 0.22,
    # El tope de la capa 3 es max(piso, fracción × chunks ya aceptados). Un tope
    # absoluto queda mal en los dos extremos: medido contra el OWASP Benchmark
    # (13.691 chunks), un tope fijo de 25 aportaba +0,3 puntos de recall — el
    # rescate funcionaba pero el tope lo anulaba. Atarlo a lo ya aceptado hace que
    # el sobrecosto máximo sea predecible: nunca más de un 10% extra.
    "m4_semantic_rescue_max": 25,
    "m4_semantic_rescue_fraction": 0.10,
    # --- Modo exhaustive ------------------------------------------------- #
    # Analiza TODO el codebase sin prefiltro de sinks, sin límite de scope y con
    # Opus en todas las tareas. Lo activa 'analyze --exhaustive'; acá queda
    # registrado para que 'config --show' lo liste.
    "exhaustive": False,
    # --- M5b: variant hunting ------------------------------------------- #
    # Usa los confirmados de M5 como semilla y caza sus vecinos en el espacio de
    # embeddings, re-analizándolos aunque el scope de M4 los hubiera descartado.
    "variant_hunting": True,
    "variant_top_k": 10,  # vecinos máximos por semilla
    "variant_min_similarity": 0.78,  # umbral coseno para considerar un vecino
    "variant_max_total": 50,  # tope duro de variantes exploradas
    "variant_max_rounds": 5,  # tope duro de rondas iterativas
}


def global_home() -> Path:
    """Directorio global de HexFlaw (``~/.hexflaw`` u override por entorno)."""
    raw = os.environ.get("HEXFLAW_HOME", "~/.hexflaw")
    return Path(raw).expanduser()


@dataclass
class Config:
    """Configuración efectiva tras aplicar la jerarquía de precedencia.

    Attributes:
        values: Diccionario de configuración ya mergeado.
        sources: Trazabilidad de qué capa aportó cada estado (para ``--show``).
    """

    values: dict[str, Any] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)

    def get(self, key: str, default: Any = None) -> Any:
        """Obtiene un valor de configuración con fallback."""
        return self.values.get(key, default)


def load_global_config() -> dict[str, Any]:
    """Carga ``~/.hexflaw/config.json`` si existe, validando permisos.

    Verifica que el directorio global sea ``700``; si no, advierte y corrige
    (CLAUDE.md §15, T-M0-1).

    Returns:
        Diccionario de config global (vacío si no existe el archivo).
    """
    home = global_home()
    if home.exists():
        _enforce_secure_perms(home)
    cfg_path = home / "config.json"
    if not cfg_path.exists():
        return {}
    try:
        return dict(storage.read_json(cfg_path))
    except (ValueError, OSError) as exc:
        logger.warning("config.json global ilegible (%s); usando defaults", exc)
        return {}


def load_local_config(project_dir: Path) -> dict[str, Any]:
    """Carga la config local de un proyecto (``<proj>/.hexflaw/config.json``).

    Args:
        project_dir: Directorio raíz del proyecto (el que contiene ``.hexflaw/``).

    Returns:
        Diccionario de config local (vacío si no existe).
    """
    cfg_path = project_dir / ".hexflaw" / "config.json"
    if not cfg_path.exists():
        return {}
    try:
        return dict(storage.read_json(cfg_path))
    except (ValueError, OSError) as exc:
        logger.warning("config.json local ilegible (%s); ignorando", exc)
        return {}


def resolve_config(
    project_dir: Path | None = None,
    overrides: dict[str, Any] | None = None,
) -> Config:
    """Resuelve la configuración efectiva aplicando la jerarquía completa.

    Args:
        project_dir: Raíz del proyecto activo, o ``None`` si no hay proyecto.
        overrides: Valores provenientes de flags de la CLI (máxima precedencia).
            Las claves con valor ``None`` se ignoran (flag no provisto).

    Returns:
        Config efectiva con trazabilidad de fuentes.
    """
    merged: dict[str, Any] = dict(DEFAULT_CONFIG)
    sources = ["defaults"]

    global_cfg = load_global_config()
    if global_cfg:
        merged.update(global_cfg)
        sources.append("global")

    if project_dir is not None:
        local_cfg = load_local_config(project_dir)
        if local_cfg:
            merged.update(local_cfg)
            sources.append("local")

    if overrides:
        clean = {k: v for k, v in overrides.items() if v is not None}
        if clean:
            merged.update(clean)
            sources.append("cli-override")

    # API keys: el entorno tiene prioridad sobre lo persistido (mejor higiene).
    for env_name, cfg_key in (
        ("ANTHROPIC_API_KEY", "anthropic_api_key"),
        ("VOYAGE_API_KEY", "voyage_api_key"),
        ("OPENAI_API_KEY", "openai_api_key"),
    ):
        value = os.environ.get(env_name)
        if value:
            merged[cfg_key] = value

    # Keyring del SO (CLAUDE.md §15, T-INFRA-1): rellena solo las keys que no vino
    # ya por entorno ni por config.json. Es el store primario; el JSON es fallback.
    for cfg_key in secrets_store.SECRET_KEYS:
        if not merged.get(cfg_key):
            secret = secrets_store.get_secret(cfg_key)
            if secret:
                merged[cfg_key] = secret

    return Config(values=merged, sources=sources)


def save_global_config(updates: dict[str, Any]) -> Path:
    """Persiste cambios en la config global con permisos ``600``.

    Args:
        updates: Pares clave/valor a fusionar en la config global existente.

    Returns:
        Ruta del ``config.json`` global escrito.
    """
    home = storage.ensure_dir(global_home())
    cfg_path = home / "config.json"
    current = load_global_config()
    current.update(updates)
    storage.write_json(cfg_path, current)
    return cfg_path


def save_secret(cfg_key: str, value: str) -> str:
    """Persiste una API key en el keyring del SO, con fallback a ``config.json``.

    Si el keyring está disponible, guarda ahí y **elimina** cualquier copia en
    texto plano que hubiera quedado en la config global (CLAUDE.md §15, T-INFRA-1).
    Si no hay keyring, cae al ``config.json`` global (``600``) y deja constancia.

    Args:
        cfg_key: Clave de config del secreto (ej. ``anthropic_api_key``).
        value: Valor del secreto.

    Returns:
        ``"keyring"`` o ``"config.json"`` según dónde se almacenó.
    """
    if secrets_store.set_secret(cfg_key, value):
        # Quitar cualquier copia en texto plano previa de la config global.
        current = load_global_config()
        if cfg_key in current:
            del current[cfg_key]
            cfg_path = global_home() / "config.json"
            storage.write_json(cfg_path, current)
        return "keyring"

    save_global_config({cfg_key: value})
    logger.warning(
        "keyring no disponible: '%s' se guardó en config.json (600). Instala el "
        "extra 'secrets' (pip install hexflaw[secrets]) para usar el keyring del SO.",
        cfg_key,
    )
    return "config.json"


def _enforce_secure_perms(home: Path) -> None:
    """Verifica/corrige permisos ``700`` del directorio global."""
    try:
        mode = home.stat().st_mode & 0o777
        if mode != storage.DIR_MODE:
            logger.warning(
                "%s tiene permisos %o, corrigiendo a 700", home, mode
            )
            os.chmod(home, storage.DIR_MODE)
    except OSError as exc:
        logger.debug("No se pudieron verificar permisos de %s: %s", home, exc)

"""Comando ``hexflaw models`` — ver y cambiar qué modelo corre cada tarea.

El pipeline no elige modelos: elige **tiers** (``cheap``/``mid``/``deep``, ver
:mod:`hexflaw.core.model_policy`) y el backend activo los traduce. Este comando es
la superficie sobre esa traducción: qué modelo va a correr realmente, y cómo
cambiarlo sin editar JSON a mano ni esperar un release cuando sale un modelo nuevo.
"""

from __future__ import annotations

import typer

from hexflaw.cli import console
from hexflaw.cli.helpers import resolve_active_config
from hexflaw.core.model_policy import ModelTier, tasks_by_tier
from hexflaw.core.models import AnalysisMode
from hexflaw.infrastructure import config as config_mod
from hexflaw.services.llm_service import ANTHROPIC_MODELS, OPENAI_MODELS, models_from_config

app = typer.Typer(help="Modelos por tier (qué modelo corre cada tarea).")

#: Backends con catálogo propio. El backend ``agent`` no aparece porque no tiene
#: uno: hereda el de Anthropic para que el request que parkea en la cola diga qué
#: capacidad se espera de quien lo responda.
_BACKENDS = {
    "api": ("anthropic", ANTHROPIC_MODELS, "Anthropic"),
    "openai": ("openai", OPENAI_MODELS, "OpenAI"),
}

_TIER_HELP = {
    ModelTier.CHEAP: "screening y patrones directos",
    ModelTier.MID: "análisis estándar y reportes",
    ModelTier.DEEP: "taint, discovery, root cause crítico",
}


def _backend_key(backend: str | None) -> str:
    """Resuelve el backend a consultar/editar, validándolo.

    Args:
        backend: Backend explícito, o ``None`` para usar el activo en config.

    Returns:
        Clave de :data:`_BACKENDS`.

    Raises:
        typer.Exit: Si el backend no tiene catálogo propio.
    """
    if backend is None:
        active = str(resolve_active_config().get("llm_backend", "api"))
        # 'agent' no tiene catálogo: usa el de Anthropic (ver build_llm_service).
        backend = "api" if active == "agent" else active
    if backend not in _BACKENDS:
        console.error(
            f"Backend sin catálogo de modelos: '{backend}'. "
            f"Opciones: {', '.join(sorted(_BACKENDS))}"
        )
        raise typer.Exit(code=1)
    return backend


@app.command("list")
def list_models(
    backend: str = typer.Option(
        None, "--backend", help="api | openai. Por defecto, el backend activo."
    ),
    mode: str = typer.Option(
        None, "--mode", help="thorough | balanced | economy. Por defecto, el activo."
    ),
) -> None:
    """Muestra qué modelo va a correr cada tarea con la config actual."""
    cfg = resolve_active_config()
    key = _backend_key(backend)
    prefix, fallback, label = _BACKENDS[key]

    raw_mode = mode or str(cfg.get("analysis_mode", "balanced"))
    try:
        analysis_mode = AnalysisMode(raw_mode)
    except ValueError:
        console.error(
            f"Modo desconocido: '{raw_mode}'. "
            f"Opciones: {', '.join(m.value for m in AnalysisMode)}"
        )
        raise typer.Exit(code=1) from None

    resolved = models_from_config(cfg, prefix, fallback)
    grouped = tasks_by_tier(analysis_mode)

    console.info(
        f"backend [bold]{key}[/] ({label}) · modo [bold]{analysis_mode.value}[/]"
    )
    tbl = console.table("Modelos por tier", ["Tier", "Modelo", "Tareas", "Origen"])
    for tier in ModelTier:
        tasks = grouped.get(tier, [])
        # El origen importa tanto como el valor: dice si lo elegiste vos o si es lo
        # que trae el paquete, que es la diferencia entre "está configurado" y
        # "todavía nadie lo tocó".
        origen = (
            "[green]config[/]" if cfg.get(f"{prefix}_model_{tier.value}")
            else "[dim]default[/]"
        )
        tbl.add_row(
            f"[bold]{tier.value}[/]",
            console.esc(resolved[tier]),
            console.esc(", ".join(t.value for t in tasks)) or "[dim]—[/]",
            origen,
        )
    console.print_table(tbl)
    console.info(
        "[dim]" + " · ".join(f"{t.value}: {_TIER_HELP[t]}" for t in ModelTier) + "[/]"
    )


@app.command("set")
def set_model(
    cheap: str = typer.Option(None, "--cheap", help="Modelo del tier cheap."),
    mid: str = typer.Option(None, "--mid", help="Modelo del tier mid."),
    deep: str = typer.Option(None, "--deep", help="Modelo del tier deep."),
    backend: str = typer.Option(
        None, "--backend", help="api | openai. Por defecto, el backend activo."
    ),
) -> None:
    """Fija el modelo de uno o más tiers en la config global."""
    key = _backend_key(backend)
    prefix, _, _ = _BACKENDS[key]

    updates: dict[str, str] = {}
    for tier, value in ((ModelTier.CHEAP, cheap), (ModelTier.MID, mid), (ModelTier.DEEP, deep)):
        if value is not None:
            updates[f"{prefix}_model_{tier.value}"] = value

    if not updates:
        console.error("Nada que cambiar: pasá al menos uno de --cheap/--mid/--deep.")
        raise typer.Exit(code=1)

    path = config_mod.save_global_config(updates)
    for cfg_key, value in updates.items():
        console.success(f"{cfg_key} = {console.esc(value)}")
    console.info(f"[dim]{path}[/]")
    # No es una advertencia decorativa: la clave del caché de análisis incluye el
    # modelo resuelto, así que cambiarlo deja fuera de juego lo analizado con el
    # anterior. Es lo correcto —reusar respuestas de otro modelo sería mentir sobre
    # quién las produjo— pero el próximo run va a costar tokens de nuevo.
    console.warn(
        "El caché de análisis de los chunks analizados con el modelo anterior queda "
        "invalidado: el próximo run los vuelve a consultar."
    )

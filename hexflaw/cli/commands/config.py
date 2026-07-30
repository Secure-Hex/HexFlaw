"""Comando ``hexflaw config`` — ver y editar configuración (global/local)."""

from __future__ import annotations

import typer

from hexflaw.cli import console
from hexflaw.cli.helpers import resolve_active_config
from hexflaw.infrastructure import config as config_mod

# Claves seguras de mostrar (nunca volcamos API keys en claro).
_REDACTED_KEYS = {"anthropic_api_key", "voyage_api_key", "openai_api_key"}


def config_command(
    show: bool = typer.Option(False, "--show", help="Mostrar config efectiva (merged)."),
    embedding_backend: str = typer.Option(
        None, "--embedding-backend", help="Backend de embeddings a configurar."
    ),
    api_key: str = typer.Option(None, "--api-key", help="Anthropic API key (global)."),
    token_budget: int = typer.Option(None, "--token-budget", help="Budget de tokens."),
    profile: str = typer.Option(
        None,
        "--profile",
        help="Perfil de calibración por defecto: fast | audit | paranoid.",
    ),
) -> None:
    """Gestiona la configuración global de HexFlaw.

    Sin flags de escritura, equivale a ``--show``.
    """
    updates: dict[str, object] = {}
    if embedding_backend is not None:
        updates["embedding_backend"] = embedding_backend
    if token_budget is not None:
        updates["token_budget"] = token_budget
    if profile is not None:
        if profile not in config_mod.PROFILES:
            console.error(
                f"Perfil desconocido: '{profile}'. "
                f"Opciones: {', '.join(sorted(config_mod.PROFILES))}"
            )
            raise typer.Exit(code=1)
        updates["profile"] = profile

    if updates or api_key is not None:
        if updates:
            path = config_mod.save_global_config(updates)
            console.success(f"Config global actualizada: [dim]{path}[/]")
        if api_key is not None:
            # Las API keys nunca van a config.json si hay keyring (T-INFRA-1).
            where = config_mod.save_secret("anthropic_api_key", api_key)
            if where == "keyring":
                console.success("Anthropic API key guardada en el keyring del SO.")
            else:
                console.warn(
                    "Anthropic API key guardada en config.json (600): keyring no "
                    "disponible. Instala 'pip install hexflaw[secrets]' para usar el keyring."
                )
        return

    cfg = resolve_active_config()
    tbl = console.table(
        f"Config efectiva · fuentes: {', '.join(cfg.sources)}", ["Clave", "Valor"]
    )
    for key in sorted(cfg.values):
        if key in _REDACTED_KEYS:
            value = "[dim italic][REDACTED][/]"
        else:
            value = console.esc(cfg.values[key])
        tbl.add_row(console.esc(key), value)
    console.print_table(tbl)

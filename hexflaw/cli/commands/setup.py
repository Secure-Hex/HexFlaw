"""Comando ``hexflaw setup`` — M0 System Profiling y recomendación de backend."""

from __future__ import annotations

import typer

from hexflaw.cli import console
from hexflaw.core.models import SystemProfile
from hexflaw.infrastructure import config as config_mod
from hexflaw.infrastructure import profile_store
from hexflaw.modules import m0_profiling
from hexflaw.services import language_service


def setup_command(
    reprofile: bool = typer.Option(
        False,
        "--reprofile",
        "--reprofle",  # alias por compatibilidad con la doc original
        help="Forzar re-perfilado aunque ya exista un system profile.",
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Aplicar la recomendación sin preguntar."
    ),
) -> None:
    """Perfila el sistema y recomienda el backend de embeddings óptimo."""
    console.banner("System Profiling · M0")
    existing = profile_store.load_profile()
    if existing is not None and not reprofile:
        console.info("[cyan]Ya existe un system profile:[/]")
        _print_profile(existing)
        console.info("\nUsa [bold]hexflaw setup --reprofile[/] para volver a perfilar.")
        return

    with console.step("Perfilando el sistema (CPU, RAM, GPU, benchmark)..."):
        profile = m0_profiling.profile_system()
        profile_store.save_profile(profile)
    _print_profile(profile)

    # Materializa los builtins de lenguajes como solo-lectura (444) en el home,
    # inspeccionables sin poder corromperlos (CLAUDE.md §14/§15, inmutabilidad).
    with console.step("Sincronizando definiciones de lenguaje builtin (444)..."):
        language_service.sync_builtins()

    apply = yes or typer.confirm(
        f"\nAplicar configuración (embedding_backend = {profile.recommended_backend})?",
        default=True,
    )
    if apply:
        config_mod.save_global_config(
            {"embedding_backend": profile.recommended_backend}
        )
        console.success(
            f"Backend [bold]{profile.recommended_backend}[/] aplicado a la config global."
        )
    else:
        console.warn("Configuración no aplicada (profile igual guardado).")


def _print_profile(profile: SystemProfile) -> None:
    """Imprime el perfil con un panel y la recomendación destacada."""
    net = "[green]Connected[/]" if profile.internet else "[red]Offline[/]"
    gpu = (
        f"[green]{profile.gpu_type}[/]"
        if profile.gpu_detected
        else "[dim]Not detected[/]"
    )
    rows = [
        ("CPU", f"{profile.cpu_model} ({profile.cpu_cores} cores)"),
        ("RAM", f"{profile.ram_total_gb} GB"),
        ("GPU", gpu),
        ("Net", net),
    ]
    if profile.benchmarks:
        rows.append(
            ("Bench", ", ".join(f"{k}={v}ms" for k, v in profile.benchmarks.items()))
        )
    console.kv_panel("System Profile", rows)
    console.console.print(
        f"[bold]Recomendación:[/] [bold green]{profile.recommended_backend}[/]\n"
        f"  [dim]{profile.recommendation_reason}[/]"
    )

"""Comando ``hexflaw analyze`` — M2 → M5 sobre la ingestión persistida."""

from __future__ import annotations

from typing import Any
from typing import List

import typer

from hexflaw.cli import console
from hexflaw.cli.helpers import build_orchestrator, handle_project_errors


def _parse_paths(raw: List[str] | None) -> list[str]:
    """Normaliza ``--path`` (repetible y/o separado por espacio/coma)."""
    result: list[str] = []
    for item in raw or []:
        result.extend(p for p in item.replace(",", " ").split() if p)
    return result


def analyze_command(
    target: str = typer.Option(
        None, "--target", help="Funcionalidad a analizar (modo directed)."
    ),
    path: List[str] = typer.Option(
        None,
        "--path",
        help="Prioriza chunks bajo estas rutas (plus, no filtro duro). Repetible.",
    ),
    mode: str = typer.Option(
        None, "--mode", help="thorough | balanced | economy (override)."
    ),
    budget: int = typer.Option(
        None, "--budget", help="Budget de tokens máximo para este análisis."
    ),
    llm_backend: str = typer.Option(
        None,
        "--llm-backend",
        help="api (Anthropic) | openai | agent (cola de archivos, sin tokens; ver 'hexflaw agent').",
    ),
    hunt_variants: bool = typer.Option(
        None,
        "--hunt-variants/--no-hunt-variants",
        help="M5b: cazar variantes de los confirmados vía embeddings (default: on salvo economy).",
    ),
    exhaustive: bool = typer.Option(
        False,
        "--exhaustive",
        help="Máxima cobertura: analiza TODO el codebase (sin prefiltro de sinks, sin "
        "límite de scope, sin dedup) con Opus en todas las tareas. El más lento y caro.",
    ),
) -> None:
    """Ejecuta el análisis estático preliminar y persiste los hallazgos."""
    overrides: dict[str, object] = {}
    if mode:
        overrides["analysis_mode"] = mode
    if budget is not None:
        overrides["token_budget"] = budget
    if llm_backend:
        overrides["llm_backend"] = llm_backend
    if hunt_variants is not None:
        overrides["variant_hunting"] = hunt_variants
    if exhaustive:
        # Preset agresivo: nada se descarta antes del LLM y se usa Opus en todo.
        overrides["exhaustive"] = True
        overrides.setdefault("analysis_mode", "thorough")
        overrides["scope_max_chunks"] = 1_000_000  # efectivamente sin límite
        overrides["m4_near_dedup_threshold"] = 2.0  # desactiva dedup near
    effective = overrides or None
    boost_paths = _parse_paths(path)

    with handle_project_errors():
        orchestrator = build_orchestrator(overrides=effective)
        findings = console.live_run(
            orchestrator,
            lambda: orchestrator.run_analyze(target, boost_paths=boost_paths),
            title="HexFlaw · analyze",
        )

    run_id = getattr(orchestrator, "last_run_id", None)
    if run_id:
        console.info(f"[dim]Run archivado: [bold]{run_id}[/] · ver historial con "
                     f"[bold]hexflaw findings runs[/][/]")
    _print_target(getattr(orchestrator, "last_target", None))
    _print_coverage(getattr(orchestrator, "last_coverage", {}), boost_paths)

    if not findings.findings:
        console.success("Sin hallazgos.")
        return

    # Los false_positive son ruido en la tabla principal; se resumen aparte.
    fps = [f for f in findings.findings if f.status.value == "false_positive"]
    notable = [f for f in findings.findings if f.status.value != "false_positive"]
    confirmed = [f for f in findings.findings if f.status.value == "confirmed"]

    if notable:
        tbl = console.table(
            f"{len(notable)} hallazgo(s) a revisar · {len(confirmed)} confirmado(s)",
            ["ID", "Estado", "Sev", "Tipo", "Ubicación", "Función"],
        )
        for f in notable:
            status_style = console.STATUS_STYLE.get(f.status.value, "white")
            sev = f.severity.value if f.severity else "—"
            sev_style = console.SEVERITY_STYLE.get(sev, "dim")
            tbl.add_row(
                f.id,
                f"[{status_style}]{f.status.value}[/]",
                f"[{sev_style}]{sev}[/]",
                console.esc(f.type),
                console.esc(f"{f.file}:{f.line}"),
                console.esc(f.function or "—"),
            )
        console.print_table(tbl)
    else:
        console.success("Ningún hallazgo a revisar (confirmed/conditional/preliminary).")

    if fps:
        console.info(
            f"[dim]+ {len(fps)} descartados como false_positive · "
            f"vélos con [bold]hexflaw findings list --status false_positive[/][/]"
        )

    for f in confirmed:
        if f.taint_path:
            console.info(f"\n[bold]{f.id}[/] taint path:")
            for step in f.taint_path:
                console.info(
                    f"  [dim]{step.step}.[/] [cyan]{console.esc(step.function)}[/]: "
                    f"{console.esc(step.note)}"
                )


def _print_target(target: object) -> None:
    """Muestra en qué modo trabajó M2 y qué target se analizó.

    En ``directed`` el target lo especificó el usuario; en ``discovery`` lo
    descubrió el modelo — en ese caso se destaca para que el usuario sepa qué
    superficie eligió la herramienta por sí sola.
    """
    if target is None:
        return
    mode = getattr(target, "mode", "directed")
    confirmed = getattr(target, "target_confirmed", "") or "—"
    profile = getattr(target, "vuln_profile", []) or []
    surface = getattr(target, "attack_surface", []) or []
    entries = getattr(target, "entry_points", []) or []

    if mode == "discovery":
        console.info(
            "[bold yellow]M2 · discovery[/] — target [bold]descubierto por el modelo[/]:"
        )
    else:
        console.info(
            "[bold cyan]M2 · directed[/] — target [bold]especificado por el usuario[/]:"
        )
    console.info(f"  [bold]» {console.esc(str(confirmed))}[/]")
    prof = ", ".join(str(v) for v in profile[:8]) or "—"
    console.info(
        f"  [dim]vuln_profile:[/] {console.esc(prof)} · "
        f"[dim]superficie:[/] {len(surface)} archivo(s) · "
        f"[dim]entry points:[/] {len(entries)}"
    )


def _print_coverage(coverage: dict[str, Any], boost_paths: list[str]) -> None:
    """Muestra qué se analizó (incluido el path apuntado y lo que salió limpio)."""
    if not coverage:
        return
    scoped = coverage.get("scoped", 0)
    analyzed = coverage.get("analyzed_llm", 0)
    cached = coverage.get("from_cache", 0)
    console.info(
        f"[dim]Cobertura: {scoped} chunks en scope · {analyzed} analizados por LLM "
        f"· {cached} de caché[/]"
    )
    if boost_paths:
        path_analyzed = coverage.get("path_analyzed", [])
        path_clean = coverage.get("path_clean", [])
        console.info(
            f"[bold]Path apuntado:[/] {len(path_analyzed)} funciones analizadas, "
            f"[green]{len(path_clean)} sin hallazgos[/] (auditadas → limpias):"
        )
        for ref in path_clean[:12]:
            console.info(f"  [green]✓[/] {console.esc(ref)}")

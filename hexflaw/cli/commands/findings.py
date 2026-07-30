"""Subcomando ``hexflaw findings`` — inspeccionar hallazgos persistidos."""

from __future__ import annotations

from typing import Any

import typer

from hexflaw.cli import console
from hexflaw.cli.helpers import build_orchestrator, handle_project_errors
from hexflaw.core import project as project_mod
from hexflaw.core.models import Finding, FindingSet, RootCause
from hexflaw.infrastructure import storage
from hexflaw.infrastructure.runs import RunStore

app = typer.Typer(help="Inspeccionar los hallazgos del proyecto.")


def _load_findings(run: str | None = None) -> tuple[project_mod.Project, FindingSet]:
    project = project_mod.load_project()
    if run:
        return project, RunStore(project.hexflaw_dir).load_run(run)
    if not project.findings_path.exists():
        raise FileNotFoundError("No hay hallazgos. Ejecuta 'hexflaw analyze' primero.")
    return project, FindingSet.model_validate(storage.read_json(project.findings_path))


def _all_runs(project: project_mod.Project) -> list[tuple[dict[str, Any], FindingSet]]:
    """Carga (meta, FindingSet) de todos los runs del historial, recientes primero.

    Permite buscar hallazgos en TODOS los análisis, no solo en el último.
    """
    store = RunStore(project.hexflaw_dir)
    out: list[tuple[dict[str, Any], FindingSet]] = []
    for meta in store.list_runs():
        rid = meta.get("run_id")
        if not rid:
            continue
        try:
            out.append((meta, store.load_run(rid)))
        except (FileNotFoundError, ValueError):
            continue
    return out


def _target_label(fs: FindingSet, meta: dict[str, Any] | None = None) -> str:
    """Etiqueta legible del target/modo con el que se obtuvo un set de hallazgos."""
    target = fs.target or (meta or {}).get("target") or "—"
    mode = fs.target_mode or (meta or {}).get("target_mode") or "directed"
    run = fs.run_id or (meta or {}).get("run_id") or "?"
    return f"[{mode}] {target}  ([dim]{run}[/])"


@app.command("runs")
def list_runs() -> None:
    """Lista el historial de análisis (cada run con su ID)."""
    with handle_project_errors():
        project = project_mod.load_project()
        records = RunStore(project.hexflaw_dir).list_runs()
        latest = RunStore(project.hexflaw_dir).latest_id()

    if not records:
        console.success("Sin runs de análisis todavía.")
        return
    tbl = console.table("Historial de análisis", ["Run ID", "Fecha", "Target", "Hallazgos"])
    for r in records:
        rid = r.get("run_id", "?")
        mark = " [green](latest)[/]" if rid == latest else ""
        by = r.get("by_status", {})
        summary = " ".join(f"{k}:{v}" for k, v in by.items()) or "0"
        mode = r.get("target_mode") or "directed"
        tgt = r.get("target") or "—"
        tbl.add_row(
            f"[bold]{console.esc(rid)}[/]{mark}",
            console.esc((r.get("created_at") or "")[:19]),
            console.esc(f"[{mode}] {tgt}"[:40]),
            summary,
        )
    console.print_table(tbl)


@app.command("recheck")
def recheck_finding(finding_id: str = typer.Argument(..., help="ID del hallazgo a re-evaluar.")) -> None:
    """Re-ejecuta M5 sobre un único hallazgo (útil para needs_review/preliminary)."""
    with handle_project_errors():
        orchestrator = build_orchestrator()
        updated = console.live_run(
            orchestrator,
            lambda: orchestrator.recheck_finding(finding_id),
            title=f"HexFlaw · recheck {finding_id}",
        )
    console.success(
        f"{updated.id} re-evaluado → [bold]{updated.status.value}[/]"
    )
    _render_finding(updated, None)


@app.command("list")
def list_findings(
    status: str = typer.Option(None, "--status", help="Filtrar por estado."),
    run: str = typer.Option(None, "--run", help="Inspeccionar un run del historial."),
    all_runs: bool = typer.Option(
        False, "--all", help="Listar hallazgos de TODOS los runs (no solo el último)."
    ),
) -> None:
    """Lista hallazgos. Por defecto el último run; ``--all`` recorre todos los runs."""
    with handle_project_errors():
        project = project_mod.load_project()
        if all_runs:
            sets = _all_runs(project)
        elif run:
            store = RunStore(project.hexflaw_dir)
            meta = next((m for m in store.list_runs() if m.get("run_id") == run), {})
            sets = [(meta, store.load_run(run))]
        else:
            _, latest = _load_findings(None)
            sets = [({}, latest)]

    def _matches(f: Finding) -> bool:
        return not status or f.status.value == status

    total = sum(1 for _, fs in sets for f in fs.findings if _matches(f))
    if total == 0:
        console.success("Sin hallazgos para mostrar.")
        return

    if all_runs:
        # Cross-run: columna extra de target para saber de qué análisis viene cada uno.
        tbl = console.table(
            f"{total} hallazgo(s) en {len(sets)} run(s)",
            ["ID", "Estado", "Sev", "Tipo", "Ubicación", "Target (modo)"],
        )
        for meta, fs in sets:
            tgt = (fs.target or meta.get("target") or "—")
            mode = (fs.target_mode or meta.get("target_mode") or "directed")
            for f in fs.findings:
                if not _matches(f):
                    continue
                st = console.STATUS_STYLE.get(f.status.value, "white")
                sev = f.severity.value if f.severity else "—"
                sev_st = console.SEVERITY_STYLE.get(sev, "dim")
                tbl.add_row(
                    f.id,
                    f"[{st}]{f.status.value}[/]",
                    f"[{sev_st}]{sev}[/]",
                    console.esc(f.type),
                    console.esc(f"{f.file}:{f.line}"),
                    console.esc(f"[{mode}] {tgt}"[:40]),
                )
        console.print_table(tbl)
        return

    meta, fs = sets[0]
    console.info(f"[dim]Target:[/] {_target_label(fs, meta)}")
    tbl = console.table(
        f"{total} hallazgo(s)", ["ID", "Estado", "Sev", "Tipo", "Ubicación", "Conf"]
    )
    for f in fs.findings:
        if not _matches(f):
            continue
        st = console.STATUS_STYLE.get(f.status.value, "white")
        sev = f.severity.value if f.severity else "—"
        sev_st = console.SEVERITY_STYLE.get(sev, "dim")
        tbl.add_row(
            f.id,
            f"[{st}]{f.status.value}[/]",
            f"[{sev_st}]{sev}[/]",
            console.esc(f.type),
            console.esc(f"{f.file}:{f.line}"),
            f"{f.confidence:.2f}",
        )
    console.print_table(tbl)


@app.command("show")
def show_finding(
    finding_id: str = typer.Argument(..., help="ID del hallazgo (ej. 9c46-F006)."),
    run: str = typer.Option(None, "--run", help="Restringir a un run específico."),
) -> None:
    """Muestra el detalle de un hallazgo, buscándolo en TODOS los runs.

    Como los IDs son únicos por run (prefijo del run), no hace falta saber de qué
    análisis vino: la búsqueda recorre todo el historial.
    """
    with handle_project_errors():
        project = project_mod.load_project()
        if run:
            store = RunStore(project.hexflaw_dir)
            meta = next((m for m in store.list_runs() if m.get("run_id") == run), {})
            candidates = [(meta, store.load_run(run))]
        else:
            candidates = _all_runs(project)
            if not candidates and project.findings_path.exists():
                _, latest = _load_findings(None)
                candidates = [({}, latest)]

        found = None
        for meta, fs in candidates:
            match = next(
                (x for x in fs.findings if x.id.lower() == finding_id.lower()), None
            )
            if match is not None:
                found = (match, fs, meta)
                break
        if found is None:
            console.error(f"No existe el hallazgo '{finding_id}' en ningún run.")
            raise typer.Exit(code=1)
        finding, fset, meta = found
        root_cause = _load_root_cause(project, finding)

    console.info(f"[dim]Target del run:[/] {_target_label(fset, meta)}")
    _render_finding(finding, root_cause)


def _load_root_cause(project: project_mod.Project, finding: Finding) -> RootCause | None:
    """Carga el root cause de M6a si fue generado (``report``/``poc``)."""
    rc_path = project.hexflaw_dir / "findings" / f"{finding.id}_{finding.type}.json"
    if not rc_path.exists():
        return None
    try:
        return RootCause.model_validate(storage.read_json(rc_path))
    except (ValueError, OSError):
        return None


def _render_finding(finding: Finding, rc: RootCause | None) -> None:
    """Renderiza el detalle de un hallazgo (y su root cause si existe)."""
    st = console.STATUS_STYLE.get(finding.status.value, "white")
    sev = finding.severity.value if finding.severity else "—"
    sev_st = console.SEVERITY_STYLE.get(sev, "dim")
    console.kv_panel(
        f"[bold]{finding.id}[/] · {console.esc(finding.type)}",
        [
            ("Estado", f"[{st}]{finding.status.value}[/]"),
            ("Severidad", f"[{sev_st}]{sev}[/]"),
            ("Confianza", f"{finding.confidence:.2f}"),
            ("Ubicación", console.esc(f"{finding.file}:{finding.line}")),
            ("Función", console.esc(finding.function or "—")),
        ],
    )

    if finding.review_reason:
        console.warn(f"Necesita revisión: {console.esc(finding.review_reason)}")
        console.info("[dim]Re-evaluá con: [bold]hexflaw findings recheck "
                     f"{finding.id}[/][/]")

    if finding.snippet:
        console.info("\n[bold]Snippet:[/]")
        console.console.print(console.esc(finding.snippet), style="yellow")
    if finding.rationale:
        console.info(f"\n[bold]Razonamiento (LLM):[/] {console.esc(finding.rationale)}")

    if finding.taint_path:
        console.info("\n[bold]Taint path:[/]")
        for s in finding.taint_path:
            console.info(
                f"  [dim]{s.step}.[/] [cyan]{console.esc(s.function)}[/] "
                f"([dim]{console.esc(s.file)}[/]): {console.esc(s.note)}"
            )

    if rc is not None:
        console.info("")
        console.kv_panel(
            "Root cause (M6a)",
            [
                ("CVSS", f"{rc.cvss_score} {console.esc(rc.cvss_vector)}"),
                ("Causa raíz", console.esc(rc.root_cause or "—")),
                ("Remediación", console.esc(rc.remediation_summary or "—")),
            ],
            border="magenta",
        )
    elif finding.status.value in ("confirmed", "conditional"):
        console.info(
            "\n[dim]Genera causa raíz, CVSS y remediación con: [bold]hexflaw report[/][/]"
        )

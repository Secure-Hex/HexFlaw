"""HexFlaw TUI — Fase 1: scaffold + comandos (Textual).

Toma la terminal y expone los comandos read-only del proyecto desde un prompt
interno (status, findings, runs, show). Los comandos de análisis (analyze/ingest)
se integran en la Fase 2 con streaming del razonamiento del modelo.
"""

from __future__ import annotations

import json as _json
from typing import Any

from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import Footer, Header, Input, RichLog, Static

from hexflaw.core import project as project_mod
from hexflaw.core.models import FindingSet
from hexflaw.infrastructure import storage
from hexflaw.infrastructure.runs import RunStore
from hexflaw.tui.graph import GraphScreen

# Estilos de estado/severidad reutilizados (mismos colores que la CLI).
_STATUS_STYLE = {
    "confirmed": "bold red",
    "conditional": "yellow",
    "preliminary": "cyan",
    "needs_review": "magenta",
    "false_positive": "dim",
}
_SEV_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green"}

_HELP = """[b]Comandos disponibles[/b]
  [cyan]status[/]            estado del proyecto y artefactos
  [cyan]runs[/]              historial de análisis (con target y modo)
  [cyan]findings[/] [dim][--all][/]   hallazgos del último run (o de todos con --all)
  [cyan]show[/] <id>         detalle de un hallazgo (busca en todos los runs)
  [cyan]graph[/]             explorar el code graph (interactivo · hover sobre nodos)
  [cyan]analyze[/] [dim][target][/]  correr análisis con razonamiento del modelo en vivo
  [cyan]clear[/]             limpia la salida
  [cyan]help[/]              esta ayuda
  [cyan]quit[/] / q          salir
[dim]analyze / ingest llegan en la Fase 2 (con razonamiento del modelo en vivo).[/]"""


class HexFlawTUI(App[None]):
    """Aplicación TUI principal de HexFlaw."""

    CSS = """
    Screen { layout: vertical; }
    #body { height: 1fr; }
    #sidebar {
        width: 34;
        border: round $accent;
        padding: 0 1;
    }
    #output {
        width: 1fr;
        border: round $primary;
        padding: 0 1;
    }
    #cmd { dock: bottom; border: round $secondary; }
    """

    BINDINGS = [
        ("ctrl+c", "quit", "Salir"),
        ("ctrl+l", "clear_log", "Limpiar"),
    ]

    TITLE = "HexFlaw"
    SUB_TITLE = "TUI · análisis de vulnerabilidades"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="body"):
            yield Static(self._sidebar_renderable(), id="sidebar")
            yield RichLog(id="output", highlight=True, markup=True, wrap=True)
        yield Input(
            placeholder="comando  (help · status · findings [--all] · show <id> · runs · quit)",
            id="cmd",
        )
        yield Footer()

    def on_mount(self) -> None:
        log = self.query_one("#output", RichLog)
        log.write("[b]HexFlaw TUI[/b] — escribí [cyan]help[/] para ver los comandos.")
        try:
            project = project_mod.load_project()
            log.write(f"Proyecto: [b]{project.metadata.name}[/]  ([dim]{project.root}[/])")
        except Exception as exc:  # proyecto no detectado
            log.write(f"[yellow]Sin proyecto detectado:[/] {exc}")
        self.query_one("#cmd", Input).focus()

    # ----- acciones de bindings ------------------------------------------- #
    def action_clear_log(self) -> None:
        self.query_one("#output", RichLog).clear()

    # ----- input de comandos ---------------------------------------------- #
    def on_input_submitted(self, event: Input.Submitted) -> None:
        raw = event.value.strip()
        self.query_one("#cmd", Input).value = ""
        if raw:
            self._dispatch(raw)

    def _dispatch(self, raw: str) -> None:
        log = self.query_one("#output", RichLog)
        parts = raw.split()
        cmd, args = parts[0].lower(), parts[1:]
        log.write(f"[dim]›[/] [b]{cmd}[/] {' '.join(args)}".rstrip())
        try:
            if cmd in ("quit", "q", "exit"):
                self.exit()
            elif cmd in ("help", "h", "?"):
                log.write(_HELP)
            elif cmd == "clear":
                log.clear()
            elif cmd == "status":
                self._cmd_status(log)
            elif cmd == "runs":
                self._cmd_runs(log)
            elif cmd in ("findings", "list"):
                self._cmd_findings(log, "--all" in args)
            elif cmd == "show":
                if not args:
                    log.write("[red]uso: show <id>[/]")
                else:
                    self._cmd_show(log, args[0])
            elif cmd == "graph":
                self.push_screen(GraphScreen(project_mod.load_project()))
            elif cmd == "analyze":
                target = " ".join(args) if args else None
                log.write(
                    f"[b]▶ analyze[/] · target: [cyan]{target or 'discovery (auto)'}[/]"
                    " — [dim]razonamiento del modelo en vivo:[/]"
                )
                self._run_analyze(target)
            elif cmd == "ingest":
                log.write("[yellow]ingest desde la TUI llega luego; usá la CLI por ahora.[/]")
            else:
                log.write(f"[red]Comando desconocido:[/] {cmd}  ([dim]help[/])")
        except Exception as exc:  # nunca tumbar la TUI por un comando
            log.write(f"[red]Error:[/] {exc}")
        # refrescar el sidebar por si cambió algo
        self.query_one("#sidebar", Static).update(self._sidebar_renderable())

    # ----- comandos -------------------------------------------------------- #
    def _cmd_status(self, log: RichLog) -> None:
        project = project_mod.load_project()
        meta = project.metadata
        tbl = Table(show_header=False, box=None)
        tbl.add_row("Proyecto", f"[b]{meta.name}[/]")
        tbl.add_row("Root", str(project.root))
        tbl.add_row("Lenguajes", ", ".join(meta.languages) or "—")
        tbl.add_row("App type", getattr(meta.app_type, "value", str(meta.app_type)))
        log.write(Panel(tbl, title="status", border_style="green"))

    def _cmd_runs(self, log: RichLog) -> None:
        project = project_mod.load_project()
        store = RunStore(project.hexflaw_dir)
        records = store.list_runs()
        latest = store.latest_id()
        if not records:
            log.write("[green]Sin runs de análisis todavía.[/]")
            return
        tbl = Table(title="Historial de análisis")
        for col in ("Run ID", "Fecha", "Target (modo)", "Hallazgos"):
            tbl.add_column(col, overflow="fold")
        for r in records:
            rid = r.get("run_id", "?")
            mark = " [green](latest)[/]" if rid == latest else ""
            mode = r.get("target_mode") or "directed"
            tgt = r.get("target") or "—"
            by = r.get("by_status", {})
            summary = " ".join(f"{k}:{v}" for k, v in by.items()) or "0"
            tbl.add_row(f"{rid}{mark}", (r.get("created_at") or "")[:19],
                        f"[{mode}] {tgt}"[:40], summary)
        log.write(tbl)

    def _cmd_findings(self, log: RichLog, all_runs: bool) -> None:
        project = project_mod.load_project()
        if all_runs:
            from hexflaw.cli.commands.findings import _all_runs
            sets = _all_runs(project)
        else:
            if not project.findings_path.exists():
                log.write("[yellow]No hay hallazgos. Corré 'analyze' primero.[/]")
                return
            sets = [({}, FindingSet.model_validate(storage.read_json(project.findings_path)))]

        rows = [(meta, f) for meta, fs in sets for f in fs.findings]
        if not rows:
            log.write("[green]Sin hallazgos para mostrar.[/]")
            return
        tbl = Table(title=f"{len(rows)} hallazgo(s)" + (" · todos los runs" if all_runs else ""))
        cols = ["ID", "Estado", "Sev", "Tipo", "Ubicación"]
        if all_runs:
            cols.append("Target")
        for c in cols:
            tbl.add_column(c, overflow="fold")
        for meta, f in rows:
            st = _STATUS_STYLE.get(f.status.value, "white")
            sev = f.severity.value if f.severity else "—"
            sev_st = _SEV_STYLE.get(sev, "dim")
            cells: list[str | Text] = [
                f.id,
                Text(f.status.value, style=st),
                Text(sev, style=sev_st),
                f.type,
                f"{f.file}:{f.line}",
            ]
            if all_runs:
                fs_for = next(fs for m, fs in sets if m is meta)
                cells.append(((fs_for.target or meta.get("target") or "—"))[:30])
            tbl.add_row(*cells)
        log.write(tbl)

    def _cmd_show(self, log: RichLog, finding_id: str) -> None:
        project = project_mod.load_project()
        from hexflaw.cli.commands.findings import _all_runs, _target_label

        candidates = _all_runs(project)
        if not candidates and project.findings_path.exists():
            candidates = [({}, FindingSet.model_validate(storage.read_json(project.findings_path)))]
        found = None
        for meta, fs in candidates:
            match = next((x for x in fs.findings if x.id.lower() == finding_id.lower()), None)
            if match:
                found = (match, fs, meta)
                break
        if found is None:
            log.write(f"[red]No existe el hallazgo '{finding_id}' en ningún run.[/]")
            return
        f, fs, meta = found
        st = _STATUS_STYLE.get(f.status.value, "white")
        body = Table(show_header=False, box=None)
        body.add_row("Estado", Text(f.status.value, style=st))
        body.add_row("Severidad", f.severity.value if f.severity else "—")
        body.add_row("Confianza", f"{f.confidence:.2f}")
        body.add_row("Ubicación", f"{f.file}:{f.line}")
        body.add_row("Función", f.function or "—")
        body.add_row("Target del run", _target_label(fs, meta))
        if f.rationale:
            body.add_row("Razonamiento", f.rationale)
        log.write(Panel(body, title=f"{f.id} · {f.type}", border_style="magenta"))
        if f.snippet:
            log.write(Panel(f.snippet, title="snippet", border_style="yellow"))

    # ----- análisis con razonamiento en vivo (Fase 2) --------------------- #
    @work(thread=True, exclusive=True, group="analyze")
    def _run_analyze(self, target: str | None) -> None:
        """Corre el análisis en un thread y streamea el razonamiento del modelo.

        Engancha ``llm.trace`` para recibir, por cada llamada (M4/M5), el prompt,
        la respuesta y el veredicto, y los vuelca en la UI vía ``call_from_thread``.
        """
        from hexflaw.cli.helpers import build_orchestrator

        try:
            orch = build_orchestrator()
        except Exception as exc:  # proyecto/config
            self.call_from_thread(self._log_line, f"[red]No se pudo iniciar: {exc}[/]")
            return
        orch.llm.trace = lambda ev: self.call_from_thread(self._on_trace, ev)
        try:
            findings = orch.run_analyze(target)
            self.call_from_thread(self._analyze_done, findings)
        except Exception as exc:
            self.call_from_thread(self._log_line, f"[red]Análisis falló: {exc}[/]")
        finally:
            orch.llm.trace = None

    def _log_line(self, text: str) -> None:
        self.query_one("#output", RichLog).write(text)

    def _on_trace(self, ev: dict[str, Any]) -> None:
        """Renderiza un evento de traza del LLM (prompt + razonamiento + veredicto)."""
        resp = ev.get("response", "") or ""
        verdict, rationale = "", resp
        # M5/M4 responden JSON; extraer veredicto y razonamiento si se puede.
        try:
            data = _json.loads(resp[resp.find("{") : resp.rfind("}") + 1])
            if isinstance(data, dict):
                verdict = str(data.get("status", "") or "")
                rationale = str(data.get("rationale") or data.get("note") or resp)
        except Exception:
            pass
        prompt = ev.get("prompt", "")
        body = Table(show_header=False, box=None)
        body.add_row(
            "[dim]modelo[/]",
            f"{ev.get('model', '')}  "
            f"([dim]{ev.get('input_tokens', 0)}+{ev.get('output_tokens', 0)} tok[/])",
        )
        body.add_row("[dim]prompt[/]", prompt[:500] + ("…" if len(prompt) > 500 else ""))
        body.add_row(
            "[dim]razonamiento[/]",
            rationale[:700] + ("…" if len(rationale) > 700 else ""),
        )
        if verdict:
            body.add_row("[dim]veredicto[/]", Text(verdict, style=_STATUS_STYLE.get(verdict, "white")))
        border = {
            "confirmed": "red", "conditional": "yellow",
            "false_positive": "grey50", "needs_review": "magenta",
        }.get(verdict, "cyan")
        self.query_one("#output", RichLog).write(
            Panel(body, title=ev.get("label") or ev.get("model"), border_style=border)
        )

    def _analyze_done(self, findings: FindingSet) -> None:
        n = len(findings.findings)
        conf = sum(1 for f in findings.findings if f.status.value == "confirmed")
        self.query_one("#output", RichLog).write(
            f"[b green]✓ análisis completo[/] — {n} hallazgo(s), {conf} confirmado(s). "
            "Escribí [cyan]findings[/] para verlos."
        )
        self.query_one("#sidebar", Static).update(self._sidebar_renderable())

    # ----- sidebar --------------------------------------------------------- #
    def _sidebar_renderable(self) -> Table:
        tbl = Table(show_header=False, box=None, padding=0)
        try:
            project = project_mod.load_project()
            meta = project.metadata
            store = RunStore(project.hexflaw_dir)
            latest = store.latest_id()
            tbl.add_row("[b]Proyecto[/]")
            tbl.add_row(f" {meta.name}")
            tbl.add_row(f"[dim] {', '.join(meta.languages) or '—'}[/]")
            tbl.add_row("")
            tbl.add_row("[b]Artefactos[/]")
            for label, path in (
                ("ingestión", project.chunks_path),
                ("code_graph", project.hexflaw_dir / "code_graph.json"),
                ("findings", project.findings_path),
            ):
                mark = "[green]✓[/]" if path.exists() else "[dim]·[/]"
                tbl.add_row(f" {mark} {label}")
            tbl.add_row("")
            tbl.add_row(f"[b]Último run[/]\n [dim]{latest or '—'}[/]")
        except Exception:
            tbl.add_row("[yellow]Sin proyecto[/]")
            tbl.add_row("[dim]corré 'hexflaw init'[/]")
        return tbl


def run_tui() -> None:
    """Lanza la TUI de HexFlaw."""
    HexFlawTUI().run()

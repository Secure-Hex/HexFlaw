"""Comando ``hexflaw agent`` — conducir el backend LLM "agente en el loop".

Cuando ``llm_backend = "agent"`` (ver :class:`AgentQueueLLMService`), el pipeline
parkea cada prompt como un request JSON en una cola en disco y se bloquea esperando
la respuesta. Estos comandos permiten a un agente externo (p.ej. Claude Code)
listar los requests pendientes, leer el prompt y dejar la respuesta — sin consumir
créditos de ninguna API.

Flujo típico (en otra terminal, con ``hexflaw analyze --llm-backend agent`` corriendo):

    hexflaw agent pending            # ver qué requests esperan
    hexflaw agent show <id>          # leer system + prompt (verbatim, --json)
    hexflaw agent answer <id> --file resp.json   # dejar la respuesta (text=...)

La respuesta es el JSON ``{"text": "<lo que devolvería el modelo>"}``; ese ``text``
debe ser exactamente lo que el módulo (M2/M4/M5/M6) espera parsear.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import typer

from hexflaw.cli import console
from hexflaw.cli.helpers import resolve_active_config
from hexflaw.infrastructure import config as config_mod
from hexflaw.services import agent_registry
from hexflaw.services.agent_registry import AgentCLI
from hexflaw.services.llm_service import AgentQueueLLMService

app = typer.Typer(
    name="agent",
    help="Conducir el backend LLM 'agente en el loop' (cola de archivos, sin tokens).",
    no_args_is_help=True,
)


def _queue_dir() -> Path:
    """Resuelve el directorio de la cola igual que :func:`build_llm_service`."""
    cfg = resolve_active_config()
    raw = cfg.get("agent_queue_dir") or str(config_mod.global_home() / "agent_queue")
    return Path(raw).expanduser()


def _pending_requests(queue: Path) -> list[dict[str, Any]]:
    """Lista los requests sin respuesta aún, ordenados por antigüedad."""
    if not queue.exists():
        return []
    pending: list[dict[str, Any]] = []
    for req_path in sorted(queue.glob("req-*.json")):
        req_id = req_path.stem[len("req-"):]
        if (queue / f"res-{req_id}.json").exists():
            continue  # ya respondido, aún no archivado por el pipeline
        try:
            data = json.loads(req_path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue
        data["_path"] = str(req_path)
        pending.append(data)
    return pending


@app.command("status")
def status() -> None:
    """Muestra el directorio de la cola y cuántos requests están pendientes."""
    queue = _queue_dir()
    pending = _pending_requests(queue)
    console.kv_panel(
        "Agent queue",
        [
            ("queue_dir", console.esc(queue)),
            ("existe", "sí" if queue.exists() else "no"),
            ("pendientes", str(len(pending))),
        ],
    )


@app.command("pending")
def pending(
    as_json: bool = typer.Option(False, "--json", help="Salida JSON (para scripting)."),
) -> None:
    """Lista los requests que esperan respuesta del agente."""
    queue = _queue_dir()
    items = _pending_requests(queue)
    if as_json:
        slim = [
            {
                "id": d.get("id"),
                "label": d.get("label", ""),
                "model": d.get("model", ""),
                "prompt_chars": len(d.get("prompt", "")),
                "created_at": d.get("created_at"),
            }
            for d in items
        ]
        typer.echo(json.dumps(slim, ensure_ascii=False, indent=2))
        return
    if not items:
        console.info("[dim]No hay requests pendientes.[/]")
        return
    now = time.time()
    tbl = console.table(f"Requests pendientes ({len(items)})", ["ID", "Tarea", "Modelo", "Edad", "Prompt"])
    for d in items:
        age = now - float(d.get("created_at") or now)
        tbl.add_row(
            console.esc(d.get("id", "")),
            console.esc(d.get("label", "") or "—"),
            console.esc(d.get("model", "")),
            f"{age:.0f}s",
            f"{len(d.get('prompt', '')):,} ch",
        )
    console.print_table(tbl)


@app.command("show")
def show(
    request_id: str = typer.Argument(..., help="ID del request (ver 'agent pending')."),
    as_json: bool = typer.Option(False, "--json", help="Volcar el request JSON completo."),
) -> None:
    """Imprime el request (system + prompt) verbatim para que el agente lo razone."""
    queue = _queue_dir()
    req_path = queue / f"req-{request_id}.json"
    if not req_path.exists():
        console.error(f"No existe el request '{request_id}' en {console.esc(queue)}.")
        raise typer.Exit(code=1)
    data = json.loads(req_path.read_text(encoding="utf-8"))
    if as_json:
        typer.echo(json.dumps(data, ensure_ascii=False, indent=2))
        return
    # Verbatim por stdout plano: el contenido es código/prompt, sin markup de rich.
    typer.echo(f"=== request {data.get('id')} · {data.get('label','')} ===")
    typer.echo(f"--- model: {data.get('model','')}  max_tokens: {data.get('max_tokens','')}")
    typer.echo("--- system ---")
    typer.echo(data.get("system", ""))
    typer.echo("--- prompt ---")
    typer.echo(data.get("prompt", ""))


@app.command("answer")
def answer(
    request_id: str = typer.Argument(..., help="ID del request a responder."),
    file: Path = typer.Option(
        None, "--file", "-f", help="Archivo con la respuesta (JSON {text:...} o texto plano)."
    ),
    text: str = typer.Option(
        None, "--text", "-t", help="Respuesta como texto directo (alternativa a --file/stdin)."
    ),
) -> None:
    """Deja la respuesta del agente para un request; el pipeline la recoge y sigue.

    La fuente de la respuesta (en orden de precedencia): ``--text`` > ``--file`` >
    STDIN. Si el contenido ya es un JSON ``{"text": ...}`` se usa tal cual; si es
    texto plano se envuelve como ``{"text": "<contenido>"}``.
    """
    queue = _queue_dir()
    req_path = queue / f"req-{request_id}.json"
    if not req_path.exists():
        console.error(f"No existe el request '{request_id}' en {console.esc(queue)}.")
        raise typer.Exit(code=1)

    if text is not None:
        raw = text
    elif file is not None:
        raw = file.read_text(encoding="utf-8")
    else:
        raw = sys.stdin.read()
    if not raw.strip():
        console.error("Respuesta vacía: provee --text, --file o contenido por STDIN.")
        raise typer.Exit(code=1)

    # Acepta tanto un JSON {text, input_tokens?, output_tokens?} como texto plano.
    payload: dict[str, Any]
    try:
        parsed = json.loads(raw)
        payload = parsed if isinstance(parsed, dict) and "text" in parsed else {"text": raw}
    except json.JSONDecodeError:
        payload = {"text": raw}
    payload["id"] = request_id

    res_path = queue / f"res-{request_id}.json"
    AgentQueueLLMService._write_atomic(res_path, payload)
    console.success(
        f"Respuesta entregada para [bold]{console.esc(request_id)}[/] "
        f"({len(payload['text']):,} ch). El pipeline continuará."
    )


def _run_agent(agent: AgentCLI | None, custom_cmd: str | None, req: dict[str, Any], timeout: float) -> str:
    """Ejecuta UN request en un proceso nuevo y devuelve el texto de la respuesta.

    Proceso nuevo por request a propósito: es lo que hace que cada batch se analice
    con el contexto limpio, igual que una llamada a la API. Un único agente
    respondiendo la cola entera arrastra en su ventana todo lo que ya vio, y las
    respuestas del batch 30 salen condicionadas por los 29 anteriores.

    Args:
        agent: CLI a invocar, o ``None`` si se usa ``custom_cmd``.
        custom_cmd: Comando propio (recibe el system en ``HEXFLAW_SYSTEM``).
        req: Request de la cola (con ``system`` y ``prompt``).
        timeout: Segundos máximos para esta invocación.

    Returns:
        Texto crudo que imprimió el agente.

    Raises:
        RuntimeError: Si el agente falla, expira o no imprime nada.
    """
    system = str(req.get("system", ""))
    prompt = str(req.get("prompt", ""))

    if custom_cmd:
        argv = ["bash", "-c", custom_cmd]
        stdin = prompt
        env = {**os.environ, "HEXFLAW_SYSTEM": system}
    elif agent is not None:
        argv = agent.argv(system)
        stdin = agent.stdin_for(system, prompt)
        env = dict(os.environ)
    else:  # pragma: no cover - lo impide la validación del comando
        raise RuntimeError("sin agente ni --cmd")

    try:
        proc = subprocess.run(
            argv, input=stdin, capture_output=True, text=True, timeout=timeout, env=env
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"timeout de {timeout:.0f}s") from exc
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"no se pudo ejecutar: {exc}") from exc

    if proc.returncode != 0:
        detail = (proc.stderr or "").strip().splitlines()
        raise RuntimeError(f"exit {proc.returncode}: {detail[-1] if detail else 'sin stderr'}")
    if not proc.stdout.strip():
        raise RuntimeError("el agente no imprimió nada")
    return proc.stdout


def _deliver(queue: Path, request_id: str, raw: str) -> None:
    """Escribe la respuesta de un request en la cola (mismo formato que 'answer')."""
    payload: dict[str, Any]
    try:
        parsed = json.loads(raw)
        payload = parsed if isinstance(parsed, dict) and "text" in parsed else {"text": raw}
    except json.JSONDecodeError:
        payload = {"text": raw}
    payload["id"] = request_id
    AgentQueueLLMService._write_atomic(queue / f"res-{request_id}.json", payload)


@app.command("drain")
def drain(
    agent_id: str = typer.Option(
        None,
        "--agent",
        help="claude | codex | opencode | qwen | gemini. Por defecto, el primero instalado.",
    ),
    cmd: str = typer.Option(
        None, "--cmd", help="Comando propio en vez de un CLI conocido (system en $HEXFLAW_SYSTEM)."
    ),
    workers: int = typer.Option(
        4, "--workers", "-w", help="Requests en paralelo, cada uno en su propio proceso."
    ),
    once: bool = typer.Option(False, "--once", help="Procesa lo pendiente y sale."),
    interval: float = typer.Option(2.0, "--interval", help="Segundos entre sondeos de la cola."),
    timeout: float = typer.Option(600.0, "--timeout", help="Segundos máximos por request."),
) -> None:
    """Responde la cola del backend 'agent' repartiendo cada batch a un proceso nuevo.

    Es el otro lado de ``hexflaw analyze --llm-backend agent``: mientras el análisis
    espera bloqueado, este comando toma los requests y los reparte.

    Cada request corre en su **propio proceso**, así que llega con el contexto
    limpio — como una llamada a la API. Y ``--workers`` los corre en paralelo, que
    es lo que hace tolerable el arranque en frío de estos CLIs: si cada invocación
    tarda medio minuto en levantar, hacerlas de a una convierte un análisis en una
    tarde.
    """
    if workers < 1:
        console.error("--workers tiene que ser al menos 1.")
        raise typer.Exit(code=1)

    agent: AgentCLI | None = None
    if cmd is None:
        if agent_id:
            agent = agent_registry.resolve(agent_id)
            if agent is None:
                console.error(
                    f"Agente desconocido: '{agent_id}'. "
                    f"Opciones: {', '.join(sorted(agent_registry.BY_ID))}"
                )
                raise typer.Exit(code=1)
            if shutil.which(agent.binary) is None:
                console.error(f"'{agent.binary}' no está en el PATH: {agent.name} no está instalado.")
                raise typer.Exit(code=1)
        else:
            found = agent_registry.detect()
            if not found.any_installed:
                console.error(
                    "No se encontró ningún CLI de agente instalado. "
                    "Instalá uno o pasá --cmd '<comando>'."
                )
                raise typer.Exit(code=1)
            agent = found.installed[0]

    queue = _queue_dir()
    label = cmd if cmd else (agent.name if agent else "?")
    console.info(
        f"Drenando [bold]{console.esc(queue)}[/] con [bold]{console.esc(label)}[/] "
        f"· {workers} en paralelo · un proceso nuevo por request"
    )

    # Los ids ya tomados. Con un solo proceso de drenado alcanza un set en memoria;
    # dos drenados sobre la misma cola duplicarían trabajo (no corrompen nada, pero
    # gastan el doble), así que no lo hagas.
    claimed: set[str] = set()
    done = 0
    failed = 0

    def handle(req: dict[str, Any]) -> tuple[str, str | None]:
        rid = str(req.get("id", ""))
        try:
            raw = _run_agent(agent, cmd, req, timeout)
        except RuntimeError as exc:
            return rid, str(exc)
        _deliver(queue, rid, raw)
        return rid, None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        while True:
            batch = [r for r in _pending_requests(queue) if str(r.get("id")) not in claimed]
            if batch:
                for req in batch:
                    claimed.add(str(req.get("id")))
                for rid, error in pool.map(handle, batch):
                    if error is None:
                        done += 1
                        console.success(f"{rid} respondido")
                    else:
                        failed += 1
                        # El request queda pendiente: la próxima vuelta lo reintenta.
                        claimed.discard(rid)
                        console.warn(f"{rid} falló ({error}); queda pendiente")
            if once:
                break
            time.sleep(interval)

    console.info(f"[dim]{done} respondidos · {failed} fallidos[/]")

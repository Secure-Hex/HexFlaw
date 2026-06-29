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
import sys
import time
from pathlib import Path

import typer

from hexflaw.cli import console
from hexflaw.cli.helpers import resolve_active_config
from hexflaw.infrastructure import config as config_mod
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


def _pending_requests(queue: Path) -> list[dict]:
    """Lista los requests sin respuesta aún, ordenados por antigüedad."""
    if not queue.exists():
        return []
    pending: list[dict] = []
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
    payload: dict
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

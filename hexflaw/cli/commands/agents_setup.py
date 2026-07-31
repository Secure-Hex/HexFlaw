"""Comando ``hexflaw agents-install`` — integra HexFlaw con los agentes instalados.

Detecta qué CLIs de agente hay en el sistema (Claude Code, Codex, opencode, Qwen,
Gemini) e instala en cada uno un slash command que corre el análisis usando ese
agente como motor LLM, vía el backend ``agent``. El costo va por la suscripción que
ya tenés, no por la API.

El comando instalado **no razona el análisis en su propia ventana**: lanza
``hexflaw agent drain``, que reparte cada batch a un proceso nuevo. Un agente
respondiendo la cola entera arrastra en su contexto todo lo que ya vio, y para el
batch 30 está decidiendo condicionado por los 29 anteriores. La API no funciona
así, y el análisis tampoco debería.
"""

from __future__ import annotations

from pathlib import Path

import typer

from hexflaw.cli import console
from hexflaw.services import agent_registry
from hexflaw.services.agent_registry import AgentCLI

#: Cuerpo del slash command. Es el mismo para todos los agentes porque el trabajo
#: real lo hace 'agent drain': el agente que recibe el slash command solo orquesta.
_BODY = """Sos el orquestador de un análisis de seguridad con HexFlaw en este repositorio.
El usuario ya corrió `hexflaw ingest` acá.

Funcionalidad a analizar (target, opcional): $ARGUMENTS

NO analices el código vos mismo. Tu trabajo es lanzar dos procesos y reportar el
resultado; cada llamada LLM la responde un proceso agente nuevo, con contexto limpio.

Pasos:

1. Lanzá el análisis EN SEGUNDO PLANO (se bloquea esperando la cola):
   - con target:  `hexflaw analyze --llm-backend agent --target "$ARGUMENTS"`
   - sin target:  `hexflaw analyze --llm-backend agent`
   Dejá el embedding local (default `local-cpu`) para no gastar API.

2. Lanzá el drenado de la cola EN SEGUNDO PLANO, que responde cada request en su
   propio proceso y en paralelo:
   `hexflaw agent drain --agent {agent_id} --workers 4`

3. Monitoreá hasta que el analyze termine (`hexflaw agent status` muestra los
   pendientes). Cuando no queden pendientes y analyze haya salido, frená el drenado.

4. Mostrá el resultado: `hexflaw findings list` y, para cada confirmado relevante,
   `hexflaw findings show <ID>` — que incluye la traza de evidencia (qué source, qué
   sink, qué sanitizer, y qué parte fue determinística vs LLM).

Si preferís hacerlo a mano, el flujo equivalente en dos terminales es:
  terminal 1: hexflaw analyze --llm-backend agent
  terminal 2: hexflaw agent drain --agent {agent_id} --workers 4
"""

_TOML_TEMPLATE = '''description = "{description}"

prompt = """
{body}
"""
'''

_MD_TEMPLATE = """---
description: {description}
---

{body}"""

_DESCRIPTION = (
    "Corre HexFlaw usando este agente como motor LLM (sin costo de API). "
    "Requiere 'hexflaw ingest' previo."
)


def _render(agent: AgentCLI) -> str:
    """Genera el contenido del slash command en el formato que usa ese CLI."""
    body = _BODY.format(agent_id=agent.id)
    if agent.command_format == "toml":
        # Las comillas triples del bloque TOML no pueden aparecer en el cuerpo.
        return _TOML_TEMPLATE.format(description=_DESCRIPTION, body=body.replace('"""', "'''"))
    return _MD_TEMPLATE.format(description=_DESCRIPTION, body=body)


def _install_for(agent: AgentCLI, name: str) -> Path:
    """Escribe el slash command de un agente y devuelve la ruta."""
    dest = agent.command_path(name)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(_render(agent), encoding="utf-8")
    return dest


def agents_install_command(
    name: str = typer.Option("hexflaw", "--name", help="Nombre del slash command."),
    only: str | None = typer.Option(
        None, "--only", help="Instalar solo en este agente (id). Por defecto, en todos."
    ),
    list_only: bool = typer.Option(
        False, "--list", help="Solo mostrar qué agentes se detectaron, sin instalar."
    ),
) -> None:
    """Detecta los CLIs de agente instalados e integra HexFlaw con todos."""
    found = agent_registry.detect()

    tbl = console.table("Agentes detectados", ["Agente", "Binario", "Estado"])
    for agent in found.installed:
        tbl.add_row(console.esc(agent.name), console.esc(agent.binary), "[green]instalado[/]")
    for agent in found.missing:
        tbl.add_row(console.esc(agent.name), console.esc(agent.binary), "[dim]no encontrado[/]")
    console.print_table(tbl)

    if list_only:
        return

    if not found.any_installed:
        console.error(
            "No se detectó ningún CLI de agente. Instalá alguno (Claude Code, Codex, "
            "opencode, Qwen, Gemini) o usá el backend 'api' con tu API key."
        )
        raise typer.Exit(code=1)

    targets = found.installed
    if only:
        targets = [a for a in found.installed if a.id == only]
        if not targets:
            console.error(
                f"'{only}' no está entre los agentes instalados: "
                f"{', '.join(a.id for a in found.installed) or 'ninguno'}"
            )
            raise typer.Exit(code=1)

    unverified: list[AgentCLI] = []
    for agent in targets:
        try:
            dest = _install_for(agent, name)
        except OSError as exc:
            # Un agente que falla no puede impedir la integración con los demás.
            console.warn(f"{agent.name}: no se pudo instalar ({exc})")
            continue
        console.success(f"{agent.name}: [dim]{console.esc(dest)}[/]")
        if not agent.verified:
            unverified.append(agent)

    if unverified:
        # Decirlo importa: un archivo que el CLI no lee es indistinguible de uno que
        # sí, hasta que tipeás el slash command y no aparece.
        console.warn(
            "Formato de comando no verificado contra una instalación real en: "
            + ", ".join(a.name for a in unverified)
            + ". Si el slash command no aparece, el flujo manual funciona igual."
        )

    ids = [a.id for a in targets]
    console.info("")
    console.info("Flujo:")
    console.info("  1. En la terminal:   [bold]hexflaw ingest ./codigo[/]")
    console.info(f"  2. En tu agente:     [bold]/{name} <target>[/]")
    console.info("")
    console.info("O a mano, en dos terminales:")
    console.info("  [bold]hexflaw analyze --llm-backend agent[/]")
    console.info(f"  [bold]hexflaw agent drain --agent {ids[0]} --workers 4[/]")
    console.info(
        "[dim]Cada batch lo responde un proceso nuevo: contexto limpio por llamada, "
        "como la API.[/]"
    )


def claude_install_command(
    global_install: bool = typer.Option(
        False, "--global", help="Ignorado: la instalación siempre es a nivel usuario."
    ),
    name: str = typer.Option("hexflaw", "--name", help="Nombre del slash command."),
) -> None:
    """Alias deprecado de ``agents-install`` (solo Claude Code)."""
    console.warn(
        "'claude-install' quedó deprecado: usá [bold]hexflaw agents-install[/], que "
        "detecta e integra todos los agentes instalados, no solo Claude Code."
    )
    agents_install_command(name=name, only="claude", list_only=False)

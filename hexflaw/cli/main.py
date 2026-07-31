"""Entrypoint Typer de HexFlaw (CLAUDE.md §10, §11).

Registra los subcomandos del slice vertical. La CLI solo invoca al Core Engine;
nunca contiene lógica de negocio.
"""

from __future__ import annotations

import typer

from hexflaw.cli.commands.agent import app as agent_app
from hexflaw.cli.commands.agents_setup import (
    agents_install_command,
    claude_install_command,
)
from hexflaw.cli.commands.analyze import analyze_command
from hexflaw.cli.commands.config import config_command
from hexflaw.cli.commands.findings import app as findings_app
from hexflaw.cli.commands.graph import graph_command
from hexflaw.cli.commands.ingest import ingest_command
from hexflaw.cli.commands.init import init_command
from hexflaw.cli.commands.languages import app as languages_app
from hexflaw.cli.commands.models import app as models_app
from hexflaw.cli.commands.poc import poc_command
from hexflaw.cli.commands.report import report_command
from hexflaw.cli.commands.run import run_command
from hexflaw.cli.commands.setup import setup_command
from hexflaw.cli.commands.status import status_command
from hexflaw.cli.commands.tui import tui_command

app = typer.Typer(
    name="hexflaw",
    help="HexFlaw — AI-powered source code vulnerability analyzer (SecureHex).",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)

app.command("setup")(setup_command)
app.command("init")(init_command)
app.command("ingest")(ingest_command)
app.command("analyze")(analyze_command)
app.command("report")(report_command)
app.command("poc")(poc_command)
app.command("run")(run_command)
app.command("graph")(graph_command)
app.command("status")(status_command)
app.command("config")(config_command)
app.command("agents-install")(agents_install_command)
app.command("claude-install", hidden=True)(claude_install_command)
app.command("tui")(tui_command)
app.add_typer(languages_app, name="languages")
app.add_typer(findings_app, name="findings")
app.add_typer(agent_app, name="agent")
app.add_typer(models_app, name="models")


if __name__ == "__main__":
    app()

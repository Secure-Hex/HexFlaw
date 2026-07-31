"""Registro de CLIs de agentes que pueden actuar como motor LLM de HexFlaw.

El backend ``agent`` (ver :class:`~hexflaw.services.llm_service.AgentQueueLLMService`)
parkea cada llamada como un request en disco y espera la respuesta. Cualquier CLI
de agente con modo headless puede responderla, así que el pipeline corre sin gastar
créditos de API: el costo va por la suscripción que ya tenés.

Este módulo sabe dos cosas de cada CLI: **cómo invocarlo headless** (para que el
drenado de la cola sea automático) y **dónde viven sus slash commands** (para
instalar la integración).

El prompt SIEMPRE va por STDIN, nunca como argumento. Es una cicatriz real: los
prompts de M5 llevan el code graph y el taint path, y pasarlos por ``argv`` los
hacía reventar con *argument list too long* a mitad de un análisis largo.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class AgentCLI:
    """Cómo detectar, invocar e integrar un CLI de agente.

    Attributes:
        id: Identificador corto (``claude``, ``codex``, ...).
        name: Nombre para mostrar.
        binary: Ejecutable a buscar en el PATH.
        args: Argumentos fijos del modo headless. El prompt va por STDIN.
        system_flag: Flag que recibe el system prompt. ``None`` si el CLI no
            separa system de user: en ese caso se antepone al prompt en el STDIN.
        commands_dir: Dónde instalar el slash command (relativo al home).
        command_format: ``markdown`` (frontmatter + cuerpo) o ``toml``.
        verified: Si el formato del slash command está confirmado contra una
            instalación real. Los no verificados siguen la documentación del
            proyecto, y el comando lo dice en vez de afirmar que quedó andando.
    """

    id: str
    name: str
    binary: str
    args: tuple[str, ...]
    system_flag: str | None
    commands_dir: Path
    command_format: str = "markdown"
    verified: bool = True
    notes: str = ""

    def command_path(self, name: str) -> Path:
        """Ruta del archivo de slash command para este CLI."""
        suffix = ".toml" if self.command_format == "toml" else ".md"
        return self.commands_dir.expanduser() / f"{name}{suffix}"

    def argv(self, system: str) -> list[str]:
        """Arma el comando completo para una invocación headless.

        Args:
            system: System prompt del request.

        Returns:
            ``argv`` listo para :func:`subprocess.run`. El prompt va por STDIN.
        """
        argv = [self.binary, *self.args]
        if self.system_flag is not None:
            argv += [self.system_flag, system]
        return argv

    def stdin_for(self, system: str, prompt: str) -> str:
        """Contenido de STDIN: el prompt, con el system adelante si no hay flag."""
        if self.system_flag is not None:
            return prompt
        return f"{system}\n\n{prompt}"


#: CLIs conocidos. Agregar uno es sumar una entrada acá: el drenado y la
#: instalación lo toman solos.
KNOWN_AGENTS: tuple[AgentCLI, ...] = (
    AgentCLI(
        id="claude",
        name="Claude Code",
        binary="claude",
        # --max-turns 1 y sin tools: queremos UNA respuesta de razonamiento, no que
        # se ponga a explorar el repo. El pipeline ya le da el contexto que precisa.
        args=("-p", "--output-format", "text", "--max-turns", "1", "--allowedTools", ""),
        system_flag="--append-system-prompt",
        commands_dir=Path("~/.claude/commands"),
    ),
    AgentCLI(
        id="codex",
        name="Codex CLI",
        binary="codex",
        # '-' fuerza la lectura del prompt por STDIN. read-only porque el agente
        # solo tiene que razonar sobre el código que ya viene en el prompt.
        args=("exec", "--skip-git-repo-check", "-s", "read-only", "-"),
        system_flag=None,
        commands_dir=Path("~/.codex/prompts"),
        verified=False,
        notes="Prompts custom en ~/.codex/prompts (según la doc de Codex).",
    ),
    AgentCLI(
        id="opencode",
        name="opencode",
        binary="opencode",
        args=("run",),
        system_flag=None,
        commands_dir=Path("~/.config/opencode/commands"),
    ),
    AgentCLI(
        id="qwen",
        name="Qwen Code",
        binary="qwen",
        args=("--approval-mode", "plan"),
        system_flag="--append-system-prompt",
        commands_dir=Path("~/.qwen/commands"),
        command_format="toml",
        verified=False,
        notes="Fork de Gemini CLI: comandos TOML en ~/.qwen/commands.",
    ),
    AgentCLI(
        id="gemini",
        name="Gemini CLI",
        binary="gemini",
        args=("--approval-mode", "plan"),
        system_flag=None,
        commands_dir=Path("~/.gemini/commands"),
        command_format="toml",
        verified=False,
        notes="Comandos TOML en ~/.gemini/commands.",
    ),
)

#: Índice por id para lookup directo.
BY_ID: dict[str, AgentCLI] = {agent.id: agent for agent in KNOWN_AGENTS}


@dataclass
class Detection:
    """Resultado de escanear el sistema por CLIs de agentes."""

    installed: list[AgentCLI] = field(default_factory=list)
    missing: list[AgentCLI] = field(default_factory=list)

    @property
    def any_installed(self) -> bool:
        """Indica si se encontró al menos un agente utilizable."""
        return bool(self.installed)


def detect(agents: tuple[AgentCLI, ...] | None = None) -> Detection:
    """Busca en el PATH cuáles de los CLIs conocidos están instalados.

    El universo se resuelve en la llamada y no como default del parámetro: un
    default lo congelaría al importar el módulo, y cualquier extensión posterior
    del registro quedaría invisible para quien ya lo había importado.

    Args:
        agents: Universo de agentes a considerar. ``None`` usa :data:`KNOWN_AGENTS`.

    Returns:
        La :class:`Detection` con instalados y faltantes.
    """
    result = Detection()
    for agent in agents if agents is not None else KNOWN_AGENTS:
        if shutil.which(agent.binary):
            result.installed.append(agent)
        else:
            result.missing.append(agent)
    return result


def resolve(agent_id: str) -> AgentCLI | None:
    """Devuelve el :class:`AgentCLI` con ese id, o ``None`` si no se conoce."""
    return BY_ID.get(agent_id)

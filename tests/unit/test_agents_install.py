"""Tests de detección de agentes, instalación multi-agente y drenado paralelo."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from hexflaw.cli.commands.agent import app as agent_app
from hexflaw.cli.commands.agents_setup import agents_install_command
from hexflaw.services import agent_registry
from hexflaw.services.agent_registry import AgentCLI, detect

runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Aísla HOME y HEXFLAW_HOME: nada toca la config real del usuario."""
    monkeypatch.setenv("HEXFLAW_HOME", str(tmp_path / "hexflaw_home"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))


def _fake_agent(tmp_path: Path, agent_id: str, fmt: str = "markdown") -> AgentCLI:
    """Un AgentCLI cuyo directorio de comandos vive bajo tmp_path."""
    return AgentCLI(
        id=agent_id,
        name=agent_id.title(),
        binary=agent_id,
        args=("run",),
        system_flag=None,
        commands_dir=tmp_path / agent_id / "commands",
        command_format=fmt,
    )


# ------------------------------- detección -------------------------------- #


def test_detect_splits_installed_from_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """La detección es por PATH; lo ausente se reporta, no se oculta."""
    agents = (
        _fake_agent(Path("/x"), "presente"),
        _fake_agent(Path("/x"), "ausente"),
    )
    monkeypatch.setattr(
        "shutil.which", lambda b: "/usr/bin/presente" if b == "presente" else None
    )
    found = detect(agents)

    assert [a.id for a in found.installed] == ["presente"]
    assert [a.id for a in found.missing] == ["ausente"]
    assert found.any_installed


def test_every_known_agent_is_usable() -> None:
    """Una entrada del registro sin lo mínimo es una integración rota en silencio."""
    for agent in agent_registry.KNOWN_AGENTS:
        assert agent.binary, f"{agent.id} sin binario no se detecta nunca"
        assert agent.args, f"{agent.id} sin args no se puede invocar headless"
        assert agent.command_format in ("markdown", "toml")
        assert agent.command_path("x").suffix in (".md", ".toml")


def test_prompt_never_travels_as_an_argument() -> None:
    """El prompt va SIEMPRE por STDIN.

    Es una cicatriz real: los prompts de M5 llevan el code graph y el taint path, y
    pasarlos por argv los hacía reventar con 'argument list too long' a mitad de un
    análisis largo.
    """
    prompt = "X" * 300_000
    for agent in agent_registry.KNOWN_AGENTS:
        argv = agent.argv("system corto")
        assert all(prompt not in part for part in argv)
        assert prompt in agent.stdin_for("system corto", prompt)


def test_system_prompt_reaches_the_agent_one_way_or_another() -> None:
    """Con flag va aparte; sin flag se antepone al prompt. Nunca se pierde."""
    for agent in agent_registry.KNOWN_AGENTS:
        argv = agent.argv("SYSTEM_MARK")
        stdin = agent.stdin_for("SYSTEM_MARK", "prompt")
        assert "SYSTEM_MARK" in argv or "SYSTEM_MARK" in stdin


# ------------------------------ instalación ------------------------------- #


def test_installs_into_every_detected_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """El pedido central: integrar TODOS los agentes instalados, no solo Claude."""
    agents = (
        _fake_agent(tmp_path, "uno"),
        _fake_agent(tmp_path, "dos", fmt="toml"),
        _fake_agent(tmp_path, "ausente"),
    )
    monkeypatch.setattr(agent_registry, "KNOWN_AGENTS", agents)
    monkeypatch.setattr(
        "shutil.which", lambda b: None if b == "ausente" else f"/usr/bin/{b}"
    )

    agents_install_command(name="hexflaw", only=None, list_only=False)

    assert (tmp_path / "uno" / "commands" / "hexflaw.md").exists()
    assert (tmp_path / "dos" / "commands" / "hexflaw.toml").exists()
    assert not (tmp_path / "ausente" / "commands").exists()


def test_installed_command_delegates_instead_of_analyzing_inline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """El comando instalado NO debe razonar el análisis en su propia ventana.

    Es el punto del cambio: si el agente que recibe el slash command contesta él
    mismo cada batch, para el batch 30 decide condicionado por los 29 anteriores.
    Tiene que delegar en 'agent drain', que da un proceso nuevo por request.
    """
    agents = (_fake_agent(tmp_path, "uno"),)
    monkeypatch.setattr(agent_registry, "KNOWN_AGENTS", agents)
    monkeypatch.setattr("shutil.which", lambda b: f"/usr/bin/{b}")

    agents_install_command(name="hexflaw", only=None, list_only=False)
    body = (tmp_path / "uno" / "commands" / "hexflaw.md").read_text(encoding="utf-8")

    assert "agent drain" in body
    assert "--llm-backend agent" in body
    assert "NO analices el código vos mismo" in body


def test_toml_command_is_parseable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Un TOML mal formado es un comando que el CLI simplemente no carga."""
    import tomllib

    agents = (_fake_agent(tmp_path, "tomlagent", fmt="toml"),)
    monkeypatch.setattr(agent_registry, "KNOWN_AGENTS", agents)
    monkeypatch.setattr("shutil.which", lambda b: f"/usr/bin/{b}")

    agents_install_command(name="hexflaw", only=None, list_only=False)
    data = tomllib.loads(
        (tmp_path / "tomlagent" / "commands" / "hexflaw.toml").read_text(encoding="utf-8")
    )
    assert data["description"]
    assert "agent drain" in data["prompt"]


def test_list_only_does_not_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """'--list' es de solo lectura."""
    agents = (_fake_agent(tmp_path, "uno"),)
    monkeypatch.setattr(agent_registry, "KNOWN_AGENTS", agents)
    monkeypatch.setattr("shutil.which", lambda b: f"/usr/bin/{b}")

    agents_install_command(name="hexflaw", only=None, list_only=True)
    assert not (tmp_path / "uno" / "commands").exists()


def test_fails_when_no_agent_is_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sin agentes no se puede integrar nada: hay que decirlo, no fingir éxito."""
    monkeypatch.setattr("shutil.which", lambda b: None)
    with pytest.raises(typer.Exit):
        agents_install_command(name="hexflaw", only=None, list_only=False)


# -------------------------------- drenado --------------------------------- #


def _queue_with(tmp_path: Path, count: int) -> Path:
    """Cola con ``count`` requests pendientes."""
    queue = tmp_path / "hexflaw_home" / "agent_queue"
    queue.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        (queue / f"req-r{i}.json").write_text(
            json.dumps(
                {
                    "id": f"r{i}",
                    "label": f"M4 batch {i}",
                    "model": "m",
                    "system": "SYSTEM_MARK",
                    "prompt": f"prompt {i}",
                    "max_tokens": 100,
                    "created_at": 1,
                }
            ),
            encoding="utf-8",
        )
    return queue


def _script(tmp_path: Path, body: str) -> str:
    """Crea un ejecutable de shell y devuelve su ruta."""
    path = tmp_path / "fake_agent.sh"
    path.write_text(f"#!/usr/bin/env bash\n{body}\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


def test_drain_answers_each_request_in_its_own_process(tmp_path: Path) -> None:
    """El corazón del cambio: un proceso nuevo por batch, no una ventana compartida.

    Cada invocación reporta su PID; que sean todos distintos es la prueba de que
    ningún request hereda el contexto del anterior.
    """
    queue = _queue_with(tmp_path, 4)
    cmd = _script(tmp_path, 'echo "{\\"text\\":\\"$$\\"}"')

    result = runner.invoke(agent_app, ["drain", "--cmd", cmd, "--once", "--workers", "4"])
    assert result.exit_code == 0, result.output

    pids = {
        json.loads((queue / f"res-r{i}.json").read_text(encoding="utf-8"))["text"]
        for i in range(4)
    }
    assert len(pids) == 4, f"los requests compartieron proceso: {pids}"


def test_drain_passes_the_system_prompt_to_a_custom_command(tmp_path: Path) -> None:
    """Con --cmd, el system llega por HEXFLAW_SYSTEM y el prompt por STDIN."""
    queue = _queue_with(tmp_path, 1)
    cmd = _script(tmp_path, 'read -r p; echo "{\\"text\\":\\"$HEXFLAW_SYSTEM|$p\\"}"')

    result = runner.invoke(agent_app, ["drain", "--cmd", cmd, "--once"])
    assert result.exit_code == 0, result.output

    text = json.loads((queue / "res-r0.json").read_text(encoding="utf-8"))["text"]
    assert text == "SYSTEM_MARK|prompt 0"


def test_drain_leaves_a_failed_request_pending(tmp_path: Path) -> None:
    """Un agente que falla no puede consumir el request: se reintenta después.

    Escribir una respuesta vacía sería peor que no escribir nada: el pipeline la
    parsearía como un análisis sin hallazgos y el batch quedaría marcado como
    revisado sin que nadie lo haya mirado.
    """
    queue = _queue_with(tmp_path, 1)
    cmd = _script(tmp_path, "exit 1")

    result = runner.invoke(agent_app, ["drain", "--cmd", cmd, "--once"])
    assert result.exit_code == 0, result.output
    assert not (queue / "res-r0.json").exists()
    assert (queue / "req-r0.json").exists()


def test_drain_treats_empty_output_as_failure(tmp_path: Path) -> None:
    """Salida vacía con exit 0 tampoco puede pasar por respuesta válida."""
    queue = _queue_with(tmp_path, 1)
    cmd = _script(tmp_path, "true")

    runner.invoke(agent_app, ["drain", "--cmd", cmd, "--once"])
    assert not (queue / "res-r0.json").exists()


def test_drain_wraps_plain_text_output(tmp_path: Path) -> None:
    """Un agente que imprime el JSON pelado (sin envolver en {text}) también sirve."""
    queue = _queue_with(tmp_path, 1)
    cmd = _script(tmp_path, "echo '{\"findings\": []}'")

    runner.invoke(agent_app, ["drain", "--cmd", cmd, "--once"])
    payload = json.loads((queue / "res-r0.json").read_text(encoding="utf-8"))
    assert json.loads(payload["text"]) == {"findings": []}


def test_drain_rejects_an_unknown_agent(tmp_path: Path) -> None:
    """Un id mal escrito no puede caer en silencio a otro agente."""
    _queue_with(tmp_path, 0)
    result = runner.invoke(agent_app, ["drain", "--agent", "clade", "--once"])
    assert result.exit_code == 1


def test_drain_rejects_zero_workers(tmp_path: Path) -> None:
    """--workers 0 no drenaría nada; fallar es mejor que colgarse en silencio."""
    _queue_with(tmp_path, 0)
    result = runner.invoke(agent_app, ["drain", "--cmd", "true", "--workers", "0", "--once"])
    assert result.exit_code == 1


def test_drain_honors_the_timeout(tmp_path: Path) -> None:
    """Un agente colgado no puede bloquear la cola para siempre."""
    _queue_with(tmp_path, 1)
    cmd = _script(tmp_path, "sleep 30")

    result = runner.invoke(
        agent_app, ["drain", "--cmd", cmd, "--once", "--timeout", "1"]
    )
    assert result.exit_code == 0
    assert "timeout" in result.output.lower()
    assert not (tmp_path / "hexflaw_home" / "agent_queue" / "res-r0.json").exists()


def test_drain_skips_already_answered_requests(tmp_path: Path) -> None:
    """Lo ya respondido no se vuelve a mandar: sería pagar dos veces lo mismo."""
    queue = _queue_with(tmp_path, 2)
    (queue / "res-r0.json").write_text(json.dumps({"id": "r0", "text": "ya"}), encoding="utf-8")
    marker = tmp_path / "calls"
    cmd = _script(tmp_path, f'echo x >> {marker}; echo "{{\\"text\\":\\"ok\\"}}"')

    runner.invoke(agent_app, ["drain", "--cmd", cmd, "--once"])

    assert marker.read_text(encoding="utf-8").count("x") == 1
    assert json.loads((queue / "res-r0.json").read_text(encoding="utf-8"))["text"] == "ya"


def test_drain_env_is_inherited_for_custom_commands(tmp_path: Path) -> None:
    """El comando propio ve el entorno del usuario (PATH, credenciales del CLI)."""
    _queue_with(tmp_path, 1)
    os.environ["HEXFLAW_TEST_MARKER"] = "presente"
    try:
        cmd = _script(tmp_path, 'echo "{\\"text\\":\\"$HEXFLAW_TEST_MARKER\\"}"')
        runner.invoke(agent_app, ["drain", "--cmd", cmd, "--once"])
        payload = json.loads(
            (tmp_path / "hexflaw_home" / "agent_queue" / "res-r0.json").read_text(encoding="utf-8")
        )
        assert payload["text"] == "presente"
    finally:
        del os.environ["HEXFLAW_TEST_MARKER"]

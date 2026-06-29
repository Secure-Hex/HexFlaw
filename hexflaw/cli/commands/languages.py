"""Subcomando ``hexflaw languages`` — plugin system de lenguajes (CLAUDE.md §9b)."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import tempfile
from dataclasses import asdict
from pathlib import Path

import typer

from hexflaw.cli import console
from hexflaw.infrastructure import storage
from hexflaw.services.language_service import LanguageService, validate_definition_dict

app = typer.Typer(help="Gestión del plugin system de lenguajes.")


def _open_in_editor(text: str) -> str | None:
    """Abre ``text`` en el editor del usuario (``$VISUAL``/``$EDITOR``).

    Returns:
        El texto editado, o ``None`` si no hubo cambios.
    """
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "vi"
    fd, name = tempfile.mkstemp(suffix=".json")
    path = Path(name)
    try:
        os.close(fd)
        path.write_text(text, encoding="utf-8")
        before = path.read_text(encoding="utf-8")
        subprocess.run([*shlex.split(editor), name], check=True)
        after = path.read_text(encoding="utf-8")
        return after if after != before else None
    finally:
        path.unlink(missing_ok=True)


@app.command("list")
def list_languages() -> None:
    """Lista todos los lenguajes disponibles (builtin + custom)."""
    service = LanguageService()
    tbl = console.table("Lenguajes disponibles", ["ID", "Origen", "Extensiones"])
    for lang_id in service.known_languages():
        is_custom = service.is_custom(lang_id)
        origin = "[yellow]custom[/]" if is_custom else "[dim]builtin[/]"
        definition = service.get(lang_id)
        exts = ", ".join(definition.extensions) if definition else ""
        tbl.add_row(f"[bold]{lang_id}[/]", origin, exts)
    console.print_table(tbl)


@app.command("show")
def show_language(language_id: str = typer.Argument(..., help="id del lenguaje.")) -> None:
    """Muestra el detalle de la definición de un lenguaje."""
    service = LanguageService()
    definition = service.get(language_id)
    if definition is None:
        console.error(f"Lenguaje no encontrado: {language_id}")
        raise typer.Exit(code=1)
    console.kv_panel(
        f"{console.esc(definition.name)} ([dim]{console.esc(definition.id)}[/])",
        [
            ("Extensiones", console.esc(", ".join(definition.extensions))),
            ("App types", console.esc(", ".join(definition.app_types)) or "—"),
            ("Vuln profile", console.esc(", ".join(definition.vuln_profile)) or "—"),
            ("Entry points", console.esc(", ".join(definition.entry_point_patterns)) or "—"),
            ("Sinks", console.esc(", ".join(definition.sink_patterns)) or "—"),
            ("tree-sitter", console.esc(definition.tree_sitter_package or "—")),
            ("Notas", console.esc(definition.notes or "—")),
        ],
    )


@app.command("validate")
def validate_language(
    path: Path = typer.Argument(..., help="Archivo JSON de definición a validar."),
) -> None:
    """Valida que un archivo de definición esté bien formado."""
    try:
        data = storage.read_json(path)
    except (ValueError, OSError) as exc:
        typer.secho(f"No se pudo leer el archivo: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc
    errors = validate_definition_dict(data)
    if errors:
        typer.secho("Definición INVÁLIDA:", fg=typer.colors.RED)
        for error in errors:
            typer.echo(f"  - {error}")
        raise typer.Exit(code=1)
    typer.secho("Definición válida.", fg=typer.colors.GREEN)


@app.command("add")
def add_language(
    path: Path = typer.Argument(..., help="Archivo JSON de definición propia."),
    overwrite: bool = typer.Option(False, "--overwrite", help="Sobrescribir si existe."),
) -> None:
    """Agrega un lenguaje desde un archivo de definición JSON propio."""
    service = LanguageService()
    try:
        data = storage.read_json(path)
    except (ValueError, OSError) as exc:
        typer.secho(f"No se pudo leer el archivo: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc

    if service.is_builtin(str(data.get("id", ""))) and overwrite:
        typer.secho(
            f"⚠️  Sobrescribiendo el builtin '{data.get('id')}' (T-LANG-3). "
            "Verifica que vuln_profile/sinks no queden vacíos.",
            fg=typer.colors.YELLOW,
        )
    try:
        target = service.add_custom(data, overwrite=overwrite)
    except ValueError as exc:
        typer.secho(str(exc), fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc
    typer.secho(f"Lenguaje agregado: {target}", fg=typer.colors.GREEN)


@app.command("edit")
def edit_language(
    language_id: str = typer.Argument(..., help="id del lenguaje a editar."),
) -> None:
    """Edita la definición custom de un lenguaje en ``$EDITOR``.

    Si el lenguaje solo existe como builtin, se siembra una copia custom a partir
    de él (precedencia custom > builtin, CLAUDE.md §9b). Tras editar, se valida; si
    la definición es inválida no se guarda.
    """
    service = LanguageService()
    definition = service.get(language_id)
    if definition is None:
        console.error(
            f"Lenguaje '{language_id}' no existe. Usá 'languages add <json>' o "
            "'languages install <id>'."
        )
        raise typer.Exit(code=1)

    seed = {k: v for k, v in asdict(definition).items() if v is not None}
    origin = "custom" if service.is_custom(language_id) else "builtin (se creará copia custom)"
    console.info(f"Editando '{language_id}' [{origin}]...")

    edited = _open_in_editor(json.dumps(seed, indent=2, ensure_ascii=False))
    if edited is None:
        console.info("Sin cambios.")
        return

    try:
        new_data = json.loads(edited)
    except json.JSONDecodeError as exc:
        console.error(f"JSON inválido, no se guardó: {console.esc(exc)}")
        raise typer.Exit(code=1) from exc

    errors = validate_definition_dict(new_data)
    if errors:
        console.error("Definición inválida, no se guardó:")
        for error in errors:
            console.error(f"  - {console.esc(error)}")
        raise typer.Exit(code=1)

    target = service.add_custom(new_data, overwrite=True)
    console.success(f"Definición custom de '{language_id}' guardada: [dim]{target}[/]")


@app.command("remove")
def remove_language(language_id: str = typer.Argument(..., help="id del lenguaje custom.")) -> None:
    """Elimina una definición de lenguaje custom."""
    service = LanguageService()
    if service.remove_custom(language_id):
        typer.secho(f"Eliminado: {language_id}", fg=typer.colors.GREEN)
    else:
        typer.secho(
            f"No existe una definición custom para '{language_id}'.", fg=typer.colors.YELLOW
        )


@app.command("install")
def install_language(language_id: str = typer.Argument(..., help="id del lenguaje a instalar.")) -> None:
    """Registra un lenguaje nuevo creando una definición por defecto.

    Por seguridad (T-LANG-1), HexFlaw **no** ejecuta ``pip install`` de paquetes
    de terceros automáticamente: imprime el comando para que lo ejecutes
    conscientemente. Crea la definición con análisis ``llm-only`` como fallback.
    """
    service = LanguageService()
    if service.get(language_id) is not None:
        typer.secho(f"'{language_id}' ya está disponible.", fg=typer.colors.YELLOW)
        raise typer.Exit(code=0)

    definition = {
        "id": language_id,
        "name": language_id.capitalize(),
        "extensions": [f".{language_id}"],
        "tree_sitter_package": f"tree-sitter-{language_id}",
        "app_types": ["binary"],
        "vuln_profile": [],
        "entry_point_patterns": [],
        "sink_patterns": [],
        "notes": "Definición autogenerada (llm-only). Editar el vuln_profile.",
    }
    target = service.add_custom(definition, overwrite=True)
    typer.secho(f"Definición creada: {target}", fg=typer.colors.GREEN)
    typer.secho(
        f"Para soporte AST, instala la grammar manualmente:\n"
        f"  pip install tree-sitter-{language_id}\n"
        "HexFlaw no instala paquetes de terceros automáticamente (T-LANG-1).",
        fg=typer.colors.YELLOW,
    )


@app.command("learn")
def learn_language(
    language_id: str = typer.Argument(
        ..., help="id del lenguaje a aprender (ej. typescript)."
    ),
    max_samples: int = typer.Option(
        20, "--samples", help="Cantidad de chunks de muestra a enviar al LLM."
    ),
) -> None:
    """Genera ``sink_patterns`` para un lenguaje vía LLM y los persiste como custom.

    Usa código real del lenguaje en el proyecto activo como contexto. Resuelve el
    peor caso del pre-filtro de M4 (lenguaje sin sinks → fail-open costoso): tras
    aprenderlos, el filtro de keywords vuelve a funcionar para ese lenguaje, y la
    definición custom se reutiliza en todo proyecto futuro (CLAUDE.md §9b).
    """
    from hexflaw.cli.helpers import build_orchestrator, handle_project_errors
    from hexflaw.services import sink_learner

    with handle_project_errors():
        orchestrator = build_orchestrator()
        ingestion = orchestrator._load_ingestion_optional()
        if ingestion is None:
            typer.secho(
                "No hay ingestión en el proyecto. Corré 'hexflaw ingest' primero.",
                fg=typer.colors.RED,
            )
            raise typer.Exit(code=1)
        samples = [c.code for c in ingestion.chunks if c.language == language_id]
        if not samples:
            typer.secho(
                f"No hay chunks del lenguaje '{language_id}' en el proyecto. "
                f"Lenguajes presentes: {', '.join(ingestion.languages) or '—'}.",
                fg=typer.colors.RED,
            )
            raise typer.Exit(code=1)
        sample_code = "\n\n".join(samples[:max_samples])
        with console.step(f"Aprendiendo sinks de '{language_id}' vía LLM..."):
            try:
                sinks = sink_learner.learn_sinks(
                    language_id, sample_code, orchestrator.llm, orchestrator.languages
                )
            except Exception as exc:  # noqa: BLE001 — reportar limpio al usuario
                typer.secho(f"No se pudieron aprender sinks: {exc}", fg=typer.colors.RED)
                raise typer.Exit(code=1) from exc

    console.kv_panel(
        "Sinks aprendidos",
        [
            ("Lenguaje", language_id),
            ("Patrones", str(len(sinks))),
            ("Persistido", f"~/.hexflaw/languages/custom/{language_id}.json"),
        ],
        border="green",
    )
    typer.echo(", ".join(sinks[:25]) + (" …" if len(sinks) > 25 else ""))

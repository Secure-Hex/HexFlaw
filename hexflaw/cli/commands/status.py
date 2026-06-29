"""Comando ``hexflaw status`` — estado del proyecto actual."""

from __future__ import annotations

from hexflaw.cli import console
from hexflaw.cli.helpers import handle_project_errors
from hexflaw.core import project as project_mod


def status_command() -> None:
    """Muestra metadata y artefactos presentes del proyecto detectado."""
    with handle_project_errors():
        project = project_mod.load_project()

    meta = project.metadata
    console.kv_panel(
        f"[bold]{console.esc(meta.name)}[/]",
        [
            ("ID", console.esc(meta.project_id)),
            ("Root", console.esc(project.root)),
            ("Creado", meta.created_at.isoformat()),
            ("Lenguajes", console.esc(", ".join(meta.languages)) or "—"),
            ("App type", meta.app_type.value),
        ],
    )

    tbl = console.table("Artefactos", ["", "Artefacto"])
    for label, path in (
        ("ingestión", project.chunks_path),
        ("file_hashes", project.file_hashes_path),
        ("code_graph", project.hexflaw_dir / "code_graph.json"),
        ("findings", project.findings_path),
        ("reports/", project.hexflaw_dir / "reports"),
        ("poc/", project.hexflaw_dir / "poc"),
    ):
        mark = "[green]✓[/]" if path.exists() else "[dim]·[/]"
        tbl.add_row(mark, label)
    console.print_table(tbl)

"""M1 — Ingestion (CLAUDE.md §6 M1, §15 M1).

Módulo de mayor riesgo del pipeline. Aplica guards de seguridad sobre el código
analizado, que es la principal superficie de ataque:
- Symlinks prohibidos (``os.lstat``, se saltan y loguean) — T-M1-2.
- Validación de que cada path resuelto queda dentro de la raíz — T-M1-1.
- Límites de tamaño por archivo y por proyecto — límites de §15.
- Nunca se ejecuta ningún archivo del codebase — inamovible por diseño.
- Rechazo de nombres con null bytes / caracteres de control — T-M1-6.
"""

from __future__ import annotations

import hashlib
import os
import stat as stat_module
from pathlib import Path

from hexflaw.core.models import (
    AppType,
    CodeChunk,
    FileEntry,
    IngestionResult,
)
from hexflaw.infrastructure.logging import get_logger, sanitize_log_value
from hexflaw.modules.chunking import chunk_hash, chunk_source
from hexflaw.services.language_service import LanguageDefinition, LanguageService

logger = get_logger(__name__)

_CONTROL_BYTES = set(range(0, 9)) | set(range(11, 32)) | {127}


def ingest(
    source_path: Path,
    project_id: str,
    languages_service: LanguageService,
    *,
    max_file_bytes: int = 10 * 1024 * 1024,
    max_project_bytes: int = 2 * 1024 * 1024 * 1024,
    prior: IngestionResult | None = None,
    project_root: Path | None = None,
    incremental: bool = False,
) -> IngestionResult:
    """Ingesta un directorio de código fuente de forma segura.

    Args:
        source_path: Directorio raíz del código a analizar.
        project_id: UUID del proyecto activo.
        languages_service: Servicio para resolver lenguaje por extensión.
        max_file_bytes: Tamaño máximo aceptado por archivo.
        max_project_bytes: Tamaño acumulado máximo del proyecto.
        prior: Resultado de una ingestión previa. Si se provee (re-ingest
            incremental), los archivos cuyo hash no cambió reutilizan sus chunks
            sin re-procesar (CLAUDE.md §6 M1, re-ingest incremental).

    Returns:
        :class:`IngestionResult` con file_map, chunks y rutas saltadas.

    Raises:
        FileNotFoundError: Si ``source_path`` no existe.
        NotADirectoryError: Si ``source_path`` no es un directorio.
    """
    prior_hash = {e.path: e.hash for e in prior.file_map} if prior else {}
    prior_chunks: dict[str, list[CodeChunk]] = {}
    if prior:
        for chunk in prior.chunks:
            prior_chunks.setdefault(chunk.file, []).append(chunk)
    reused_files = 0

    source_path = source_path.resolve()
    root = project_root.resolve() if project_root is not None else None
    if not source_path.exists():
        raise FileNotFoundError(f"La ruta de origen no existe: {source_path}")
    if not source_path.is_dir():
        raise NotADirectoryError(
            f"Por ahora ingest solo acepta directorios: {source_path}"
        )

    file_map: list[FileEntry] = []
    chunks: list[CodeChunk] = []
    skipped: list[str] = []
    languages_seen: set[str] = set()
    app_types_seen: set[str] = set()
    total_bytes = 0

    for path in _walk_safe(source_path, skipped):
        # Path relativo al ROOT del proyecto (no al source del ingest): así dos
        # ingests de sub-paths distintos producen rutas consistentes y mergeables.
        if root is not None and path.is_relative_to(root):
            rel = path.relative_to(root).as_posix()
        else:
            rel = path.relative_to(source_path).as_posix()

        if _has_control_chars(rel):
            logger.warning("Path con caracteres de control, saltado: %s", sanitize_log_value(rel))
            skipped.append(rel)
            continue

        definition = languages_service.detect_by_extension(path)
        if definition is None:
            # Fallback por shebang para archivos sin extensión / extensión rara
            # (CGIs, hooks, scripts en firmware). Lee solo la primera línea.
            definition = languages_service.detect_by_shebang(_peek_first_line(path))
        if definition is None:
            continue  # archivo de lenguaje no soportado, se ignora silenciosamente

        try:
            size = path.stat().st_size
        except OSError as exc:
            logger.warning("No se pudo stat %s: %s", rel, exc)
            skipped.append(rel)
            continue

        if size > max_file_bytes:
            logger.warning("Archivo excede límite (%d bytes), saltado: %s", size, rel)
            skipped.append(rel)
            continue
        if total_bytes + size > max_project_bytes:
            logger.warning("Límite de proyecto alcanzado; deteniendo ingestión")
            break

        content = _read_text(path)
        if content is None:
            skipped.append(rel)
            continue

        total_bytes += size
        languages_seen.add(definition.id)
        app_types_seen.update(definition.app_types)

        file_hash = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
        file_map.append(
            FileEntry(path=rel, language=definition.id, hash=file_hash, size_bytes=size)
        )
        if prior_hash.get(rel) == file_hash and rel in prior_chunks:
            chunks.extend(prior_chunks[rel])  # incremental: archivo sin cambios
            reused_files += 1
        else:
            chunks.extend(_chunk_file(rel, definition, content))

    # --- Merge con el índice previo --------------------------------------- #
    # Footgun fix: un ingest de un sub-path NO debe tirar en silencio lo ya
    # indexado de otros paths. En incremental ACUMULA (conserva archivos de
    # otros roots); en ambos modos detecta y reporta los archivos que caen.
    dropped_from_prior: list[str] = []
    if prior is not None:
        current_paths = {e.path for e in file_map}
        # Prefijo del source relativo al proyecto: distingue "borrado bajo este
        # root" (se cae, correcto) de "pertenece a otro path" (se conserva).
        source_rel = ""
        if root is not None and source_path.is_relative_to(root):
            source_rel = source_path.relative_to(root).as_posix()
        # relative_to(self) da ".", que significa "el source ES el root" → todo
        # el índice está bajo este ingest (no hay "otro path" que conservar).
        if source_rel == ".":
            source_rel = ""

        def _under_source(p: str) -> bool:
            return source_rel == "" or p == source_rel or p.startswith(source_rel + "/")

        for entry in prior.file_map:
            if entry.path in current_paths:
                continue  # re-ingerido (actualizado) en este walk
            if incremental and not _under_source(entry.path):
                # Archivo de otro path previamente indexado → conservar (acumular).
                file_map.append(entry)
                chunks.extend(prior_chunks.get(entry.path, []))
                languages_seen.add(entry.language)
            else:
                # Bajo el root re-ingerido pero ya no aparece (borrado), o ingest
                # no-incremental que reemplaza el índice → se cae.
                dropped_from_prior.append(entry.path)

        if dropped_from_prior:
            logger.warning(
                "Ingest deja fuera del índice %d archivo(s) previamente indexado(s). "
                "%s. Para acumular varios paths usá --incremental o ingerí un root común.",
                len(dropped_from_prior),
                "Re-ingest incremental: archivos borrados del source"
                if incremental
                else "Ingest no-incremental: reemplaza el índice",
            )

    app_type = _infer_app_type(app_types_seen)
    logger.info(
        "Ingestión: %d archivos (%d reusados), %d chunks, %d saltados, lenguajes=%s",
        len(file_map),
        reused_files,
        len(chunks),
        len(skipped),
        sorted(languages_seen),
    )
    return IngestionResult(
        project_id=project_id,
        languages=sorted(languages_seen),
        app_type=app_type,
        file_map=file_map,
        chunks=chunks,
        skipped=skipped,
        dropped_from_prior=dropped_from_prior,
    )


def _walk_safe(root: Path, skipped: list[str]):
    """Recorre ``root`` sin seguir symlinks (T-M1-2) y sin salir del sandbox (T-M1-1).

    Yields:
        Rutas de archivos regulares seguros bajo ``root``.
    """
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # No descender en directorios que sean symlinks ni en .hexflaw/.git
        dirnames[:] = [
            d
            for d in dirnames
            if d not in (".hexflaw", ".git")
            and not Path(dirpath, d).is_symlink()
        ]
        for filename in filenames:
            candidate = Path(dirpath, filename)
            try:
                st = candidate.lstat()  # lstat: no sigue el symlink
            except OSError:
                continue
            if stat_module.S_ISLNK(st.st_mode):
                logger.warning("Symlink saltado (prohibido en ingest): %s", candidate)
                skipped.append(str(candidate.relative_to(root)))
                continue
            if not stat_module.S_ISREG(st.st_mode):
                continue
            # Defensa en profundidad contra path traversal: el realpath debe seguir bajo root.
            real = candidate.resolve()
            if root not in real.parents and real != root:
                logger.warning("Path fuera del sandbox, saltado: %s", candidate)
                skipped.append(str(candidate))
                continue
            yield candidate


def _chunk_file(
    rel_path: str, definition: LanguageDefinition, content: str
) -> list[CodeChunk]:
    """Convierte el contenido de un archivo en :class:`CodeChunk` Pydantic."""
    result: list[CodeChunk] = []
    for i, raw in enumerate(chunk_source(content, definition.id)):
        result.append(
            CodeChunk(
                id=f"{rel_path}::{i}",
                file=rel_path,
                language=definition.id,
                name=raw.name,
                code=raw.code,
                line_start=raw.line_start,
                line_end=raw.line_end,
                hash=chunk_hash(raw.code),
            )
        )
    return result


def _peek_first_line(path: Path) -> str:
    """Lee la primera línea de un archivo (acotado), para detección por shebang.

    Lee solo un prefijo pequeño: no carga binarios grandes en memoria y devuelve
    ``""`` ante cualquier error o contenido binario.
    """
    try:
        with path.open("rb") as fh:
            head = fh.read(256)
    except OSError:
        return ""
    if b"\x00" in head:  # binario: no intentar shebang
        return ""
    return head.split(b"\n", 1)[0].decode("utf-8", errors="replace")


def _read_text(path: Path) -> str | None:
    """Lee un archivo como texto UTF-8 tolerante; ``None`` si parece binario."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        logger.warning("No se pudo leer %s: %s", path, exc)
        return None
    if b"\x00" in raw[:4096]:  # heurística de binario disfrazado (T-M1-4): no se ejecuta, solo se ignora
        logger.debug("Archivo binario disfrazado ignorado: %s", path)
        return None
    return raw.decode("utf-8", errors="replace")


def _has_control_chars(name: str) -> bool:
    """Detecta caracteres de control / null bytes en un nombre de path (T-M1-6)."""
    return any(ord(ch) in _CONTROL_BYTES for ch in name)


def _infer_app_type(app_types: set[str]) -> AppType:
    """Infiere el tipo de aplicación dominante a partir de los lenguajes vistos."""
    # Prioridad simple para el slice; M2/M0 pueden refinar luego.
    for preferred in ("firmware", "binary", "web", "mobile", "contract"):
        if preferred in app_types:
            try:
                return AppType(preferred)
            except ValueError:
                continue
    return AppType.UNKNOWN

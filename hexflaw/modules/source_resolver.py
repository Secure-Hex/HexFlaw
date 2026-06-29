"""Normalización de la fuente de ingestión (CLAUDE.md §6 M1, §15 M1).

M1 acepta cuatro ``source_type``: ``directory``, ``zip``, ``git`` y ``url``. Este
módulo resuelve cualquiera de ellos a un **directorio local seguro** sobre el que
luego camina :mod:`hexflaw.modules.m1_ingestion`.

Todo lo que no sea un directorio ya presente se materializa en un **sandbox
temporal** (``tempfile.mkdtemp`` con permisos ``700``) que se elimina al salir.
Guards aplicados:

- **Zip-slip / path traversal (T-M1-1):** cada miembro del zip se valida con
  ``realpath`` contra el sandbox; cualquier ruta que escape se rechaza.
- **Symlinks (T-M1-2):** los symlinks dentro del zip NO se extraen.
- **Git hooks (T-M1-5):** ``git clone`` con ``core.hooksPath=/dev/null``,
  ``GIT_CONFIG_NOSYSTEM=1`` y sin prompts, ``--no-local --no-hardlinks``.
- **Descargas (T-M1-1/§15):** solo ``http(s)``, con timeout y tope de tamaño.
- **Nunca se ejecuta nada del codebase** — inamovible.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from hexflaw.infrastructure.logging import get_logger, sanitize_log_value

logger = get_logger(__name__)

#: Hosts cuyas URLs http(s) se tratan como repos git (clone) y no como descarga.
_GIT_HOSTS = {"github.com", "gitlab.com", "bitbucket.org", "codeberg.org"}

#: Tope de descarga por URL (T-M1-1): evita agotar disco con un recurso enorme.
_MAX_DOWNLOAD_BYTES = 500 * 1024 * 1024

#: Timeouts (segundos) para operaciones de red potencialmente bloqueantes (§15).
_GIT_TIMEOUT = 300
_HTTP_TIMEOUT = 120


class IngestSourceError(RuntimeError):
    """No se pudo clasificar o materializar la fuente de ingestión."""


def classify_source(source: str) -> str:
    """Clasifica la fuente en ``directory`` | ``zip`` | ``git`` | ``url``.

    Args:
        source: Ruta local o URL.

    Returns:
        El ``source_type`` detectado.

    Raises:
        IngestSourceError: Si la fuente no existe ni es una URL reconocible.
    """
    s = source.strip()
    low = s.lower()
    if s.startswith("git@") or low.startswith(("git://", "ssh://")):
        return "git"
    if low.startswith(("http://", "https://")):
        host = (urlparse(s).hostname or "").lower()
        if low.endswith(".git") or host in _GIT_HOSTS:
            return "git"
        return "url"
    if low.startswith("file://"):
        # Mirror local: repo git si tiene .git / termina en .git; si no, el path.
        local = Path(urlparse(s).path)
        if low.endswith(".git") or (local / ".git").exists():
            return "git"
        s = str(local)
        low = s.lower()
    p = Path(s).expanduser()
    if p.is_dir():
        return "directory"
    if p.is_file() and low.endswith(".zip"):
        return "zip"
    raise IngestSourceError(
        f"Fuente no reconocida: {sanitize_log_value(s)}. Esperado un directorio, "
        "un .zip, una URL git o una URL http(s)."
    )


@contextmanager
def resolved_source(source: str | os.PathLike[str]) -> Iterator[Path]:
    """Resuelve la fuente a un directorio local, materializándola si hace falta.

    Para ``directory`` cede el path tal cual (sin sandbox ni cleanup). Para
    ``zip``/``git``/``url`` materializa en un sandbox temporal ``700`` que se
    elimina al cerrar el contexto.

    Args:
        source: Ruta local o URL.

    Yields:
        Directorio local seguro listo para :func:`m1_ingestion.ingest`.
    """
    src = str(source)
    kind = classify_source(src)
    if kind == "directory":
        yield Path(src).expanduser()
        return

    sandbox = Path(tempfile.mkdtemp(prefix="hexflaw-ingest-"))
    os.chmod(sandbox, 0o700)
    try:
        if kind == "zip":
            _extract_zip(Path(src).expanduser(), sandbox)
        elif kind == "git":
            _clone_git(src, sandbox)
        else:  # url
            _download(src, sandbox)
        logger.info("Fuente '%s' materializada en sandbox %s", kind, sandbox)
        yield sandbox
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)


def _extract_zip(zip_path: Path, dest: Path) -> None:
    """Extrae un zip al sandbox con guards de zip-slip y symlinks (T-M1-1/2)."""
    dest_real = dest.resolve()
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.infolist():
            name = member.filename
            # Symlinks dentro del zip: marcados en los bits altos de external_attr.
            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode):
                logger.warning("Symlink en zip saltado (T-M1-2): %s", sanitize_log_value(name))
                continue
            target = (dest / name).resolve()
            # Zip-slip: el destino real debe quedar dentro del sandbox (T-M1-1).
            if dest_real != target and dest_real not in target.parents:
                logger.warning("Zip-slip rechazado: %s", sanitize_log_value(name))
                continue
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member) as fsrc, open(target, "wb") as fdst:
                shutil.copyfileobj(fsrc, fdst)


def _clone_git(url: str, dest: Path) -> None:
    """Clona un repo git deshabilitando hooks y config del sistema (T-M1-5)."""
    env = {
        **os.environ,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",  # nunca pedir credenciales interactivas
        "GIT_ASKPASS": "",
    }
    cmd = [
        "git",
        "-c", "core.hooksPath=/dev/null",  # hooks maliciosos del repo no corren
        "clone",
        "--no-local",
        "--no-hardlinks",
        "--depth", "1",
        url,
        str(dest),
    ]
    try:
        subprocess.run(
            cmd,
            env=env,
            check=True,
            capture_output=True,
            timeout=_GIT_TIMEOUT,
        )
    except FileNotFoundError as exc:
        raise IngestSourceError("git no está instalado o no está en PATH.") from exc
    except subprocess.TimeoutExpired as exc:
        raise IngestSourceError(f"git clone excedió {_GIT_TIMEOUT}s.") from exc
    except subprocess.CalledProcessError as exc:
        detail = sanitize_log_value((exc.stderr or b"").decode("utf-8", "replace")[:300])
        raise IngestSourceError(f"git clone falló: {detail}") from exc


def _download(url: str, dest: Path) -> None:
    """Descarga una URL http(s) al sandbox; si es zip, la extrae (T-M1-1)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise IngestSourceError(f"Esquema no soportado para descarga: {parsed.scheme}")
    filename = Path(parsed.path).name or "download"
    out = dest / filename
    req = Request(url, headers={"User-Agent": "HexFlaw"})
    try:
        with urlopen(req, timeout=_HTTP_TIMEOUT) as resp:  # noqa: S310 (esquema validado)
            total = 0
            with open(out, "wb") as fh:
                while True:
                    chunk = resp.read(64 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > _MAX_DOWNLOAD_BYTES:
                        raise IngestSourceError(
                            f"Descarga excede el tope de {_MAX_DOWNLOAD_BYTES} bytes."
                        )
                    fh.write(chunk)
    except OSError as exc:
        raise IngestSourceError(f"Fallo al descargar {sanitize_log_value(url)}: {exc}") from exc

    if filename.lower().endswith(".zip"):
        _extract_zip(out, dest)
        out.unlink(missing_ok=True)  # no dejar el archivo comprimido en el scope

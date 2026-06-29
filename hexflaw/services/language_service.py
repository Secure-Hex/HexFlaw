"""LanguageService — gestión del plugin system de lenguajes (CLAUDE.md §9b, §14).

Los módulos del pipeline nunca leen archivos JSON de lenguajes directamente:
siempre consultan a este servicio para obtener la definición activa.

Precedencia: custom (``~/.hexflaw/languages/custom/``) sobre builtin. En el
slice vertical, builtin se lee directo del paquete; el copiado a
``~/.hexflaw/languages/builtin/`` y los subcomandos ``languages`` quedan
pendientes.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from hexflaw.infrastructure import storage
from hexflaw.infrastructure.config import global_home
from hexflaw.infrastructure.logging import get_logger

logger = get_logger(__name__)

_BUILTIN_DIR = Path(__file__).resolve().parent.parent / "infrastructure" / "languages"

# Intérprete de shebang → id de lenguaje HexFlaw. Resuelve archivos sin extensión
# (CGIs, hooks, scripts en firmware). Solo surte efecto si existe la definición.
_SHEBANG_INTERPRETERS: dict[str, str] = {
    "python": "python",
    "node": "javascript",
    "nodejs": "javascript",
    "php": "php",
    "ruby": "ruby",
}

# Longitud máxima por campo string (CLAUDE.md §15, T-LANG-2).
_MAX_FIELD_LEN = 500

# Schema estricto: claves permitidas y su tipo Python esperado (T-LANG-2).
_ALLOWED_FIELDS: dict[str, type] = {
    "id": str,
    "name": str,
    "extensions": list,
    "tree_sitter_package": str,
    "app_types": list,
    "vuln_profile": list,
    "entry_point_patterns": list,
    "sink_patterns": list,
    "notes": str,
}
_REQUIRED_FIELDS = ("id", "name", "extensions")


def validate_definition_dict(data: dict) -> list[str]:
    """Valida un dict de definición de lenguaje contra el schema estricto.

    Aplica ``additionalProperties: false`` y los límites de longitud del threat
    model (CLAUDE.md §15, T-LANG-2).

    Args:
        data: Diccionario crudo a validar.

    Returns:
        Lista de errores (vacía si la definición es válida).
    """
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["La definición debe ser un objeto JSON."]
    for field_name in _REQUIRED_FIELDS:
        if field_name not in data:
            errors.append(f"Falta campo requerido: '{field_name}'")
    for key, value in data.items():
        expected = _ALLOWED_FIELDS.get(key)
        if expected is None:
            errors.append(f"Campo no permitido (additionalProperties=false): '{key}'")
            continue
        if not isinstance(value, expected):
            errors.append(f"Campo '{key}' debe ser {expected.__name__}")
        if isinstance(value, str) and len(value) > _MAX_FIELD_LEN:
            errors.append(f"Campo '{key}' excede {_MAX_FIELD_LEN} caracteres")
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str) and len(item) > _MAX_FIELD_LEN:
                    errors.append(f"Un elemento de '{key}' excede {_MAX_FIELD_LEN} caracteres")
                    break
    return errors


@dataclass
class LanguageDefinition:
    """Definición de cómo analizar un lenguaje (subset relevante al slice)."""

    id: str
    name: str
    extensions: list[str]
    app_types: list[str] = field(default_factory=list)
    vuln_profile: list[str] = field(default_factory=list)
    entry_point_patterns: list[str] = field(default_factory=list)
    sink_patterns: list[str] = field(default_factory=list)
    tree_sitter_package: str | None = None
    notes: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "LanguageDefinition":
        """Construye y valida una definición desde un dict JSON.

        Args:
            data: Diccionario crudo de la definición de lenguaje.

        Returns:
            Definición validada.

        Raises:
            ValueError: Si faltan campos requeridos o exceden límites de longitud.
        """
        for required in ("id", "name", "extensions"):
            if required not in data:
                raise ValueError(f"Definición de lenguaje sin campo requerido: '{required}'")
        for key, value in data.items():
            if isinstance(value, str) and len(value) > _MAX_FIELD_LEN:
                raise ValueError(f"Campo '{key}' excede {_MAX_FIELD_LEN} caracteres")
        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            extensions=list(data["extensions"]),
            app_types=list(data.get("app_types", [])),
            vuln_profile=list(data.get("vuln_profile", [])),
            entry_point_patterns=list(data.get("entry_point_patterns", [])),
            sink_patterns=list(data.get("sink_patterns", [])),
            tree_sitter_package=data.get("tree_sitter_package"),
            notes=str(data.get("notes", "")),
        )


def _home_builtin_dir() -> Path:
    """Directorio de builtins copiados al home (``~/.hexflaw/languages/builtin/``)."""
    return global_home() / "languages" / "builtin"


def _builtin_source() -> Path:
    """Fuente activa de builtins: el home si fue sincronizado, si no el paquete."""
    home = _home_builtin_dir()
    if home.is_dir() and any(home.glob("*.json")):
        return home
    return _BUILTIN_DIR


def sync_builtins() -> Path:
    """Copia los builtins del paquete al home con permisos ``444`` (inmutables).

    CLAUDE.md §14/§15: en la primera ejecución (``hexflaw setup``) los builtins se
    materializan en ``~/.hexflaw/languages/builtin/`` como solo-lectura, para que
    sean inspeccionables sin poder corromperlos. Re-copia solo los que cambiaron
    (actualización del paquete). Si algo falla, deja la fuente del paquete y avisa.

    Returns:
        El directorio de builtins efectivo tras el sync.
    """
    home = _home_builtin_dir()
    try:
        home.mkdir(parents=True, exist_ok=True)
        os.chmod(home, 0o700)  # escribible durante el sync
        for src in sorted(_BUILTIN_DIR.glob("*.json")):
            dst = home / src.name
            if dst.exists() and dst.read_bytes() == src.read_bytes():
                continue
            if dst.exists():
                os.chmod(dst, 0o644)  # hacer escribible para sobrescribir
            shutil.copyfile(src, dst)
            os.chmod(dst, 0o444)  # inmutable (solo lectura)
        os.chmod(home, 0o555)  # directorio inmutable tras el sync
    except OSError as exc:
        logger.warning("No se pudieron sincronizar los builtins a %s: %s", home, exc)
        return _BUILTIN_DIR
    return home


class LanguageService:
    """Carga y resuelve definiciones de lenguaje (builtin + custom)."""

    def __init__(self) -> None:
        self._by_id: dict[str, LanguageDefinition] = {}
        self._by_ext: dict[str, LanguageDefinition] = {}
        self._load_all()

    def _load_all(self) -> None:
        """Carga builtins (home si fue sincronizado, si no del paquete) y custom."""
        self._load_dir(_builtin_source())
        custom_dir = global_home() / "languages" / "custom"
        if custom_dir.is_dir():
            self._load_dir(custom_dir)  # precedencia: sobrescribe builtin

    def _load_dir(self, directory: Path) -> None:
        if not directory.is_dir():
            return
        for json_file in sorted(directory.glob("*.json")):
            try:
                definition = LanguageDefinition.from_dict(storage.read_json(json_file))
            except (ValueError, OSError) as exc:
                logger.warning("Definición de lenguaje inválida %s: %s", json_file, exc)
                continue
            self._by_id[definition.id] = definition
            for ext in definition.extensions:
                self._by_ext[ext.lower()] = definition

    def detect_by_extension(self, path: Path) -> LanguageDefinition | None:
        """Resuelve la definición de lenguaje a partir de la extensión de archivo.

        Args:
            path: Ruta del archivo.

        Returns:
            La definición correspondiente, o ``None`` si la extensión no se conoce.
        """
        return self._by_ext.get(path.suffix.lower())

    def detect_by_shebang(self, first_line: str) -> LanguageDefinition | None:
        """Resuelve la definición a partir de la primera línea (``#!`` shebang).

        Fallback para archivos sin extensión o con extensión desconocida (común en
        firmware: CGIs, hooks, scripts ejecutables). Solo resuelve a lenguajes con
        definición cargada; un intérprete sin definición (ej. ``bash`` si no hay
        ``bash.json``) devuelve ``None``.

        Args:
            first_line: Primera línea del archivo.

        Returns:
            La definición correspondiente, o ``None`` si no hay shebang reconocible.
        """
        line = first_line.strip()
        if not line.startswith("#!"):
            return None
        tokens = line[2:].split()
        if not tokens:
            return None
        # Forma 'env python3' → toma el primer token que no sea 'env' ni una opción.
        interp = tokens[0].rsplit("/", 1)[-1]
        if interp == "env":
            interp = next((t for t in tokens[1:] if not t.startswith("-")), "")
        interp = interp.rsplit("/", 1)[-1].lower()
        # Normaliza versiones embebidas: python3 → python, php8 → php, ruby2.7 → ruby.
        normalized = interp.rstrip("0123456789.")
        lang_id = _SHEBANG_INTERPRETERS.get(interp) or _SHEBANG_INTERPRETERS.get(
            normalized
        )
        return self._by_id.get(lang_id) if lang_id else None

    def get(self, language_id: str) -> LanguageDefinition | None:
        """Obtiene la definición activa de un lenguaje por su ``id``."""
        return self._by_id.get(language_id)

    def known_languages(self) -> list[str]:
        """Lista los ``id`` de todos los lenguajes cargados."""
        return sorted(self._by_id)

    @property
    def custom_dir(self) -> Path:
        """Directorio de definiciones custom (``~/.hexflaw/languages/custom/``)."""
        return global_home() / "languages" / "custom"

    def is_builtin(self, language_id: str) -> bool:
        """Indica si existe una definición builtin para ``language_id``."""
        return (_BUILTIN_DIR / f"{language_id}.json").exists()

    def is_custom(self, language_id: str) -> bool:
        """Indica si existe una definición custom para ``language_id``."""
        return (self.custom_dir / f"{language_id}.json").exists()

    def add_custom(self, data: dict, *, overwrite: bool = False) -> Path:
        """Agrega/actualiza una definición custom validándola primero.

        Args:
            data: Diccionario de la definición.
            overwrite: Si ``True``, permite sobrescribir una existente.

        Returns:
            Ruta del archivo JSON escrito.

        Raises:
            ValueError: Si la definición es inválida o ya existe sin overwrite.
        """
        errors = validate_definition_dict(data)
        if errors:
            raise ValueError("Definición inválida: " + "; ".join(errors))
        language_id = str(data["id"])
        target = self.custom_dir / f"{language_id}.json"
        if target.exists() and not overwrite:
            raise ValueError(
                f"Ya existe una definición custom para '{language_id}'. Usa overwrite."
            )
        storage.ensure_dir(self.custom_dir)
        storage.write_json(target, data, mode=0o600)
        self._by_id[language_id] = LanguageDefinition.from_dict(data)
        for ext in data["extensions"]:
            self._by_ext[str(ext).lower()] = self._by_id[language_id]
        logger.info("Definición custom agregada: %s", language_id)
        return target

    def remove_custom(self, language_id: str) -> bool:
        """Elimina una definición custom.

        Args:
            language_id: ``id`` del lenguaje custom a eliminar.

        Returns:
            ``True`` si se eliminó; ``False`` si no existía.
        """
        target = self.custom_dir / f"{language_id}.json"
        if not target.exists():
            return False
        target.unlink()
        logger.info("Definición custom eliminada: %s", language_id)
        return True

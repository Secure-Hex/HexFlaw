"""Detección de frameworks y overlay de sus patrones sobre el lenguaje.

Saber que un archivo es Python dice poco: ``def index(self)`` es una función más,
salvo que el proyecto sea Django, donde es un handler HTTP alcanzable por
cualquiera. El lenguaje define la sintaxis; el framework define **qué entra desde
afuera y qué sale hacia un intérprete**, que es exactamente lo que M3 necesita
para marcar entry points y sinks.

Las definiciones viven en ``hexflaw/infrastructure/frameworks/*.json`` y se
aplican como overlay en memoria sobre :class:`LanguageService`, igual que los
sinks aprendidos: son del proyecto analizado, no del sistema.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hexflaw.core.models import CodeChunk
from hexflaw.infrastructure.logging import get_logger

logger = get_logger(__name__)

_FRAMEWORK_DIR = Path(__file__).resolve().parent.parent / "infrastructure" / "frameworks"

#: Cuántos ARCHIVOS distintos deben mostrar un marcador para dar por presente al
#: framework. Se cuenta por archivo y no por chunk porque los marcadores típicos
#: son imports, y un import vive en un solo chunk por archivo: contar chunks
#: dejaba sin detectar a cualquier app de un solo módulo, que en Flask es lo normal.
#:
#: El umbral es 1 a propósito. Equivocarse de más —aplicar patrones de Flask a un
#: repo que apenas lo importa— cuesta candidatos de más, que el prefiltro filtra.
#: Equivocarse de menos cuesta no marcar un solo endpoint del proyecto, y M5 se
#: queda sin entry point desde el cual remontar el taint.
_MIN_MARKER_FILES = 1

#: Tamaño máximo de cada campo string, igual que en las definiciones de lenguaje.
_MAX_FIELD_LEN = 500


@dataclass(frozen=True)
class FrameworkDefinition:
    """Cómo reconocer un framework y qué patrones aporta al análisis."""

    id: str
    name: str
    language: str
    markers: list[str] = field(default_factory=list)
    also_languages: list[str] = field(default_factory=list)
    entry_point_patterns: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    sink_patterns: list[str] = field(default_factory=list)
    sanitizers: list[str] = field(default_factory=list)
    notes: str = ""

    @property
    def languages(self) -> list[str]:
        """Lenguajes a los que aplica (el propio más los compartidos)."""
        return [self.language, *self.also_languages]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FrameworkDefinition":
        """Construye y valida una definición desde un dict JSON.

        Args:
            data: Diccionario crudo de la definición.

        Returns:
            Definición validada.

        Raises:
            ValueError: Si faltan campos requeridos o algún string excede el límite.
        """
        for required in ("id", "name", "language", "markers"):
            if required not in data:
                raise ValueError(f"Definición de framework sin campo requerido: '{required}'")
        for key, value in data.items():
            if isinstance(value, str) and len(value) > _MAX_FIELD_LEN:
                raise ValueError(f"Campo '{key}' excede {_MAX_FIELD_LEN} caracteres")
        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            language=str(data["language"]),
            markers=[str(m) for m in data["markers"]],
            also_languages=[str(item) for item in data.get("also_languages", [])],
            entry_point_patterns=[str(p) for p in data.get("entry_point_patterns", [])],
            sources=[str(s) for s in data.get("sources", [])],
            sink_patterns=[str(p) for p in data.get("sink_patterns", [])],
            sanitizers=[str(s) for s in data.get("sanitizers", [])],
            notes=str(data.get("notes", "")),
        )


def load_definitions(directory: Path | None = None) -> list[FrameworkDefinition]:
    """Carga todas las definiciones de framework disponibles.

    Un archivo malformado se saltea con warning en vez de abortar: perder el
    soporte de un framework degrada el análisis, no lo invalida.

    Args:
        directory: Directorio de definiciones. Por defecto el del paquete.

    Returns:
        Lista de definiciones válidas.
    """
    source = directory or _FRAMEWORK_DIR
    definitions: list[FrameworkDefinition] = []
    for path in sorted(source.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            for entry in raw.get("frameworks", []):
                definitions.append(FrameworkDefinition.from_dict(entry))
        except (OSError, ValueError) as exc:
            logger.warning("Definición de framework ilegible en %s: %s", path, exc)
    return definitions


def detect(
    chunks: list[CodeChunk], definitions: list[FrameworkDefinition] | None = None
) -> list[FrameworkDefinition]:
    """Detecta qué frameworks usa el codebase mirando marcadores en el código.

    Args:
        chunks: Chunks de la ingestión.
        definitions: Definiciones candidatas. Por defecto, todas las del paquete.

    Returns:
        Frameworks presentes, ordenados por ``id``.
    """
    candidates = definitions if definitions is not None else load_definitions()
    by_language: dict[str, list[FrameworkDefinition]] = {}
    for definition in candidates:
        for language in definition.languages:
            by_language.setdefault(language, []).append(definition)

    files_by_framework: dict[str, set[str]] = {}
    found: dict[str, FrameworkDefinition] = {}
    for chunk in chunks:
        for definition in by_language.get(chunk.language, []):
            if any(marker in chunk.code for marker in definition.markers):
                files_by_framework.setdefault(definition.id, set()).add(chunk.file)
                found[definition.id] = definition

    detected = [
        found[fid]
        for fid, files in files_by_framework.items()
        if len(files) >= _MIN_MARKER_FILES
    ]
    for definition in detected:
        logger.info(
            "Framework detectado: %s (%d archivos con marcadores)",
            definition.name,
            len(files_by_framework[definition.id]),
        )
    return sorted(detected, key=lambda d: d.id)


def overlays(
    frameworks: list[FrameworkDefinition],
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Agrupa los patrones de los frameworks detectados por lenguaje.

    Args:
        frameworks: Frameworks detectados.

    Returns:
        Tupla ``(sinks_por_lenguaje, entry_points_por_lenguaje)``.
    """
    sinks: dict[str, set[str]] = {}
    entries: dict[str, set[str]] = {}
    for definition in frameworks:
        for language in definition.languages:
            sinks.setdefault(language, set()).update(definition.sink_patterns)
            entries.setdefault(language, set()).update(definition.entry_point_patterns)
    return (
        {lang: sorted(values) for lang, values in sinks.items() if values},
        {lang: sorted(values) for lang, values in entries.items() if values},
    )


def taint_patterns(
    frameworks: list[FrameworkDefinition], language: str
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Fuentes y sanitizadores aportados por los frameworks activos.

    Las fuentes son la mitad que más importa: sin ellas el grafo no sabe que
    ``request.args.get("x")`` devuelve un dato del atacante, y el flujo hacia el
    sink nunca se marca. Los parámetros de una función se siembran como tainted
    por defecto, pero un handler HTTP no recibe parámetros — lee del request.

    Args:
        frameworks: Frameworks detectados.
        language: Lenguaje a consultar.

    Returns:
        Tupla ``(fuentes, sanitizadores)``, sin duplicados y ordenadas.
    """
    sources: set[str] = set()
    sanitizers: set[str] = set()
    for definition in frameworks:
        if language in definition.languages:
            sources.update(definition.sources)
            sanitizers.update(definition.sanitizers)
    return tuple(sorted(sources)), tuple(sorted(sanitizers))

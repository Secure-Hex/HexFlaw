"""Helper HTTP mínimo para backends de embeddings por API (stdlib only).

Usa ``urllib`` para no agregar dependencias. Los backends que lo usan envían
código a un proveedor externo para vectorizarlo: esto implica que el código sale
de la máquina, por lo que solo deben usarse por **decisión explícita** del
usuario (CLAUDE.md §2.3). El default recomendado sigue siendo ``local-cpu``.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class EmbeddingHTTPError(RuntimeError):
    """Error de transporte o de la API de embeddings remota."""


def post_json(
    url: str, payload: dict[str, Any], headers: dict[str, str], *, timeout: float = 30.0
) -> dict[str, Any]:
    """Realiza un POST JSON y devuelve la respuesta parseada.

    Args:
        url: Endpoint destino.
        payload: Cuerpo a serializar como JSON.
        headers: Cabeceras HTTP (incluida la autenticación).
        timeout: Timeout en segundos.

    Returns:
        Respuesta JSON deserializada.

    Raises:
        EmbeddingHTTPError: Ante error de red, HTTP o JSON inválido.
    """
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="POST")
    request.add_header("Content-Type", "application/json")
    for key, value in headers.items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:300]
        raise EmbeddingHTTPError(f"HTTP {exc.code} de {url}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise EmbeddingHTTPError(f"Fallo al contactar {url}: {exc}") from exc

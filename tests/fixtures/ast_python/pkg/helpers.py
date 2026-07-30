"""Fixture de M3: destino de una llamada calificada cross-file (helpers.write)."""

import os


def write(data):
    """Sink real: os.system con dato entrante."""
    os.system(data)

"""Fixture de M3: homónimo de app.run_command para probar la desambiguación."""


def run_command(cmd):
    """Mismo nombre que app.run_command, otro archivo: no deben mezclarse."""
    return len(cmd)


def caller(cmd):
    """Debe ligarse al run_command de ESTE archivo, no al de app.py."""
    run_command(cmd)

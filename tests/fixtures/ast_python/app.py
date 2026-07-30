"""Fixture de M3: resolución de llamadas, alias de import y métodos vía AST."""

import subprocess as sp
from os import system as syscmd

from pkg import helpers


def handler(cmd):
    """Entry point que delega en run_command (arista esperada)."""
    run_command(cmd)


def run_command(cmd):
    """Sinks vía alias: sp.run -> subprocess.run, syscmd -> os.system."""
    sp.run(cmd, shell=True)
    syscmd(cmd)
    helpers.write(cmd)


def inert(value):
    """Llama a execute sin ser un método: no debe ligarse a Controller.execute."""
    return len(value)


class Controller:
    """Clase con dos métodos donde uno llama al otro por self."""

    LIMIT = 5

    def handle(self, req):
        self.execute(req)

    def execute(self, req):
        sp.Popen(req)

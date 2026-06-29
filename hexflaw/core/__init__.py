"""Core Engine — orquestación del pipeline, agnóstica a interfaz y backends.

Esta capa nunca importa nada de ``hexflaw.cli``. La dependencia va en una sola
dirección: CLI → Core → Services → Infrastructure.
"""

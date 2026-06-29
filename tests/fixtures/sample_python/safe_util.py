"""Fixture de control: código sin sinks peligrosos (debe filtrarse en M4 capa 1)."""


def add(a: int, b: int) -> int:
    """Suma dos enteros."""
    return a + b


def greet(name: str) -> str:
    """Devuelve un saludo formateado."""
    return f"Hola, {name}"

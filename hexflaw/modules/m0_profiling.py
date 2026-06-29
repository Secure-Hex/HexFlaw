"""M0 — System Profiling (CLAUDE.md §6 M0, §15 M0).

Detecta el hardware disponible, mide un benchmark rápido de embeddings y
recomienda el backend óptimo según la lógica de la especificación.

Privacidad: el chequeo de conectividad solo abre un socket a un host público
conocido; no envía datos. El benchmark no es influenciable por variables de
entorno no documentadas (T-M0-1).
"""

from __future__ import annotations

import os
import platform
import shutil
import socket
import time
from pathlib import Path

from hexflaw.core.models import SystemProfile
from hexflaw.infrastructure.logging import get_logger
from hexflaw.services.embedding import get_embedding_service

logger = get_logger(__name__)

_BENCH_SAMPLE = "int main(int argc, char **argv) { return system(argv[1]); }"


def profile_system() -> SystemProfile:
    """Ejecuta el perfilado completo del sistema.

    Returns:
        :class:`SystemProfile` con detección, benchmark y recomendación.
    """
    cpu_model, cpu_freq = _detect_cpu()
    ram_gb = _detect_ram_gb()
    gpu_type = _detect_gpu()
    ollama = _detect_ollama()
    internet = _detect_internet()
    benchmarks = _benchmark_embeddings()

    backend, reason = recommend_backend(
        ram_gb=ram_gb, gpu_type=gpu_type, ollama=ollama, internet=internet
    )

    profile = SystemProfile(
        cpu_model=cpu_model,
        cpu_cores=os.cpu_count() or 0,
        cpu_freq_mhz=cpu_freq,
        ram_total_gb=round(ram_gb, 1),
        gpu_detected=gpu_type is not None,
        gpu_type=gpu_type,
        ollama_available=ollama,
        internet=internet,
        benchmarks=benchmarks,
        recommended_backend=backend,
        recommendation_reason=reason,
    )
    logger.info("System profile: backend recomendado=%s (%s)", backend, reason)
    return profile


def recommend_backend(
    *, ram_gb: float, gpu_type: str | None, ollama: bool, internet: bool
) -> tuple[str, str]:
    """Aplica la lógica de recomendación de backend (CLAUDE.md §6 M0).

    Args:
        ram_gb: RAM total en GB.
        gpu_type: Tipo de GPU detectada (``"cuda"``/``"rocm"``/``"metal"``) o ``None``.
        ollama: Si Ollama está disponible.
        internet: Si hay conectividad a internet.

    Returns:
        Tupla ``(backend_id, razón)``.
    """
    # Sin internet → forzar backend local (local-cpu u ollama).
    if not internet:
        if gpu_type and ollama:
            return "ollama", "Sin internet y GPU+Ollama disponibles."
        return "local-cpu", "Sin internet: backend local obligatorio."

    # GPU disponible → ollama (nomic-embed-code) si está instalado.
    if gpu_type:
        if ollama:
            return "ollama", f"GPU {gpu_type} + Ollama disponibles (nomic-embed-code)."
        return "local-cpu", f"GPU {gpu_type} detectada pero Ollama no está instalado."

    # Sin GPU, según RAM.
    if ram_gb >= 16:
        return "local-cpu", "RAM suficiente para inferencia en CPU, sin dependencia externa."
    if ram_gb >= 8:
        return "local-cpu", "RAM suficiente para CPU; voyage es alternativa si se requiere velocidad."
    return "voyage", "RAM insuficiente para inferencia local; se requiere backend por API."


def _detect_cpu() -> tuple[str, float | None]:
    """Detecta modelo y frecuencia de CPU (Linux: ``/proc/cpuinfo``)."""
    model = platform.processor() or platform.machine() or "unknown"
    freq: float | None = None
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        try:
            for line in cpuinfo.read_text(errors="replace").splitlines():
                if line.startswith("model name") and ":" in line:
                    model = line.split(":", 1)[1].strip()
                elif line.lower().startswith("cpu mhz") and ":" in line and freq is None:
                    freq = float(line.split(":", 1)[1].strip())
        except (OSError, ValueError) as exc:
            logger.debug("No se pudo parsear /proc/cpuinfo: %s", exc)
    return model, freq


def _detect_ram_gb() -> float:
    """Detecta RAM total en GB (Linux ``/proc/meminfo`` o ``sysconf``)."""
    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        try:
            for line in meminfo.read_text(errors="replace").splitlines():
                if line.startswith("MemTotal"):
                    kb = float(line.split()[1])
                    return kb / (1024 * 1024)
        except (OSError, ValueError, IndexError) as exc:
            logger.debug("No se pudo parsear /proc/meminfo: %s", exc)
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        return (pages * page_size) / (1024**3)
    except (ValueError, OSError, AttributeError):
        return 0.0


def _detect_gpu() -> str | None:
    """Detecta GPU acelerada: CUDA, ROCm o Metal (Apple Silicon)."""
    if shutil.which("nvidia-smi"):
        return "cuda"
    if shutil.which("rocminfo"):
        return "rocm"
    if platform.system() == "Darwin" and platform.machine() == "arm64":
        return "metal"
    return None


def _detect_ollama() -> bool:
    """Detecta si Ollama está instalado u operativo en el puerto estándar."""
    if shutil.which("ollama"):
        return True
    return _can_connect("127.0.0.1", 11434, timeout=0.5)


def _detect_internet() -> bool:
    """Comprueba conectividad abriendo un socket a un host público conocido."""
    return _can_connect("1.1.1.1", 443, timeout=2.0)


def _can_connect(host: str, port: int, *, timeout: float) -> bool:
    """Intenta una conexión TCP corta; ``True`` si tiene éxito."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _benchmark_embeddings() -> dict[str, float]:
    """Mide ms por embedding del backend local (siempre disponible).

    Returns:
        Mapa ``backend_id -> ms``. Solo incluye backends instanciables sin red.
    """
    results: dict[str, float] = {}
    try:
        service = get_embedding_service("local-cpu")
        start = time.perf_counter()
        for _ in range(5):
            service.embed(_BENCH_SAMPLE)
        elapsed_ms = (time.perf_counter() - start) / 5 * 1000
        results["local-cpu"] = round(elapsed_ms, 2)
    except (ValueError, RuntimeError) as exc:
        logger.debug("Benchmark local-cpu falló: %s", exc)
    return results

"""Selecciona el motor de análisis dinámico disponible."""
from __future__ import annotations

from ..config import config
from ..models import DynamicResult
from .triage import run_triage


def run_dynamic(filename: str, data: bytes) -> DynamicResult:
    """Ejecuta el análisis dinámico si hay un sandbox configurado.

    De momento el motor implementado es tria.ge. VirusTotal u otros se
    añadirían aquí con la misma interfaz (filename, data) -> DynamicResult.
    """
    if config.triage_api_key:
        return run_triage(filename, data)
    return DynamicResult(engine="ninguno", error="sin sandbox configurado")

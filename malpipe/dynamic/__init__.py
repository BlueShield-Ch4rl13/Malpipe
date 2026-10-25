"""Selecciona el motor de análisis dinámico disponible."""
from __future__ import annotations

from ..config import config
from ..models import DynamicResult, FamilyConfig
from .cape import run_cape
from .triage import run_triage


def run_dynamic(filename: str, data: bytes) -> tuple[DynamicResult, list[FamilyConfig]]:
    """Detona la muestra en el sandbox configurado (MALPIPE_SANDBOX).

    Devuelve el resultado y las configuraciones de familia que haya extraído el
    sandbox (CAPEv2 las saca del volcado de memoria; tria.ge no las da por API).
    """
    motor = config.motor_dinamico
    if motor == "cape":
        return run_cape(filename, data)
    if motor == "triage":
        return run_triage(filename, data), []
    return DynamicResult(engine="ninguno", error="sin sandbox configurado (CAPE_URL o TRIAGE_API_KEY)"), []

"""Configuración del pipeline. Todo lo sensible se lee de variables de entorno."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class Config:
    # --- Sandbox dinámico ---
    # Solo tria.ge está implementado. (Hubo una variable VT_API_KEY que
    # activaba el dinámico sin que existiera un cliente de VirusTotal.)
    triage_api_key: str = os.getenv("TRIAGE_API_KEY", "")
    triage_base_url: str = os.getenv("TRIAGE_BASE_URL", "https://tria.ge/api/v0")
    # El portal web solo manda muestras de terceros al sandbox si se pide de
    # forma explícita: cada subida va a tria.ge con TU cuenta (y en las cuentas
    # gratuitas el análisis es público).
    web_dynamic: bool = os.getenv("MALPIPE_WEB_DYNAMIC", "0") == "1"

    # --- Comportamiento ---
    # Segundos máximos esperando el informe del sandbox antes de rendirse.
    dynamic_timeout: int = int(os.getenv("MALPIPE_DYNAMIC_TIMEOUT", "300"))
    # Reglas YARA
    yara_rules_dir: str = os.getenv("MALPIPE_YARA_DIR", "rules")
    # Nº máximo de strings "interesantes" que se guardan en el informe
    max_strings: int = int(os.getenv("MALPIPE_MAX_STRINGS", "40"))

    @property
    def dynamic_available(self) -> bool:
        return bool(self.triage_api_key)


config = Config()

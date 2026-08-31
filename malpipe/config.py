"""Configuración del pipeline. Todo lo sensible se lee de variables de entorno."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class Config:
    # --- Sandbox dinámico (elige uno) ---
    triage_api_key: str = os.getenv("TRIAGE_API_KEY", "")
    triage_base_url: str = os.getenv("TRIAGE_BASE_URL", "https://tria.ge/api/v0")
    vt_api_key: str = os.getenv("VT_API_KEY", "")

    # --- Comportamiento ---
    # Segundos máximos esperando el informe del sandbox antes de rendirse.
    dynamic_timeout: int = int(os.getenv("MALPIPE_DYNAMIC_TIMEOUT", "300"))
    # Reglas YARA
    yara_rules_dir: str = os.getenv("MALPIPE_YARA_DIR", "rules")
    # Nº máximo de strings "interesantes" que se guardan en el informe
    max_strings: int = int(os.getenv("MALPIPE_MAX_STRINGS", "40"))

    @property
    def dynamic_available(self) -> bool:
        return bool(self.triage_api_key or self.vt_api_key)


config = Config()

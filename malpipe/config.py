"""Configuración del pipeline. Todo lo sensible se lee de variables de entorno."""
from __future__ import annotations

import os
from dataclasses import dataclass


def env(nombre: str, defecto: str = "") -> str:
    """Una variable vacia cuenta como no puesta: docker compose pasa "VAR=" de
    .env como cadena vacia, y int("") tumbaba el arranque."""
    return os.getenv(nombre) or defecto


def env_int(nombre: str, defecto: int) -> int:
    return int(env(nombre, str(defecto)))


@dataclass
class Config:
    # --- Sandbox dinámico ---
    # Dos motores: CAPEv2 propio (la muestra no sale de tu red) y tria.ge.
    # MALPIPE_SANDBOX: auto (CAPE si hay CAPE_URL, si no tria.ge si hay clave),
    # cape o triage.
    sandbox: str = env("MALPIPE_SANDBOX", "auto")
    cape_url: str = env("CAPE_URL", "")
    cape_token: str = env("CAPE_TOKEN", "")
    cape_options: str = env("CAPE_OPCIONES", "")
    cape_verify_tls: bool = env("CAPE_VERIFICAR_TLS", "1") != "0"
    cape_intervalo: int = env_int("CAPE_INTERVALO", 15)
    triage_api_key: str = env("TRIAGE_API_KEY", "")
    triage_base_url: str = env("TRIAGE_BASE_URL", "https://tria.ge/api/v0")
    # El portal web solo manda muestras de terceros al sandbox si se pide de
    # forma explícita: cada subida va a tria.ge con TU cuenta (y en las cuentas
    # gratuitas el análisis es público).
    web_dynamic: bool = env("MALPIPE_WEB_DYNAMIC", "0") == "1"

    # --- Comportamiento ---
    # Segundos máximos esperando el informe del sandbox antes de rendirse.
    dynamic_timeout: int = env_int("MALPIPE_DYNAMIC_TIMEOUT", 300)
    # Reglas YARA
    yara_rules_dir: str = env("MALPIPE_YARA_DIR", "rules")
    # Nº máximo de strings "interesantes" que se guardan en el informe
    max_strings: int = env_int("MALPIPE_MAX_STRINGS", 40)

    # --- News CTI ---
    cti_url: str = env("MALPIPE_CTI_URL", "")

    @property
    def motor_dinamico(self) -> str:
        if self.sandbox == "cape" or (self.sandbox == "auto" and self.cape_url):
            return "cape" if self.cape_url else ""
        if self.sandbox in ("triage", "auto") and self.triage_api_key:
            return "triage"
        return ""

    @property
    def dynamic_available(self) -> bool:
        return bool(self.motor_dinamico)


config = Config()

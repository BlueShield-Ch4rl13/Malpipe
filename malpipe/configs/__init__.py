"""Extraccion de la configuracion de familias conocidas.

Cada extractor recibe los bytes de la muestra y devuelve una FamilyConfig si
reconoce el formato de su familia, o None. Ninguno ejecuta nada: leen
estructuras documentadas publicamente (Cobalt Strike, Remcos) o, en el caso de
njRAT, buscan su marca y sus cadenas tipicas (confianza media).

Limites, para leer el resultado con criterio:
  - Funcionan sobre la muestra tal cual. Si esta empaquetada o cifrada (lo
    normal en una muestra real de primera fase), la configuracion no esta en
    claro y no sale nada: hace falta el volcado de memoria del sandbox, que es
    justo lo que CAPEv2 entrega en sus "configs".
  - Se han probado con muestras sinteticas que reproducen cada formato, no con
    malware real (en tests/test_configs.py esta como se construyen).
"""
from __future__ import annotations

import logging

from ..models import FamilyConfig
from . import cobaltstrike, njrat, remcos

log = logging.getLogger("malpipe.configs")

EXTRACTORES = (cobaltstrike.extraer, remcos.extraer, njrat.extraer)


def extraer_configuraciones(data: bytes) -> list[FamilyConfig]:
    encontradas: list[FamilyConfig] = []
    for extractor in EXTRACTORES:
        try:
            cfg = extractor(data)
        except Exception as e:  # noqa: BLE001 - un formato roto no tumba el analisis
            log.debug("extractor %s fallo: %s", extractor.__module__, e)
            continue
        if cfg is not None:
            encontradas.append(cfg)
    return encontradas


__all__ = ["extraer_configuraciones", "EXTRACTORES"]

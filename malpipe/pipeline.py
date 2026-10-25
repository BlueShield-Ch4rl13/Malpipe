"""Orquestador del pipeline: encadena las fases y devuelve el informe."""
from __future__ import annotations

import logging
import os

from .configs import extraer_configuraciones
from .dynamic import run_dynamic
from .enrich.attack import map_attack
from .enrich.cti import cruzar
from .enrich.verdict import score_report
from .models import Report, YaraMatch
from .static import run_static

log = logging.getLogger("malpipe")


def analyze_bytes(
    filename: str,
    data: bytes,
    *,
    do_dynamic: bool = True,
    cti_feed: dict | None = None,
    yara_matches: list[YaraMatch] | None = None,
) -> Report:
    """Analiza el contenido de un fichero (en memoria) y devuelve el informe.

    No toca el disco: util para el backend web y para el portal en el
    navegador, que no deben guardar los ficheros que sube la gente.

    cti_feed: el iocs_latest.json de News CTI ya cargado; si se pasa, se cruzan
    los indicadores de la muestra con el. yara_matches: coincidencias YARA ya
    calculadas fuera (el portal del navegador escanea con YARA-X en JavaScript);
    si se pasan, sustituyen al escaneo con yara-python.
    """
    report = Report()
    report.static = run_static(filename, data)
    if yara_matches is not None:
        report.static.yara = list(yara_matches)
    report.configs = extraer_configuraciones(data)

    if do_dynamic:
        report.dynamic, configs_sandbox = run_dynamic(filename, data)
        conocidas = {(c.family, tuple(c.c2)) for c in report.configs}
        report.configs += [c for c in configs_sandbox if (c.family, tuple(c.c2)) not in conocidas]

    if cti_feed is not None:
        try:
            report.cti = cruzar(report.static, report.dynamic, report.configs, cti_feed)
        except Exception as exc:  # noqa: BLE001 - un feed raro no tumba el analisis
            report.cti.error = f"{type(exc).__name__}: {exc}"

    report.attack = map_attack(report.static, report.dynamic)
    score_report(report)
    return report


def analyze(filepath: str, *, do_dynamic: bool = True, cti_feed: dict | None = None) -> Report:
    """Analiza un fichero del disco y devuelve el informe completo.

    do_dynamic=False fuerza solo estático aunque haya sandbox configurado.
    """
    with open(filepath, "rb") as f:
        data = f.read()
    return analyze_bytes(os.path.basename(filepath), data, do_dynamic=do_dynamic, cti_feed=cti_feed)

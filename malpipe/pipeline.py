"""Orquestador del pipeline: encadena las fases y devuelve el informe."""
from __future__ import annotations

import os

from .dynamic import run_dynamic
from .enrich.attack import map_attack
from .enrich.verdict import score_report
from .models import Report
from .static import run_static


def analyze_bytes(
    filename: str, data: bytes, *, do_dynamic: bool = True
) -> Report:
    """Analiza el contenido de un fichero (en memoria) y devuelve el informe.

    No toca el disco: útil para el backend web, que no debe persistir los
    ficheros que suben los usuarios.
    """
    report = Report()
    report.static = run_static(filename, data)

    if do_dynamic:
        report.dynamic = run_dynamic(filename, data)

    report.attack = map_attack(report.static, report.dynamic)
    score_report(report)
    return report


def analyze(filepath: str, *, do_dynamic: bool = True) -> Report:
    """Analiza un fichero del disco y devuelve el informe completo.

    do_dynamic=False fuerza solo estático aunque haya sandbox configurado.
    """
    with open(filepath, "rb") as f:
        data = f.read()
    return analyze_bytes(os.path.basename(filepath), data, do_dynamic=do_dynamic)

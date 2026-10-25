"""Puntuación agregada y veredicto. Heurística transparente y explicable:
cada punto que suma queda escrito en report.reasons."""
from __future__ import annotations

from ..models import Report

# Umbrales del veredicto sobre 100
_MALICIOUS = 70
_SUSPICIOUS = 35

# Entropía por encima de la cual una sección parece empaquetada/cifrada
_HIGH_ENTROPY = 7.2


def score_report(report: Report) -> None:
    """Rellena report.score (0-100), report.verdict y report.reasons in-place.

    Cada razón empieza por lo que aporta: "+N" suma N puntos; "≥N" fija un
    mínimo de N (una familia identificada o un hash conocido son malware por sí
    solos, sumen lo que sumen las demás señales)."""
    score = 0
    razones: list[str] = []
    st = report.static
    dy = report.dynamic

    def sumar(puntos: int, motivo: str) -> None:
        nonlocal score
        if puntos:
            score += puntos
            razones.append(f"+{puntos} {motivo}")

    # --- Señales estáticas ---
    sumar(min(len(st.pe.suspicious_imports) * 4, 24),
          f"{len(st.pe.suspicious_imports)} import(s) de API sospechosa")
    if any(s.entropy >= _HIGH_ENTROPY for s in st.pe.sections):
        sumar(12, f"sección con entropía >= {_HIGH_ENTROPY} (posible empaquetado o cifrado)")
    if st.yara:
        sumar(20, f"YARA: {', '.join(sorted({m.rule for m in st.yara}))}")
    if st.indicators.urls or st.indicators.domains:
        sumar(6, "URL o dominios en las cadenas")

    # --- Señales dinámicas (las de más peso) ---
    if dy.analyzed and dy.score is not None:
        # tria.ge y CAPE puntúan 0-10 -> lo llevamos a 0-50
        sumar(int(dy.score * 5), f"{dy.engine}: {dy.score}/10")

    # --- Cobertura ATT&CK ---
    sumar(min(len(report.attack) * 3, 15), f"{len(report.attack)} técnica(s) ATT&CK")

    # --- News CTI: la red de la muestra ya está fichada ---
    red = [m for m in report.cti.matches if not m.type.startswith("filehash")]
    sumar(min(len(red) * 10, 20), f"{len(red)} indicador(es) de red ya en News CTI")

    # --- Lo que fija el veredicto como mínimo ---
    if dy.family:
        score = max(score, _MALICIOUS)
        razones.append(f"≥{_MALICIOUS} familia identificada por el sandbox: {dy.family}")
    familias = sorted({c.family for c in report.configs if c.confidence == "alta"})
    if familias:
        score = max(score, _MALICIOUS)
        razones.append(f"≥{_MALICIOUS} configuración de {', '.join(familias)} extraída")
    if any(m.type.startswith("filehash") for m in report.cti.matches):
        score = max(score, 80)
        razones.append("≥80 el hash de la muestra ya está en News CTI")

    report.score = max(0, min(score, 100))
    report.reasons = razones

    if report.score >= _MALICIOUS:
        report.verdict = "malicioso"
    elif report.score >= _SUSPICIOUS:
        report.verdict = "sospechoso"
    else:
        report.verdict = "limpio" if dy.analyzed else "desconocido"

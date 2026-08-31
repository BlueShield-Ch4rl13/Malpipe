"""Puntuación agregada y veredicto. Heurística transparente y explicable."""
from __future__ import annotations

from ..models import Report

# Umbrales del veredicto sobre 100
_MALICIOUS = 70
_SUSPICIOUS = 35

# Entropía por encima de la cual una sección parece empaquetada/cifrada
_HIGH_ENTROPY = 7.2


def score_report(report: Report) -> None:
    """Rellena report.score (0-100) y report.verdict in-place."""
    score = 0
    st = report.static
    dy = report.dynamic

    # --- Señales estáticas ---
    score += min(len(st.pe.suspicious_imports) * 4, 24)
    if any(s.entropy >= _HIGH_ENTROPY for s in st.pe.sections):
        score += 12  # posible packer
    if st.yara:
        score += 20
    if st.indicators.urls or st.indicators.domains:
        score += 6

    # --- Señales dinámicas (las de más peso) ---
    if dy.analyzed and dy.score is not None:
        # tria.ge puntúa 0-10 -> lo llevamos a 0-50
        score += int(dy.score * 5)
    if dy.family:
        score = max(score, _MALICIOUS)  # familia conocida = malicioso

    # --- Cobertura ATT&CK ---
    score += min(len(report.attack) * 3, 15)

    report.score = max(0, min(score, 100))

    if report.score >= _MALICIOUS:
        report.verdict = "malicioso"
    elif report.score >= _SUSPICIOUS:
        report.verdict = "sospechoso"
    else:
        report.verdict = "limpio" if dy.analyzed else "desconocido"

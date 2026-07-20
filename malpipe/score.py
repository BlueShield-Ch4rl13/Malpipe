"""Puntuación de peligrosidad de la muestra (estática).

Combina las señales del análisis estático en una puntuación explicable 0-100 y
un veredicto. Como en un buen triaje, cada punto viene de una razón concreta;
no es un antivirus, es una priorización para decidir a qué muestra dedicar el
análisis dinámico o el reversing.
"""
from __future__ import annotations

# Peso por severidad de regla YARA
YARA_WEIGHT = {"high": 30, "medium": 18, "low": 8, "info": 0}
# Capacidades de alto impacto (suman más)
HIGH_IMPACT = {"Inyección de código", "Cifrado (posible ransomware)", "Robo de credenciales",
               "Hollowing / mapeo de secciones", "Evasión: deshabilitar defensas"}

BANDS = [(0, 24, "benigno", "Sin indicios de malware", "#4FD6C4"),
         (25, 54, "sospechoso", "Sospechoso — requiere análisis", "#E0A34A"),
         (55, 79, "probable", "Probablemente malicioso", "#FF9F45"),
         (80, 100, "malicioso", "Muy probablemente malicioso", "#F0616D")]


def _band(score):
    for lo, hi, key, label, color in BANDS:
        if lo <= score <= hi:
            return key, label, color
    return "malicioso", "Muy probablemente malicioso", "#F0616D"


def score(identity: dict, pe: dict, capabilities: list, yara_hits: list, iocs: list) -> dict:
    risk = 0
    reasons: list[dict] = []

    def add(pts, label):
        nonlocal risk
        risk += pts
        reasons.append({"points": pts, "label": label})

    # YARA (la señal más fuerte)
    for m in yara_hits:
        sev = (m.get("meta", {}) or {}).get("severity", "medium")
        w = YARA_WEIGHT.get(sev, 12)
        if w:
            add(w, f"Regla YARA: {m['rule']} ({sev})")

    # Capacidades ATT&CK
    for c in capabilities:
        pts = 12 if c["capability"] in HIGH_IMPACT else 5
        add(pts, f"Capacidad: {c['capability']} ({c['attack']})")

    # Empaquetado / entropía
    ent = identity.get("entropy", 0)
    if ent >= 7.2:
        add(15, f"Entropía global muy alta ({ent}) — empaquetado o cifrado")

    # Anomalías estructurales del PE
    anoms = (pe or {}).get("anomalies", [])
    for a in anoms:
        if "RWX" in a or "empaquetado" in a:
            add(8, a)
        else:
            add(3, a)

    # Firma ausente en un PE (no concluyente)
    if pe and not pe.get("has_signature") and pe.get("sections"):
        add(4, "PE sin firma digital embebida")

    # IOCs de red incrustados
    net = sum(1 for i in iocs if i["type"] in ("url", "ipv4", "domain"))
    if net:
        add(min(12, net * 3), f"{net} indicador(es) de red incrustado(s)")

    risk = min(100, risk)
    reasons.sort(key=lambda r: r["points"], reverse=True)
    key, label, color = _band(risk)

    # Confianza según cuánta señal estática hubo
    signals = len(yara_hits) + len(capabilities) + len(anoms)
    confidence = "alta" if signals >= 6 else "media" if signals >= 2 else "baja"

    return {"risk_score": risk, "verdict_key": key, "verdict": label, "verdict_color": color,
            "confidence": confidence, "reasons": reasons[:12]}

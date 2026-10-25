"""Informe -> evento MISP (formato JSON de importacion de MISP).

Un evento por muestra con sus atributos (hashes, nombre, IP, dominios, URL,
correos y los C2 de la configuracion), etiquetado TLP:AMBER y con las tecnicas
ATT&CK como etiquetas de la galaxia mitre-attack-pattern. Se importa en MISP
desde Events > Import from... > MISP JSON, o con PyMISP (add_event).

Los atributos de red y los hashes van con to_ids solo si el veredicto es
malicioso: un IOC de una muestra limpia no debe acabar en las reglas de
deteccion de nadie.
"""
from __future__ import annotations

import ipaddress
import uuid

from ..models import Report

ESPACIO = uuid.UUID("6b1c1bd6-5a51-4f5e-9c6f-6d6d2d3a6a10")    # propio de malpipe
NIVEL = {"malicioso": "1", "sospechoso": "2", "limpio": "3", "desconocido": "4"}


def _uuid(*partes: object) -> str:
    return str(uuid.uuid5(ESPACIO, "|".join(str(p) for p in partes)))


def _es_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def a_misp(report: Report) -> dict:
    st = report.static
    ids = report.verdict == "malicioso"
    atributos: list[dict] = []

    def attr(tipo: str, categoria: str, valor: str, to_ids: bool, comentario: str = "") -> None:
        if not valor:
            return
        if any(a["type"] == tipo and a["value"] == valor for a in atributos):
            return
        atributos.append({"uuid": _uuid(st.hashes.sha256, tipo, valor), "type": tipo, "category": categoria,
                          "value": valor, "to_ids": to_ids, "comment": comentario})

    attr("filename", "Payload delivery", st.filename, False)
    attr("sha256", "Payload delivery", st.hashes.sha256, ids)
    attr("sha1", "Payload delivery", st.hashes.sha1, ids)
    attr("md5", "Payload delivery", st.hashes.md5, ids)
    attr("imphash", "Payload delivery", st.hashes.imphash, False)
    attr("ssdeep", "Payload delivery", st.hashes.ssdeep, False)
    for ip in st.indicators.ips:
        attr("ip-dst", "Network activity", ip, ids, "en las cadenas de la muestra")
    for d in st.indicators.domains:
        attr("domain", "Network activity", d, ids, "en las cadenas de la muestra")
    for u in st.indicators.urls:
        attr("url", "Network activity", u, ids, "en las cadenas de la muestra")
    for e in st.indicators.emails:
        attr("email-src", "Payload delivery", e, False, "en las cadenas de la muestra")
    for cfg in report.configs:
        for c2 in cfg.c2:
            comentario = f"C2 de {cfg.family} (configuracion extraida, confianza {cfg.confidence})"
            if "://" in c2:
                attr("url", "Network activity", c2, True, comentario)
            elif c2.count(":") == 1:
                host, puerto = c2.split(":")
                attr("ip-dst|port" if _es_ip(host) else "hostname|port", "Network activity",
                     f"{host}|{puerto}", True, comentario)
            else:
                attr("ip-dst" if _es_ip(c2) else "hostname", "Network activity", c2, True, comentario)
    for y in st.yara:
        attr("comment", "Other", f"YARA: {y.rule}", False)

    etiquetas = [{"name": "tlp:amber"}, {"name": f'malpipe:veredicto="{report.verdict}"'}]
    for t in report.attack:
        etiquetas.append({"name": f'misp-galaxy:mitre-attack-pattern="{t.name} - {t.id}"'})
    familias = sorted({c.family for c in report.configs}
                      | ({report.dynamic.family} if report.dynamic.family else set()))

    return {"Event": {
        "uuid": _uuid(st.hashes.sha256, report.generated_at),
        "info": f"malpipe: {st.filename} - {report.verdict} ({report.score}/100)"
                + (f" - {', '.join(familias)}" if familias else ""),
        "date": report.generated_at[:10],
        "threat_level_id": NIVEL.get(report.verdict, "4"),
        "analysis": "2",
        "distribution": "0",
        "Tag": etiquetas,
        "Attribute": atributos,
    }}

"""Informe -> bundle STIX 2.1.

Que lleva:
  - la muestra como objeto file (hashes, nombre, tamano) y un malware-analysis
    de malpipe con su resultado (malicious, suspicious, benign o unknown);
  - un indicator con patron STIX por cada IOC (hashes, IP, dominios, URL y C2);
  - si el veredicto es malicioso o hay familia: un objeto malware, las tecnicas
    ATT&CK como attack-pattern y las relaciones indicates y uses.

Los ID son deterministas (UUIDv5 sobre el contenido): exportar dos veces el
mismo informe da el mismo bundle, y una plataforma que lo importe dos veces no
duplica nada. Todo va marcado TLP:AMBER.
"""
from __future__ import annotations

import json
import uuid

from ..models import Report

ESPACIO = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")   # el de los SCO de STIX 2.1
TLP_AMBER = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
RESULTADO = {"malicioso": "malicious", "sospechoso": "suspicious", "limpio": "benign", "desconocido": "unknown"}


def _id(tipo: str, *partes: object) -> str:
    return f"{tipo}--{uuid.uuid5(ESPACIO, json.dumps([tipo, *partes], sort_keys=True, default=str))}"


def _fecha(iso: str) -> str:
    # STIX exige "Z" y como mucho milisegundos
    base = iso.replace("+00:00", "")
    if "." in base:
        entero, frac = base.split(".", 1)
        base = f"{entero}.{frac[:3]}"
    return base + "Z"


def _escapar(v: str) -> str:
    return v.replace("\\", "\\\\").replace("'", "\\'")


def a_stix(report: Report) -> dict:
    st = report.static
    ahora = _fecha(report.generated_at)
    comunes = {"spec_version": "2.1", "created": ahora, "modified": ahora}
    yo = {"type": "identity", "id": _id("identity", "malpipe"), **comunes, "name": "malpipe",
          "identity_class": "system"}
    marcas = {"created_by_ref": yo["id"], "object_marking_refs": [TLP_AMBER]}
    objetos: list[dict] = [yo]

    hashes = {k: v for k, v in (("SHA-256", st.hashes.sha256), ("SHA-1", st.hashes.sha1), ("MD5", st.hashes.md5)) if v}
    fichero = {"type": "file", "spec_version": "2.1", "id": _id("file", hashes), "hashes": hashes,
               "size": st.size, "name": st.filename or "muestra"}
    objetos.append(fichero)

    familias = sorted({c.family for c in report.configs}
                      | ({report.dynamic.family} if report.dynamic.family else set()))
    malicioso = report.verdict == "malicioso" or bool(familias)
    malware = None
    if malicioso:
        malware = {"type": "malware", "id": _id("malware", familias or st.hashes.sha256), **comunes, **marcas,
                   "name": ", ".join(familias) if familias else f"Muestra {st.hashes.sha256[:12]}",
                   "is_family": bool(familias), "sample_refs": [fichero["id"]]}
        objetos.append(malware)

    analisis = {"type": "malware-analysis", "id": _id("malware-analysis", st.hashes.sha256, report.generated_at),
                **comunes, **marcas, "product": "malpipe", "version": report.version,
                "result": RESULTADO.get(report.verdict, "unknown"), "sample_ref": fichero["id"],
                "analysis_engine_version": report.version}
    objetos.append(analisis)
    if report.reasons:
        # malware-analysis no tiene descripcion en STIX 2.1: el porque va en una nota
        objetos.append({"type": "note", "id": _id("note", analisis["id"]), **comunes, **marcas,
                        "abstract": f"Por qué malpipe dice {report.verdict} ({report.score}/100)",
                        "content": "\n".join(report.reasons), "object_refs": [analisis["id"]]})

    patrones: list[tuple[str, str]] = []
    for nombre, valor in hashes.items():
        patrones.append((f"Hash {nombre} de la muestra", f"[file:hashes.'{nombre}' = '{valor}']"))
    for ip in st.indicators.ips:
        patrones.append((f"IP {ip}", f"[ipv4-addr:value = '{ip}']"))
    for d in st.indicators.domains:
        patrones.append((f"Dominio {d}", f"[domain-name:value = '{_escapar(d)}']"))
    for u in st.indicators.urls:
        patrones.append((f"URL {u}", f"[url:value = '{_escapar(u)}']"))
    for cfg in report.configs:
        for c2 in cfg.c2:
            if "://" in c2:
                patrones.append((f"C2 de {cfg.family}: {c2}", f"[url:value = '{_escapar(c2)}']"))
            else:
                host = c2.rsplit(":", 1)[0]
                tipo = "ipv4-addr" if host.replace(".", "").isdigit() else "domain-name"
                patrones.append((f"C2 de {cfg.family}: {c2}", f"[{tipo}:value = '{_escapar(host)}']"))

    tipo_indicador = ["malicious-activity"] if malicioso else ["anomalous-activity"]
    vistos = set()
    for nombre, patron in patrones:
        if patron in vistos:
            continue
        vistos.add(patron)
        ind = {"type": "indicator", "id": _id("indicator", patron), **comunes, **marcas, "name": nombre,
               "indicator_types": tipo_indicador, "pattern": patron, "pattern_type": "stix",
               "valid_from": ahora}
        objetos.append(ind)
        if malware:
            objetos.append({"type": "relationship", "id": _id("relationship", ind["id"], "indicates", malware["id"]),
                            **comunes, **marcas, "relationship_type": "indicates",
                            "source_ref": ind["id"], "target_ref": malware["id"]})

    if malware:
        for t in report.attack:
            ap = {"type": "attack-pattern", "id": _id("attack-pattern", t.id), **comunes, **marcas, "name": t.name,
                  "external_references": [{"source_name": "mitre-attack", "external_id": t.id,
                                           "url": f"https://attack.mitre.org/techniques/{t.id.replace('.', '/')}/"}]}
            objetos.append(ap)
            objetos.append({"type": "relationship", "id": _id("relationship", malware["id"], "uses", ap["id"]),
                            **comunes, **marcas, "relationship_type": "uses",
                            "source_ref": malware["id"], "target_ref": ap["id"]})

    return {"type": "bundle", "id": _id("bundle", st.hashes.sha256, report.generated_at), "objects": objetos}

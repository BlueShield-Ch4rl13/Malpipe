"""Cruce con News CTI: hashes, red de las cadenas, C2 de la configuracion."""
from __future__ import annotations

import hashlib
import json

import muestras_sinteticas as m

from malpipe import analyze_bytes
from malpipe.__main__ import main
from malpipe.enrich.cti import cargar_feed


def feed(*iocs) -> dict:
    return {"generated_utc": "2026-10-25T06:00:00Z", "iocs": list(iocs)}


def ioc(tipo, valor, **kw):
    return {"type": tipo, "value": valor, "threat": kw.get("threat", "Prueba"), "level": "alta", "score": 80,
            "sources": ["ThreatFox"], "reference": "https://ejemplo.test/ioc", "variants": kw.get("variants", [])}


def test_hash_conocido_es_malicioso():
    datos = b"un fichero cualquiera"
    f = feed(ioc("filehash-sha256", hashlib.sha256(datos).hexdigest(), threat="AgentTesla"))
    r = analyze_bytes("x.bin", datos, do_dynamic=False, cti_feed=f)
    assert r.cti.checked and r.cti.indicators == 1
    assert [x.threat for x in r.cti.matches] == ["AgentTesla"]
    assert r.verdict == "malicioso" and r.score >= 80
    assert "≥80 el hash de la muestra ya está en News CTI" in r.reasons


def test_red_de_las_cadenas_y_ip_con_puerto():
    datos = b"conecta a 203.0.113.9 y a http://gate.ejemplo-malo.top/panel/login.php ya"
    f = feed(ioc("ip:port", "203.0.113.9:4444"), ioc("domain", "gate.ejemplo-malo.top"),
             ioc("url", "http://otra.top/x"))
    r = analyze_bytes("x.txt", datos, do_dynamic=False, cti_feed=f)
    vistos = {(x.type, x.matched) for x in r.cti.matches}
    assert ("ip:port", "203.0.113.9") in vistos, "1.2.3.4 casa con 1.2.3.4:puerto"
    assert ("domain", "gate.ejemplo-malo.top") in vistos, "el host de una URL casa con el dominio"
    assert any("de red ya en News CTI" in x for x in r.reasons)


def test_c2_de_la_configuracion_se_cruza():
    f = feed(ioc("domain", "cdn.ejemplo-malo.test", threat="Cobalt Strike"))
    r = analyze_bytes("beacon.bin", m.beacon_cobaltstrike(), do_dynamic=False, cti_feed=f)
    assert [x.matched for x in r.cti.matches] == ["cdn.ejemplo-malo.test"]


def test_sin_feed_no_se_cruza():
    r = analyze_bytes("x.bin", b"hola", do_dynamic=False)
    assert not r.cti.checked and r.cti.matches == []


def test_feed_local_y_cli(tmp_path, capsys):
    muestra = tmp_path / "muestra.bin"
    muestra.write_bytes(b"datos de prueba 198.51.100.20")
    fich = tmp_path / "iocs_latest.json"
    fich.write_text(json.dumps(feed(ioc("ipv4", "198.51.100.20"))), encoding="utf-8")
    assert cargar_feed(str(fich))["_fuente"] == str(fich)
    salida = tmp_path / "out"
    assert main([str(muestra), "-o", str(salida), "--no-dynamic", "--cti-fichero", str(fich),
                 "--stix", "--misp"]) == 0
    texto = capsys.readouterr().out
    assert "News CTI  : 1 coincidencia(s): 198.51.100.20" in texto
    ficheros = sorted(p.name.split(".", 1)[1] for p in salida.iterdir())
    assert ficheros == ["html", "json", "misp.json", "stix.json"]
    informe = json.loads(next(salida.glob("*[0-9a-f].json")).read_text(encoding="utf-8"))
    assert informe["cti"]["matches"][0]["matched"] == "198.51.100.20"

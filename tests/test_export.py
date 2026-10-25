"""STIX 2.1 y MISP: validados con las librerias de referencia (stix2 y PyMISP)."""
from __future__ import annotations

import json

import muestras_sinteticas as m
import pytest

from malpipe import analyze_bytes
from malpipe.export import a_misp, a_stix

stix2 = pytest.importorskip("stix2")


@pytest.fixture
def informe():
    return analyze_bytes("beacon.bin", m.beacon_cobaltstrike() + b" 198.51.100.30 http://x.ejemplo-malo.top/a",
                         do_dynamic=False)


def test_stix_valido_y_completo(informe):
    bundle = a_stix(informe)
    analizado = stix2.parse(json.dumps(bundle), allow_custom=False)      # estricto: falla si algo no es STIX 2.1
    tipos = sorted({o.type for o in analizado.objects})
    assert {"identity", "file", "malware", "malware-analysis", "indicator", "relationship"} <= set(tipos)
    malware = next(o for o in analizado.objects if o.type == "malware")
    assert malware.name == "Cobalt Strike" and malware.is_family
    patrones = [o.pattern for o in analizado.objects if o.type == "indicator"]
    assert f"[file:hashes.'SHA-256' = '{informe.static.hashes.sha256}']" in patrones
    assert "[ipv4-addr:value = '198.51.100.30']" in patrones
    assert "[url:value = 'https://cdn.ejemplo-malo.test:443/jquery-3.3.1.min.js']" in patrones, "el C2 extraido"
    assert all(o.object_marking_refs == [stix2.TLP_AMBER.id] for o in analizado.objects
               if o.type in ("indicator", "malware"))
    analisis = next(o for o in analizado.objects if o.type == "malware-analysis")
    assert analisis.result == "malicious"


def test_stix_determinista(informe):
    assert json.dumps(a_stix(informe), sort_keys=True) == json.dumps(a_stix(informe), sort_keys=True)


def test_stix_de_una_muestra_limpia_no_crea_malware():
    r = analyze_bytes("nota.txt", b"texto normal", do_dynamic=False)
    objetos = stix2.parse(json.dumps(a_stix(r)), allow_custom=False).objects
    assert not any(o.type == "malware" for o in objetos)
    assert all(o.indicator_types == ["anomalous-activity"] for o in objetos if o.type == "indicator")


def test_misp_valido(informe):
    pymisp = pytest.importorskip("pymisp")
    evento = a_misp(informe)
    ev = pymisp.MISPEvent()
    ev.load(json.dumps(evento))                       # PyMISP comprueba tipos y categorias
    tipos = {a.type for a in ev.attributes}
    assert {"sha256", "md5", "filename", "ip-dst", "url"} <= tipos
    assert ev.threat_level_id == 1 and ev.distribution == 0
    c2 = next(a for a in ev.attributes if a.value == "https://cdn.ejemplo-malo.test:443/jquery-3.3.1.min.js")
    assert c2.to_ids and "Cobalt Strike" in c2.comment
    assert "tlp:amber" in {t.name for t in ev.tags}


def test_misp_de_una_muestra_limpia_sin_to_ids():
    r = analyze_bytes("nota.txt", b"visita http://ejemplo-limpio.com/x", do_dynamic=False)
    attrs = a_misp(r)["Event"]["Attribute"]
    assert attrs and not any(a["to_ids"] for a in attrs)

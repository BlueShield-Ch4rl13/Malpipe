"""Extraccion de configuracion de familias, con muestras sinteticas (ver muestras_sinteticas.py)."""
from __future__ import annotations

import os

import muestras_sinteticas as m
import pytest

from malpipe import analyze_bytes
from malpipe.configs import cobaltstrike, extraer_configuraciones, remcos


@pytest.mark.parametrize("clave, version", [(0x2E, "4.x"), (0x69, "3.x")])
def test_cobalt_strike(clave, version):
    (cfg,) = extraer_configuraciones(m.beacon_cobaltstrike(clave))
    assert cfg.family == "Cobalt Strike" and cfg.confidence == "alta"
    assert cfg.c2 == ["https://cdn.ejemplo-malo.test:443/jquery-3.3.1.min.js"]
    assert cfg.values["BeaconType"] == "HTTPS" and cfg.values["Port"] == "443"
    assert cfg.values["SleepTime"] == "60000" and cfg.values["Watermark"] == "305419896"
    assert cfg.values["version"] == version
    assert cfg.values["UserAgent"].startswith("Mozilla/5.0")


def test_cobalt_strike_no_salta_con_datos_aleatorios():
    for _ in range(20):
        assert cobaltstrike.extraer(os.urandom(50_000)) is None


def test_remcos():
    (cfg,) = extraer_configuraciones(m.remcos())
    assert cfg.family == "Remcos"
    assert cfg.c2 == ["c2.ejemplo-malo.test:2404", "198.51.100.7:8080"]
    assert cfg.values["mutex"] == "Rmc-ABC123" and cfg.values["tls"] == ["1", "0"]
    assert cfg.values["nombre_asignado"] == "RemoteHost"


def test_remcos_con_otra_clave_no_inventa_nada():
    blob = remcos.recurso_settings(m.remcos())
    roto = bytes([blob[0]]) + b"x" * blob[0] + blob[1 + blob[0]:]       # clave cambiada
    assert remcos.extraer(m.pe_con_recurso("SETTINGS", roto)) is None
    assert remcos.extraer(m.pe_con_recurso("OTRO", blob)) is None       # recurso con otro nombre


def test_njrat_con_confianza_media():
    (cfg,) = extraer_configuraciones(m.njrat())
    assert cfg.family == "njRAT" and cfg.confidence == "media"
    assert cfg.c2 == ["rat.ejemplo-malo.test:5552"], "server.exe no es un host"
    assert cfg.values["version"] == "0.7d" and cfg.values["campana"] == "HacKed"


def test_familia_con_configuracion_es_maliciosa():
    r = analyze_bytes("beacon.bin", m.beacon_cobaltstrike(), do_dynamic=False)
    assert r.verdict == "malicioso" and r.score >= 70
    assert any("Cobalt Strike" in x for x in r.reasons)


def test_njrat_por_heuristica_no_fija_el_veredicto():
    r = analyze_bytes("rat.exe", m.njrat(), do_dynamic=False)
    assert r.configs and r.configs[0].confidence == "media"
    assert not any("configuración de" in x for x in r.reasons), "solo la confianza alta fija malicioso"

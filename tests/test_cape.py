"""Conector de CAPEv2 con respuestas simuladas que siguen su API v2 (web/apiv2/views.py)."""
from __future__ import annotations

import muestras_sinteticas as m
import pytest

from malpipe import analyze_bytes
from malpipe.config import config
from malpipe.dynamic import cape

INFORME = {
    "malscore": 9.2,
    "detections": [{"family": "AgentTesla", "details": [{"Yara": "AgentTesla"}]}],
    "signatures": [
        {"name": "persistence_autorun", "description": "Installs itself for autorun at Windows startup",
         "severity": 3, "ttp": ["T1547.001"]},
        {"name": "injection_rwx", "description": "Creates RWX memory", "severity": 2},
    ],
    "ttps": [{"signature": "injection_rwx", "ttps": ["T1055"]}],
    "network": {"hosts": [{"ip": "203.0.113.50", "country_name": "XX"}, "203.0.113.51"],
                "domains": [{"domain": "smtp.ejemplo-malo.test", "ip": "203.0.113.50"}],
                "http": [{"uri": "http://203.0.113.50/gate.php", "host": "203.0.113.50"}]},
    "CAPE": {"configs": [{"AgentTesla": {"Protocol": "SMTP", "C2": "smtp.ejemplo-malo.test",
                                         "Port": 587, "Username": "u@ejemplo-malo.test"}}]},
}


class Respuesta:
    def __init__(self, datos, codigo=200):
        self._datos, self.status_code = datos, codigo

    def json(self):
        return self._datos

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


@pytest.fixture
def cape_simulado(monkeypatch):
    llamadas = []
    estados = iter(["pending", "running", "completed", "reported"])

    def peticion(metodo, url, headers=None, timeout=None, verify=None, **kw):
        llamadas.append((metodo, url, headers, kw))
        if url.endswith("/apiv2/tasks/create/file/"):
            return Respuesta({"error": False, "data": {"task_ids": [42], "message": "Task ID 42 has been submitted"}})
        if url.endswith("/apiv2/tasks/status/42/"):
            return Respuesta({"error": False, "data": next(estados)})
        if url.endswith("/apiv2/tasks/get/report/42/json/"):
            return Respuesta(INFORME)
        return Respuesta({"error": True, "error_value": "no existe"}, 404)

    monkeypatch.setattr(cape.requests, "request", peticion)
    monkeypatch.setattr(cape.time, "sleep", lambda s: None)
    for k, v in {"sandbox": "auto", "cape_url": "http://cape.lab:8000", "cape_token": "secreto",
                 "cape_options": "route=none", "triage_api_key": ""}.items():
        monkeypatch.setattr(config, k, v)
    return llamadas


def test_cape_de_extremo_a_extremo(cape_simulado):
    r = analyze_bytes("muestra.exe", b"MZ" + b"\x00" * 200, do_dynamic=True)
    d = r.dynamic
    assert d.engine == "CAPEv2" and d.analyzed and d.score == 9.2 and d.family == "AgentTesla"
    assert d.sandbox_url == "http://cape.lab:8000/analysis/42/"
    assert d.hosts == ["203.0.113.50", "203.0.113.51"] and d.domains == ["smtp.ejemplo-malo.test"]
    assert d.urls == ["http://203.0.113.50/gate.php"]
    assert d.ttps == ["T1055", "T1547.001"]
    assert {(t.id, t.source) for t in r.attack} >= {("T1055", "sandbox"), ("T1547.001", "sandbox")}
    (cfg,) = [c for c in r.configs if c.extractor == "cape"]
    assert cfg.family == "AgentTesla" and cfg.source == "dynamic" and cfg.c2 == ["smtp.ejemplo-malo.test"]
    assert r.verdict == "malicioso"

    metodo, url, cab, kw = cape_simulado[0]
    assert (metodo, url) == ("POST", "http://cape.lab:8000/apiv2/tasks/create/file/")
    assert cab == {"Authorization": "Token secreto"} and kw["data"] == {"options": "route=none"}
    assert kw["files"]["file"][0] == "muestra.exe"


def test_cape_tarea_fallida(monkeypatch, cape_simulado):
    monkeypatch.setattr(cape, "_esperar", lambda tarea: "failed_analysis")
    r = analyze_bytes("m.exe", b"MZ", do_dynamic=True)
    assert not r.dynamic.analyzed and "failed_analysis" in r.dynamic.error


def test_cape_caido_no_tumba_el_analisis(monkeypatch, cape_simulado):
    def caido(*a, **k):
        raise ConnectionError("sin ruta al host")
    monkeypatch.setattr(cape.requests, "request", caido)
    r = analyze_bytes("beacon.bin", m.beacon_cobaltstrike(), do_dynamic=True)
    assert "ConnectionError" in r.dynamic.error
    assert r.configs and r.configs[0].family == "Cobalt Strike", "el estatico sigue"


def test_sin_sandbox(monkeypatch):
    monkeypatch.setattr(config, "cape_url", "")
    monkeypatch.setattr(config, "triage_api_key", "")
    r = analyze_bytes("x", b"x", do_dynamic=True)
    assert r.dynamic.engine == "ninguno"

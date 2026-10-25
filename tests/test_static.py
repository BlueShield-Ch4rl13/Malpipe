"""Tests del análisis estático. No requieren red ni claves de API."""
from __future__ import annotations

import hashlib

from malpipe.enrich.attack import map_attack
from malpipe.enrich.verdict import score_report
from malpipe.models import Report
from malpipe.static import run_static
from malpipe.static.strings_ex import analyze_strings


def test_hashes_and_type():
    data = b"MZ" + b"\x00" * 100 + b"http://malicioso.example.top/gate.php"
    res = run_static("fake.bin", data)
    assert res.hashes.sha256 == hashlib.sha256(data).hexdigest()
    assert res.size == len(data)
    assert "PE" in res.filetype


def test_ioc_extraction():
    data = b"conecta a 45.66.77.88 y http://evil.top/panel admin@evil.top"
    ind, _ = analyze_strings(data)
    assert "45.66.77.88" in ind.ips
    assert any("evil.top" in u for u in ind.urls)
    assert "admin@evil.top" in ind.emails


def test_private_ip_filtered():
    data = b"loopback 127.0.0.1 y nulo 0.0.0.0 pero real 8.8.4.4"
    ind, _ = analyze_strings(data)
    assert "127.0.0.1" not in ind.ips
    assert "8.8.4.4" in ind.ips


def test_verdict_runs():
    report = Report()
    report.static = run_static("x.txt", b"texto inofensivo")
    report.attack = map_attack(report.static, report.dynamic)
    score_report(report)
    assert report.verdict in {"limpio", "sospechoso", "malicioso", "desconocido"}
    assert 0 <= report.score <= 100


def test_variables_vacias_cuentan_como_no_puestas(monkeypatch):
    # docker compose pasa "MALPIPE_DYNAMIC_TIMEOUT=" de .env como cadena vacia
    from malpipe.config import env, env_int
    monkeypatch.setenv("MALPIPE_DYNAMIC_TIMEOUT", "")
    monkeypatch.setenv("MALPIPE_SANDBOX", "")
    assert env_int("MALPIPE_DYNAMIC_TIMEOUT", 300) == 300
    assert env("MALPIPE_SANDBOX", "auto") == "auto"

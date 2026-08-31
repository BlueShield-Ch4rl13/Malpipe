"""Tests del portal web. Se saltan si no están instaladas las dependencias web."""
from __future__ import annotations

import io

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("multipart")

from fastapi.testclient import TestClient  # noqa: E402

from webapp.server import app  # noqa: E402

client = TestClient(app)


def test_config_endpoint():
    r = client.get("/api/config")
    assert r.status_code == 200
    assert "max_mb" in r.json()


def test_frontend_served():
    r = client.get("/")
    assert r.status_code == 200
    assert "Content-Security-Policy" in r.headers


def test_analyze_and_result():
    payload = b"MZ" + b"\x00" * 60 + b"http://malo.example.top/gate.php"
    files = {"file": ("m.bin", io.BytesIO(payload), "application/octet-stream")}
    r = client.post("/api/analyze", files=files, data={"cf_turnstile_response": ""})
    assert r.status_code == 200
    job_id = r.json()["job_id"]

    res = client.get(f"/api/result/{job_id}").json()
    assert res["report"]["static"]["filetype"].startswith("PE")
    assert any("malo.example.top" in u for u in res["report"]["static"]["indicators"]["urls"])


def test_empty_file_rejected():
    files = {"file": ("empty.bin", io.BytesIO(b""), "application/octet-stream")}
    r = client.post("/api/analyze", files=files, data={"cf_turnstile_response": ""})
    assert r.status_code == 400

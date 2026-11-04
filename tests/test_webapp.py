"""Tests del portal web. Se saltan si no están instaladas las dependencias web."""
from __future__ import annotations

import io

import httpx
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


def test_turnstile_se_lee_del_formulario(monkeypatch):
    """El token llega como campo del formulario. Antes FastAPI lo buscaba en la URL,
    llegaba vacío y, con Turnstile configurado, todas las subidas daban 403."""
    import webapp.server as srv

    vistos = []

    async def falso(token, ip):
        vistos.append(token)
        return token == "token-bueno"

    monkeypatch.setattr(srv, "_turnstile_ok", falso)
    files = {"file": ("m.bin", io.BytesIO(b"MZ" + b"\x00" * 60), "application/octet-stream")}
    r = client.post("/api/analyze", files=files, data={"cf_turnstile_response": "token-bueno"})
    assert r.status_code == 200, r.text
    assert vistos == ["token-bueno"]


def test_fichero_grande_se_corta_antes_de_leerlo(monkeypatch):
    """413 por el middleware, sin llegar al handler (que ya habría volcado el fichero)."""
    import webapp.server as srv

    llamado = []
    monkeypatch.setattr(srv.store, "create", lambda *a: llamado.append(a))
    grande = b"A" * (srv.MAX_MB * 1024 * 1024 + 200 * 1024)
    files = {"file": ("grande.bin", io.BytesIO(grande), "application/octet-stream")}
    r = client.post("/api/analyze", files=files)
    assert r.status_code == 413
    assert llamado == []


def test_cf_connecting_ip_solo_detras_de_cloudflare(monkeypatch):
    """Sin túnel, una cabecera CF-Connecting-IP inventada no cambia la IP del rate-limit."""
    from starlette.requests import Request

    import webapp.server as srv

    def peticion(ip_directa: str) -> Request:
        return Request({"type": "http", "headers": [(b"cf-connecting-ip", b"198.51.100.7")],
                        "client": (ip_directa, 5000)})

    monkeypatch.setattr(srv, "BEHIND_CLOUDFLARE", False)
    assert srv._client_ip(peticion("203.0.113.5")) == "203.0.113.5"
    monkeypatch.setattr(srv, "BEHIND_CLOUDFLARE", True)
    assert srv._client_ip(peticion("127.0.0.1")) == "198.51.100.7", "desde el túnel local, sí"
    # (una IP publica real: las de documentacion como 203.0.113.0/24 cuentan como privadas)
    assert srv._client_ip(peticion("8.8.4.4")) == "8.8.4.4", "desde fuera, nunca"


def test_publicado_sin_turnstile_no_arranca():
    import webapp.server as srv

    with pytest.raises(RuntimeError, match="TURNSTILE_SECRET"):
        srv._comprobar_configuracion(True, "", False)
    srv._comprobar_configuracion(True, "secreto", False)
    srv._comprobar_configuracion(True, "", True)   # pedido a proposito
    srv._comprobar_configuracion(False, "", False)  # desarrollo local


@pytest.mark.parametrize("respuesta", [
    pytest.param(lambda r: httpx.Response(500, text="caido"), id="500"),
    pytest.param(lambda r: httpx.Response(200, text="<html>no es json</html>"), id="no-json"),
    pytest.param(lambda r: httpx.Response(200, json=["lista"]), id="json-raro"),
    pytest.param(lambda r: (_ for _ in ()).throw(httpx.ConnectTimeout("sin red")), id="timeout"),
])
def test_siteverify_que_falla_da_503_y_no_deja_pasar(monkeypatch, respuesta):
    import webapp.server as srv

    real = httpx.AsyncClient
    monkeypatch.setattr(srv, "TURNSTILE_SECRET", "secreto")
    monkeypatch.setattr(srv.httpx, "AsyncClient",
                        lambda **k: real(transport=httpx.MockTransport(respuesta), **k))
    llamado = []
    monkeypatch.setattr(srv.store, "create", lambda *a: llamado.append(a))
    files = {"file": ("m.bin", io.BytesIO(b"MZ" + b"\x00" * 60), "application/octet-stream")}
    r = client.post("/api/analyze", files=files, data={"cf_turnstile_response": "token"})
    assert r.status_code == 503, r.text
    assert llamado == []


def test_siteverify_solo_acepta_success_true(monkeypatch):
    import webapp.server as srv

    real = httpx.AsyncClient
    monkeypatch.setattr(srv, "TURNSTILE_SECRET", "secreto")
    monkeypatch.setattr(srv.httpx, "AsyncClient", lambda **k: real(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"success": "false"})), **k))
    files = {"file": ("m.bin", io.BytesIO(b"MZ" + b"\x00" * 60), "application/octet-stream")}
    assert client.post("/api/analyze", files=files, data={"cf_turnstile_response": "t"}).status_code == 403


def test_el_rate_limit_no_guarda_ips_para_siempre(monkeypatch):
    import webapp.server as srv

    monkeypatch.setattr(srv, "_hits", {})
    monkeypatch.setattr(srv, "_MAX_IPS", 100)
    reloj = [1000.0]
    monkeypatch.setattr(srv.time, "time", lambda: reloj[0])
    for i in range(150):
        assert srv._rate_ok(f"10.0.{i // 250}.{i % 250}")
    reloj[0] += srv.RATE_WINDOW + 1
    assert srv._rate_ok("10.9.9.9")
    assert len(srv._hits) == 1, "las IPs sin nada en la ventana se han tirado"
    for _ in range(srv.RATE_MAX - 1):
        assert srv._rate_ok("10.9.9.9")
    assert not srv._rate_ok("10.9.9.9")


def test_exportar_stix_y_misp():
    r = client.post("/api/analyze", files={"file": ("m.bin", io.BytesIO(b"MZ hola 198.51.100.40"),
                                                    "application/octet-stream")},
                    data={"cf_turnstile_response": ""})
    job = r.json()["job_id"]
    stix = client.get(f"/api/result/{job}/stix")
    assert stix.status_code == 200 and stix.json()["type"] == "bundle"
    assert "attachment" in stix.headers["content-disposition"]
    misp = client.get(f"/api/result/{job}/misp")
    assert misp.status_code == 200 and "Attribute" in misp.json()["Event"]
    assert client.get(f"/api/result/{job}/pdf").status_code == 404

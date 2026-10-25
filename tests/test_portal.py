"""El portal del navegador de extremo a extremo, en Chromium de verdad.

Se sirve box/ (lo que se publica, ya con el motor dentro) con las mismas
cabeceras que en Cloudflare (CSP incluida) y el feed de News CTI se
sustituye por uno de prueba. Comprueba que Pyodide y YARA-X arrancan bajo esa
CSP, que el analisis sale igual que en la CLI y que las descargas funcionan.

Contra el portal ya publicado:
    MALPIPE_PORTAL_URL=https://box.carlosvillalbalagos.com/ pytest tests/test_portal.py
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import muestras_sinteticas as m
import pytest
import servidor_estatico

sync_api = pytest.importorskip("playwright.sync_api")
URL_EXTERNA = os.environ.get("MALPIPE_PORTAL_URL", "")
pytestmark = pytest.mark.skipif(not URL_EXTERNA and not (servidor_estatico.DIST / "index.html").exists(),
                                reason="falta el motor en box/: npm ci && npm run box")
ESPERA = 180_000          # la primera carga descarga y compila ~18 MB de WebAssembly

FEED = {"generated_utc": "2026-10-25T06:00:00Z", "iocs": [
    {"type": "domain", "value": "cdn.ejemplo-malo.test", "threat": "Cobalt Strike", "level": "alta", "score": 90,
     "sources": ["ThreatFox"], "reference": "https://ejemplo.test"}]}


@pytest.fixture(scope="module")
def portal():
    if URL_EXTERNA:
        yield URL_EXTERNA.rstrip("/") + "/"
        return
    srv, url = servidor_estatico.arrancar()
    yield url
    srv.shutdown()


@pytest.fixture(scope="module")
def navegador():
    with sync_api.sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


@pytest.fixture
def pagina(navegador, portal):
    ctx = navegador.new_context(accept_downloads=True)
    page = ctx.new_page()
    page.errores = []
    page.on("console", lambda msg: page.errores.append(msg.text) if msg.type == "error" else None)
    page.on("pageerror", lambda e: page.errores.append(str(e)))
    page.route("https://raw.githubusercontent.com/**", lambda r: r.fulfill(
        status=200, content_type="application/json", headers={"Access-Control-Allow-Origin": "*"},
        body=json.dumps(FEED)))
    page.goto(portal)
    yield page
    ctx.close()


def resultado(page) -> str:
    page.wait_for_selector("#resultado:not([hidden]) .veredicto", timeout=ESPERA)
    return page.inner_text("#resultado")


def pestana(page, id_: str) -> str:
    """Abre una pestaña del detalle y devuelve el texto de su panel."""
    page.click(f"#pes-{id_}")
    assert page.get_attribute(f"#pes-{id_}", "aria-selected") == "true"
    return page.inner_text(f"#pan-{id_}")


def sin_errores(page):
    assert not [e for e in page.errores if "Content Security Policy" in e or "Refused" in e], page.errores
    assert not page.errores, page.errores


def test_beacon_sintetico(pagina):
    pagina.click("#ej-beacon")
    texto = resultado(pagina)
    assert pagina.inner_text(".veredicto") == "MALICIOSO"
    assert "Cobalt Strike" in texto and "hxxps://cdn[.]ejemplo-malo[.]test:443/jquery-3[.]3[.]1[.]min[.]js" in texto
    assert "configuración de Cobalt Strike extraída" in texto
    assert "cdn[.]ejemplo-malo[.]test" in pestana(pagina, "cti")
    with pagina.expect_download() as d:
        pagina.click("#btn-json")
    assert json.loads(Path(d.value.path()).read_text(encoding="utf-8"))["verdict"] == "malicioso"
    with pagina.expect_download() as d:
        pagina.click("button:text('STIX 2.1')")
    stix = json.loads(Path(d.value.path()).read_text(encoding="utf-8"))
    assert stix["type"] == "bundle" and any(o["type"] == "malware" for o in stix["objects"])
    with pagina.expect_download() as d:
        pagina.click("button:text('Evento MISP')")
    assert json.loads(Path(d.value.path()).read_text(encoding="utf-8"))["Event"]["threat_level_id"] == "1"
    sin_errores(pagina)


def test_eicar_con_yara(pagina):
    pagina.click("#ej-eicar")
    resultado(pagina)
    assert "EICAR_Test_File" in pestana(pagina, "yara")
    # las flechas mueven entre pestañas, y «Nuevo análisis» vuelve a la portada
    pagina.focus("#pes-yara")
    pagina.keyboard.press("ArrowRight")
    assert pagina.get_attribute("#pes-yara", "aria-selected") == "false"
    pagina.click("#btn-volver")
    assert pagina.is_visible("#drop") and pagina.is_hidden("#btn-json")
    sin_errores(pagina)


def test_fichero_subido_remcos_y_html_que_no_se_ejecuta(pagina, tmp_path):
    muestra = tmp_path / "factura.exe"
    # Un nombre y unas cadenas con HTML: se tienen que ver como texto, no ejecutarse
    muestra.write_bytes(m.remcos() + b"<img src=x onerror=alert(1)> http://198.51.100.9/<b>x</b>")
    pagina.on("dialog", lambda d: (_ for _ in ()).throw(AssertionError("se ha ejecutado JavaScript de la muestra")))
    pagina.set_input_files("#fichero", str(muestra))
    texto = resultado(pagina)
    assert "Remcos" in texto and "c2[.]ejemplo-malo[.]test:2404" in texto
    assert ".rsrc" in pestana(pagina, "pe")
    assert pagina.locator("#resultado img").count() == 0
    with pagina.expect_download() as d:
        pagina.click("button:text('Informe HTML')")
    html = Path(d.value.path()).read_text(encoding="utf-8")
    assert "Remcos" in html and "<img src=x" not in html
    sin_errores(pagina)


def test_cabeceras(portal):
    import urllib.request
    with urllib.request.urlopen(portal) as r:
        csp = r.headers["Content-Security-Policy"]
    assert "'wasm-unsafe-eval'" in csp and "'unsafe-eval'" not in csp and "'unsafe-inline'" not in csp
    with urllib.request.urlopen(portal + "construccion.json") as r:
        c = json.load(r)
    with urllib.request.urlopen(portal + c["rutas"]["pyodide"].removeprefix("./") + "pyodide.asm.wasm") as r:
        assert "immutable" in r.headers["Cache-Control"]

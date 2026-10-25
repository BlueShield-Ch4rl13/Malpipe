"""Entrada del portal que corre en el navegador (box.carlosvillalbalagos.com).

El portal carga este mismo paquete en Pyodide (Python compilado a WebAssembly)
y llama a analizar() con los bytes del fichero, que nunca salen del navegador.
YARA lo pasa ya resuelto el JavaScript (YARA-X en WebAssembly), porque
yara-python no existe en Pyodide, y el feed de News CTI lo descarga el
navegador. El resto es el mismo codigo que la linea de ordenes: mismo analisis
estatico, mismas configuraciones de familia, mismo veredicto.

No hay dinamico: detonar necesita un sandbox y una clave, y en el navegador
cualquiera la veria.
"""
from __future__ import annotations

import json

from .export import a_misp, a_stix
from .models import YaraMatch
from .pipeline import analyze_bytes
from .report import render_html


def analizar(nombre: str, datos: bytes, yara_json: str = "[]", feed_json: str = "") -> str:
    """Devuelve un JSON con el informe y sus exportaciones (STIX, MISP y HTML)."""
    yara = [YaraMatch(rule=m["rule"], tags=list(m.get("tags") or []), meta=dict(m.get("meta") or {}))
            for m in json.loads(yara_json or "[]")]
    feed = json.loads(feed_json) if feed_json else None
    if hasattr(datos, "to_bytes"):          # Uint8Array de JavaScript (JsProxy de Pyodide)
        datos = datos.to_bytes()
    if feed is not None:
        feed.setdefault("_fuente", "News CTI (descargado por el navegador)")
    informe = analyze_bytes(nombre, bytes(datos), do_dynamic=False, cti_feed=feed, yara_matches=yara)
    informe.dynamic.engine = "no disponible en el navegador"
    return json.dumps({
        "informe": informe.to_dict(),
        "stix": a_stix(informe),
        "misp": a_misp(informe),
        "html": render_html(informe),
    }, ensure_ascii=False, default=str)

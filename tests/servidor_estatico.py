"""Servidor de box/ con las cabeceras de _headers, como las aplica Cloudflare Pages.

Lo usan las pruebas del portal; tambien sirve para verlo en local:
    python tests/servidor_estatico.py      ->  http://127.0.0.1:8787
"""
from __future__ import annotations

import functools
import http.server
import re
import sys
import threading
from pathlib import Path

DIST = Path(__file__).resolve().parent.parent / "box"
TIPOS = {".mjs": "text/javascript", ".js": "text/javascript", ".wasm": "application/wasm",
         ".whl": "application/octet-stream", ".json": "application/json", ".svg": "image/svg+xml"}


def leer_headers(ruta: Path) -> list[tuple[re.Pattern, list[tuple[str, str]]]]:
    reglas: list[tuple[re.Pattern, list[tuple[str, str]]]] = []
    for linea in ruta.read_text(encoding="utf-8").splitlines():
        if not linea.strip() or linea.lstrip().startswith("#"):
            continue
        if not linea[0].isspace():
            patron = "^" + re.escape(linea.strip()).replace(r"\*", ".*") + "$"
            reglas.append((re.compile(patron), []))
        elif reglas:
            nombre, valor = linea.strip().split(":", 1)
            reglas[-1][1].append((nombre.strip(), valor.strip()))
    return reglas


class Manejador(http.server.SimpleHTTPRequestHandler):
    extensions_map = {**http.server.SimpleHTTPRequestHandler.extensions_map, **TIPOS}
    reglas: list = []

    def end_headers(self):
        ruta = self.path.split("?", 1)[0]
        for patron, cabeceras in self.reglas:
            if patron.match(ruta):
                for nombre, valor in cabeceras:
                    self.send_header(nombre, valor)
        super().end_headers()

    def log_message(self, *args):
        pass


def arrancar(puerto: int = 0) -> tuple[http.server.ThreadingHTTPServer, str]:
    Manejador.reglas = leer_headers(DIST / "_headers")
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", puerto), functools.partial(Manejador, directory=str(DIST)))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


if __name__ == "__main__":
    srv, url = arrancar(int(sys.argv[1]) if len(sys.argv) > 1 else 8787)
    print(f"portal en {url} (Ctrl+C para parar)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.shutdown()

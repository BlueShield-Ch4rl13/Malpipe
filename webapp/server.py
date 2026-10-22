"""Backend del portal web de malpipe.

Expone una API mínima sobre el pipeline y sirve el frontend estático.
Seguridad de base: límite de tamaño antes de leer el cuerpo, la muestra solo
en memoria, rate-limit por IP y verificación opcional de Cloudflare Turnstile.

Arrancar:
    uvicorn webapp.server:app --host 127.0.0.1 --port 8000
"""
from __future__ import annotations

import ipaddress
import os
import time
from collections import defaultdict

import httpx
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from starlette.formparsers import MultiPartParser

from .jobs import store

# --- Configuración del portal (por entorno) ---
MAX_MB = int(os.getenv("MALPIPE_MAX_UPLOAD_MB", "30"))
RATE_MAX = int(os.getenv("MALPIPE_RATE_MAX", "5"))          # análisis...
RATE_WINDOW = int(os.getenv("MALPIPE_RATE_WINDOW", "600"))  # ...por esta ventana (s)
TURNSTILE_SECRET = os.getenv("TURNSTILE_SECRET", "")
TURNSTILE_SITEKEY = os.getenv("TURNSTILE_SITEKEY", "")
# Solo detrás de Cloudflare Tunnel: entonces la IP real llega en CF-Connecting-IP.
BEHIND_CLOUDFLARE = os.getenv("MALPIPE_BEHIND_CLOUDFLARE", "0") == "1"

# Starlette guarda en memoria hasta spool_max_size y el resto lo vuelca a un
# fichero temporal en /tmp. Con el umbral igual al límite de subida, una
# muestra nunca toca el disco (el límite se aplica antes, en LimiteCuerpo).
MultiPartParser.spool_max_size = MAX_MB * 1024 * 1024 + 64 * 1024

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

app = FastAPI(title="malpipe · portal de análisis", docs_url=None, redoc_url=None)


class LimiteCuerpo:
    """Corta /api/analyze en cuanto el cuerpo pasa del límite, mientras llega.

    El handler no ve el fichero hasta que FastAPI ha leído y parseado el
    cuerpo entero: comprobar el tamaño ahí ya era tarde. Este middleware ASGI
    rechaza por Content-Length y, si no lo hay o miente, cuenta los bytes
    según entran.
    """

    def __init__(self, app, max_bytes: int, ruta: str = "/api/analyze") -> None:
        self.app, self.max_bytes, self.ruta = app, max_bytes, ruta

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] != self.ruta:
            return await self.app(scope, receive, send)
        cabeceras = dict(scope.get("headers") or [])
        declarado = cabeceras.get(b"content-length", b"")
        if declarado.isdigit() and int(declarado) > self.max_bytes:
            return await self._rechazar(send)
        recibidos = 0

        async def receive_limitado():
            nonlocal recibidos
            mensaje = await receive()
            if mensaje["type"] == "http.request":
                recibidos += len(mensaje.get("body", b""))
                if recibidos > self.max_bytes:
                    raise _CuerpoDemasiadoGrande
            return mensaje

        try:
            await self.app(scope, receive_limitado, send)
        except _CuerpoDemasiadoGrande:
            await self._rechazar(send)

    async def _rechazar(self, send):
        cuerpo = f'{{"detail":"El fichero supera {MAX_MB} MB."}}'.encode()
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(cuerpo)).encode())]})
        await send({"type": "http.response.body", "body": cuerpo})


class _CuerpoDemasiadoGrande(Exception):
    pass


# Margen para las cabeceras multipart y el campo de Turnstile
app.add_middleware(LimiteCuerpo, max_bytes=MAX_MB * 1024 * 1024 + 64 * 1024)

# --- Rate limiting sencillo en memoria (Cloudflare hace el trabajo pesado) ---
_hits: dict[str, list[float]] = defaultdict(list)


def _client_ip(request: Request) -> str:
    """IP para el rate-limit.

    CF-Connecting-IP solo se cree si el portal está detrás de Cloudflare
    Tunnel (MALPIPE_BEHIND_CLOUDFLARE=1) y la conexión llega del túnel, es
    decir, de una dirección local o privada. Antes se creía siempre: con el
    puerto abierto, cualquiera mandaba una IP inventada en cada petición y el
    límite por IP no limitaba nada.
    """
    directa = request.client.host if request.client else "?"
    if BEHIND_CLOUDFLARE:
        try:
            origen = ipaddress.ip_address(directa)
        except ValueError:
            return directa
        if origen.is_loopback or origen.is_private:
            return request.headers.get("cf-connecting-ip") or directa
    return directa


def _rate_ok(ip: str) -> bool:
    now = time.time()
    _hits[ip] = [t for t in _hits[ip] if now - t < RATE_WINDOW]
    if len(_hits[ip]) >= RATE_MAX:
        return False
    _hits[ip].append(now)
    return True


async def _turnstile_ok(token: str, ip: str) -> bool:
    if not TURNSTILE_SECRET:
        return True  # verificación desactivada (desarrollo local)
    if not token:
        return False
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={"secret": TURNSTILE_SECRET, "response": token, "remoteip": ip},
        )
    return bool(r.json().get("success"))


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "script-src 'self' https://challenges.cloudflare.com; "
        "frame-src https://challenges.cloudflare.com; "
        "connect-src 'self'"
    )
    return resp


@app.get("/api/config")
async def api_config():
    """Config pública que el frontend necesita (la sitekey no es secreta)."""
    return {"turnstile_sitekey": TURNSTILE_SITEKEY, "max_mb": MAX_MB}


@app.post("/api/analyze")
async def api_analyze(
    request: Request,
    file: UploadFile = File(...),
    # Form: el frontend lo manda como campo del formulario. Declarado como
    # str a secas, FastAPI lo buscaba en la URL, llegaba vacío y, con
    # Turnstile configurado, todas las subidas daban 403.
    cf_turnstile_response: str = Form(""),
):
    ip = _client_ip(request)

    if not await _turnstile_ok(cf_turnstile_response, ip):
        raise HTTPException(status_code=403, detail="Verificación anti-bots fallida.")
    if not _rate_ok(ip):
        raise HTTPException(
            status_code=429,
            detail=f"Demasiados análisis. Máximo {RATE_MAX} cada {RATE_WINDOW // 60} min.",
        )

    max_bytes = MAX_MB * 1024 * 1024

    # Rechazo temprano por cabecera: si el cuerpo ya declara exceder el límite,
    # cortamos antes de buffear nada.
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > max_bytes:
        raise HTTPException(status_code=413, detail=f"El fichero supera {MAX_MB} MB.")

    # Lectura en trozos con tope: nunca retenemos en memoria más de lo permitido.
    chunks: list[bytes] = []
    total = 0
    while chunk := await file.read(1024 * 1024):
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(status_code=413, detail=f"El fichero supera {MAX_MB} MB.")
        chunks.append(chunk)
    data = b"".join(chunks)

    if not data:
        raise HTTPException(status_code=400, detail="Fichero vacío.")

    # La muestra se analiza en memoria y no se guarda en disco (ver
    # spool_max_size). Si MALPIPE_WEB_DYNAMIC=1, se envía además a tria.ge.
    # El estático es trabajo CPU-bound: se saca del event loop a un hilo.
    filename = os.path.basename(file.filename or "sample.bin")
    job = await run_in_threadpool(store.create, filename, data)
    del data
    return {"job_id": job.id, "status": job.status, "phase": job.phase}


@app.get("/api/result/{job_id}")
async def api_result(job_id: str):
    job = store.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Trabajo no encontrado o expirado.")
    payload = {
        "id": job.id,
        "filename": job.filename,
        "status": job.status,
        "phase": job.phase,
        "error": job.error,
        "report": job.report.to_dict() if job.report else None,
    }
    return JSONResponse(payload)


# El frontend estático se sirve en la raíz.
app.mount("/", StaticFiles(directory=_STATIC_DIR, html=True), name="static")

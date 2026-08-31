"""Backend del portal web de malpipe.

Expone una API mínima sobre el pipeline y sirve el frontend estático.
Seguridad de base: no persiste ficheros, límite de tamaño, rate-limit por IP
y verificación opcional de Cloudflare Turnstile.

Arrancar:
    uvicorn webapp.server:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import os
import time
from collections import defaultdict

import httpx
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .jobs import store

# --- Configuración del portal (por entorno) ---
MAX_MB = int(os.getenv("MALPIPE_MAX_UPLOAD_MB", "30"))
RATE_MAX = int(os.getenv("MALPIPE_RATE_MAX", "5"))          # análisis...
RATE_WINDOW = int(os.getenv("MALPIPE_RATE_WINDOW", "600"))  # ...por esta ventana (s)
TURNSTILE_SECRET = os.getenv("TURNSTILE_SECRET", "")
TURNSTILE_SITEKEY = os.getenv("TURNSTILE_SITEKEY", "")

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

app = FastAPI(title="malpipe · portal de análisis", docs_url=None, redoc_url=None)

# --- Rate limiting sencillo en memoria (Cloudflare hace el trabajo pesado) ---
_hits: dict[str, list[float]] = defaultdict(list)


def _client_ip(request: Request) -> str:
    # Detrás de Cloudflare, la IP real llega en CF-Connecting-IP.
    return request.headers.get("cf-connecting-ip") or (
        request.client.host if request.client else "?"
    )


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
    cf_turnstile_response: str = "",
):
    ip = _client_ip(request)

    if not await _turnstile_ok(cf_turnstile_response, ip):
        raise HTTPException(status_code=403, detail="Verificación anti-bots fallida.")
    if not _rate_ok(ip):
        raise HTTPException(
            status_code=429,
            detail=f"Demasiados análisis. Máximo {RATE_MAX} cada {RATE_WINDOW // 60} min.",
        )

    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Fichero vacío.")
    if len(data) > MAX_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"El fichero supera {MAX_MB} MB.")

    # El fichero se analiza en memoria y NO se guarda en disco.
    filename = os.path.basename(file.filename or "sample.bin")
    job = store.create(filename, data)
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

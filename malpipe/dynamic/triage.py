"""Análisis dinámico a través del sandbox gestionado tria.ge (Hatching Triage).

La muestra se detona en la infraestructura del sandbox, NO en la máquina local.
Requiere TRIAGE_API_KEY. Si no hay clave, el pipeline omite esta fase.

Nota: el esquema exacto de la API de tria.ge puede cambiar. El parseo es
defensivo (todo con .get). Verifica los endpoints contra la documentación
vigente en https://tria.ge/docs si algo deja de encajar.
"""
from __future__ import annotations

import time

from ..config import config
from ..models import DynamicResult

try:
    import requests  # type: ignore
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {config.triage_api_key}"}


def _submit(data: bytes, filename: str) -> str:
    url = f"{config.triage_base_url}/samples"
    files = {"file": (filename, data)}
    payload = {"_json": '{"kind":"file","interactive":false}'}
    r = requests.post(url, headers=_headers(), data=payload, files=files, timeout=60)
    r.raise_for_status()
    return r.json().get("id", "")


def _wait_for_report(sample_id: str) -> bool:
    url = f"{config.triage_base_url}/samples/{sample_id}"
    deadline = time.time() + config.dynamic_timeout
    while time.time() < deadline:
        r = requests.get(url, headers=_headers(), timeout=30)
        r.raise_for_status()
        status = r.json().get("status", "")
        if status == "reported":
            return True
        if status in ("failed", "canceled"):
            return False
        time.sleep(10)
    return False


def _overview(sample_id: str) -> dict:
    url = f"{config.triage_base_url}/samples/{sample_id}/overview.json"
    r = requests.get(url, headers=_headers(), timeout=30)
    r.raise_for_status()
    return r.json()


def run_triage(filename: str, data: bytes) -> DynamicResult:
    res = DynamicResult(engine="tria.ge")
    if not config.triage_api_key:
        res.error = "sin TRIAGE_API_KEY"
        return res
    if not _HAS_REQUESTS:
        res.error = "falta el paquete 'requests'"
        return res

    try:
        sample_id = _submit(data, filename)
        if not sample_id:
            res.error = "el sandbox no devolvió id de muestra"
            return res
        res.sandbox_url = f"https://tria.ge/{sample_id}"

        if not _wait_for_report(sample_id):
            res.error = "el informe no estuvo listo dentro del timeout"
            return res

        overview = _overview(sample_id)
        res.analyzed = True

        analysis = overview.get("analysis", {})
        res.score = analysis.get("score")
        family = analysis.get("family") or overview.get("targets", [{}])[0].get("family")
        if isinstance(family, list):
            family = ", ".join(family)
        res.family = family or ""

        for sig in overview.get("signatures", []):
            name = sig.get("name") or sig.get("desc") or ""
            if name:
                res.signatures.append(name)

        res.signatures = sorted(set(res.signatures))
    except Exception as exc:  # noqa: BLE001 — el pipeline no debe caerse por el sandbox
        res.error = f"{type(exc).__name__}: {exc}"
    return res

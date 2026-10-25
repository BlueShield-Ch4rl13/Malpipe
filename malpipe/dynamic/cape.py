"""Analisis dinamico en una instancia propia de CAPEv2 (host aislado).

A diferencia de tria.ge, la muestra no sale de tu red: se detona en tu CAPE,
que ademas extrae la configuracion de muchas familias de su volcado de memoria
(lo que el analisis estatico no ve si la muestra esta empaquetada).

API v2 de CAPE (web/apiv2/ en el repositorio de CAPEv2):
  POST {CAPE_URL}/apiv2/tasks/create/file/          -> data.task_ids
  GET  {CAPE_URL}/apiv2/tasks/status/<id>/          -> data: pending | running | completed | reported | failed_*
  GET  {CAPE_URL}/apiv2/tasks/get/report/<id>/json/ -> informe completo
Con autenticacion por token (api.conf), cabecera "Authorization: Token <token>".

Configuracion: CAPE_URL, CAPE_TOKEN, CAPE_OPCIONES (p. ej. "route=none"),
CAPE_VERIFICAR_TLS (1 por defecto). Como montar el host: docs/CAPE.md.

Probado con respuestas simuladas que siguen esa API (tests/test_cape.py), no
contra una instancia real.
"""
from __future__ import annotations

import time

from ..config import config
from ..models import DynamicResult, FamilyConfig

try:
    import requests  # type: ignore
except ImportError:  # pragma: no cover
    requests = None

FALLIDOS = ("failed_analysis", "failed_processing", "failed_reporting", "banned")


def _cab() -> dict[str, str]:
    return {"Authorization": f"Token {config.cape_token}"} if config.cape_token else {}


def _api(ruta: str) -> str:
    return f"{config.cape_url.rstrip('/')}/apiv2/{ruta.lstrip('/')}"


def _pedir(metodo: str, ruta: str, **kw):
    r = requests.request(metodo, _api(ruta), headers=_cab(), timeout=kw.pop("timeout", 60),
                         verify=config.cape_verify_tls, **kw)
    r.raise_for_status()
    datos = r.json()
    if isinstance(datos, dict) and datos.get("error"):
        raise RuntimeError(datos.get("error_value") or "CAPE devolvio un error")
    return datos


def _enviar(nombre: str, datos: bytes) -> int:
    form = {"options": config.cape_options} if config.cape_options else {}
    r = _pedir("POST", "tasks/create/file/", files={"file": (nombre, datos)}, data=form)
    ids = (r.get("data") or {}).get("task_ids") or []
    if not ids:
        raise RuntimeError("CAPE no devolvio ninguna tarea")
    return int(ids[0])


def _esperar(tarea: int) -> str:
    fin = time.time() + config.dynamic_timeout
    estado = ""
    while time.time() < fin:
        estado = str(_pedir("GET", f"tasks/status/{tarea}/", timeout=30).get("data", ""))
        if estado == "reported" or estado in FALLIDOS:
            return estado
        time.sleep(config.cape_intervalo)
    return estado or "sin respuesta"


def _lista(valor) -> list:
    return valor if isinstance(valor, list) else []


def interpretar(informe: dict, res: DynamicResult) -> list[FamilyConfig]:
    """Rellena res con el informe de CAPE y devuelve las configuraciones extraidas."""
    res.analyzed = True
    malscore = informe.get("malscore")
    res.score = float(malscore) if isinstance(malscore, (int, float)) else None

    familias = []
    det = informe.get("detections")
    for d in det if isinstance(det, list) else [det] if det else []:
        nombre = d.get("family") if isinstance(d, dict) else d
        if nombre and nombre not in familias:
            familias.append(str(nombre))
    res.family = ", ".join(familias)

    ttps = set()
    for sig in _lista(informe.get("signatures")):
        if isinstance(sig, dict) and sig.get("name"):
            res.signatures.append(str(sig.get("description") or sig["name"]))
            ttps.update(str(t) for t in _lista(sig.get("ttp")) if str(t).startswith("T"))
    for t in _lista(informe.get("ttps")):
        if isinstance(t, dict):
            ttps.update(str(x) for x in _lista(t.get("ttps")) if str(x).startswith("T"))
        elif str(t).startswith("T"):
            ttps.add(str(t))
    res.signatures = sorted(set(res.signatures))
    res.ttps = sorted(ttps)

    red = informe.get("network") or {}
    res.hosts = sorted({(h.get("ip") if isinstance(h, dict) else h) for h in _lista(red.get("hosts"))} - {None, ""})
    res.domains = sorted({(d.get("domain") if isinstance(d, dict) else d)
                          for d in _lista(red.get("domains"))} - {None, ""})
    res.urls = sorted({h.get("uri") for h in _lista(red.get("http")) if isinstance(h, dict) and h.get("uri")})

    configs = []
    for entrada in _lista((informe.get("CAPE") or {}).get("configs")):
        if not isinstance(entrada, dict):
            continue
        for familia, valores in entrada.items():
            if not isinstance(valores, dict):
                continue
            c2 = []
            for clave, v in valores.items():
                if any(k in clave.lower() for k in ("c2", "address", "url", "domain", "host")):
                    c2.extend(str(x) for x in (v if isinstance(v, list) else [v]) if x)
            configs.append(FamilyConfig(family=familia, extractor="cape", c2=sorted(set(c2)),
                                        values={k: v for k, v in valores.items()}, confidence="alta",
                                        source="dynamic"))
    return configs


def run_cape(nombre: str, datos: bytes) -> tuple[DynamicResult, list[FamilyConfig]]:
    res = DynamicResult(engine="CAPEv2")
    if not config.cape_url:
        res.error = "sin CAPE_URL"
        return res, []
    if requests is None:
        res.error = "falta el paquete 'requests'"
        return res, []
    try:
        tarea = _enviar(nombre, datos)
        res.sandbox_url = f"{config.cape_url.rstrip('/')}/analysis/{tarea}/"
        estado = _esperar(tarea)
        if estado != "reported":
            res.error = f"la tarea {tarea} termino en '{estado}'"
            return res, []
        informe = _pedir("GET", f"tasks/get/report/{tarea}/json/", timeout=120)
        return res, interpretar(informe, res)
    except Exception as exc:  # noqa: BLE001 - el pipeline no se cae por el sandbox
        res.error = f"{type(exc).__name__}: {exc}"
        return res, []

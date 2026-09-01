"""Análisis dinámico: detonación en un sandbox AISLADO y parseo del informe.

Este módulo NO ejecuta la muestra en tu máquina. Delega la detonación en un
sandbox aislado y se limita a enviar la muestra y a normalizar el informe de
comportamiento que devuelve (procesos creados, conexiones de red, ficheros y
claves tocadas, y comportamientos mapeados a ATT&CK).

Dos backends soportados (elige uno por variable de entorno):

  CAPEv2 self-hosted   MALPIPE_SANDBOX=cape
                       CAPE_URL=http://tu-cape:8000  CAPE_TOKEN=...
  API cloud (tria.ge)  MALPIPE_SANDBOX=triage  TRIAGE_TOKEN=...

Sin backend configurado, devuelve un aviso y no hace nada — el análisis estático
sigue siendo el resultado principal.

ISOLATION-FIRST (lee esto antes de montar el dinámico):
  · La VM de detonación va en una red aislada (host-only o INetSim/FakeNet para
    simular Internet). Nunca en la red de casa/empresa.
  · Usa snapshots: se revierte tras cada muestra.
  · Sin credenciales ni datos reales en la VM. Portapapeles y carpetas
    compartidas deshabilitados.
  · La muestra viaja cifrada/con contraseña 'infected' fuera del sandbox.
"""
from __future__ import annotations

import logging
import os
import time
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    import requests  # solo hace falta si se usa el análisis dinámico
except ImportError:  # pragma: no cover
    requests = None

# Sondeo del informe: 60 intentos × 15 s = 15 minutos de espera máxima
POLL_ATTEMPTS = 60
POLL_INTERVAL = 15

# Timeouts HTTP (segundos)
TIMEOUT_UPLOAD = 120
TIMEOUT_STATUS = 30
TIMEOUT_REPORT = 120


def detonate(sample: Path) -> dict:
    backend = os.getenv("MALPIPE_SANDBOX", "").lower()
    if backend == "cape":
        return _cape(sample)
    if backend == "triage":
        return _triage(sample)
    return {
        "status": "no_configurado",
        "nota": (
            "Análisis dinámico omitido: define MALPIPE_SANDBOX (cape|triage) y "
            "las credenciales. La detonación debe ocurrir en un sandbox aislado, "
            "nunca en este equipo."
        ),
    }


def _requests_missing() -> dict | None:
    """Devuelve un error si 'requests' no está instalado; None si todo va bien."""
    if requests is None:
        return {
            "status": "error",
            "nota": "Falta el paquete 'requests': pip install requests",
        }
    return None


# ------------------------------------------------------------ CAPEv2
def _cape(sample: Path) -> dict:
    if (err := _requests_missing()) is not None:
        return err
    base = os.getenv("CAPE_URL", "").rstrip("/")
    headers = {"Authorization": f"Token {os.getenv('CAPE_TOKEN', '')}"}
    if not base:
        return {"status": "error", "nota": "Falta CAPE_URL"}
    try:
        with open(sample, "rb") as f:
            r = requests.post(
                f"{base}/apiv2/tasks/create/file/",
                headers=headers,
                files={"file": (sample.name, f)},
                timeout=TIMEOUT_UPLOAD,
            )
        r.raise_for_status()
        task_id = (r.json().get("data") or {}).get("task_ids", [None])[0]
        if not task_id:
            return {"status": "error", "nota": "CAPE no devolvió task_id"}

        # Espera al informe (poll con tope)
        for _ in range(POLL_ATTEMPTS):
            s = requests.get(
                f"{base}/apiv2/tasks/status/{task_id}/",
                headers=headers,
                timeout=TIMEOUT_STATUS,
            )
            if (s.json().get("data") or "") == "reported":
                break
            time.sleep(POLL_INTERVAL)
        else:
            logger.warning(
                "CAPE: la tarea %s no llegó a 'reported' tras %s s; "
                "el informe puede estar incompleto",
                task_id,
                POLL_ATTEMPTS * POLL_INTERVAL,
            )

        rep = requests.get(
            f"{base}/apiv2/tasks/get/report/{task_id}/",
            headers=headers,
            timeout=TIMEOUT_REPORT,
        )
        return _normalize_cape(rep.json())
    except Exception as exc:
        logger.warning("CAPE falló con %s: %s", sample.name, exc, exc_info=True)
        return {"status": "error", "nota": f"CAPE falló: {exc}"}


def _normalize_cape(rep: dict) -> dict:
    """Extrae lo esencial del informe CAPE a una forma común."""
    beh = rep.get("behavior", {}) or {}
    net = rep.get("network", {}) or {}
    procs = [
        {
            "pid": p.get("pid"),
            "name": p.get("process_name"),
            "cmd": p.get("command_line", ""),
        }
        for p in beh.get("processes", [])
    ][:200]
    hosts = [h.get("ip") for h in net.get("hosts", []) if h.get("ip")]
    domains = [d.get("domain") for d in net.get("domains", []) if d.get("domain")]
    ttps = [
        {"attack": t.get("ttp"), "desc": t.get("signature")}
        for t in rep.get("ttps", [])
    ]
    signatures = [s.get("description") for s in rep.get("signatures", [])][:50]
    return {
        "status": "ok",
        "backend": "cape",
        "processes": procs,
        "network": {"hosts": hosts, "domains": domains},
        "attack": ttps,
        "signatures": signatures,
    }


# ------------------------------------------------------------ tria.ge
def _triage(sample: Path) -> dict:
    if (err := _requests_missing()) is not None:
        return err
    token = os.getenv("TRIAGE_TOKEN", "")
    base = "https://tria.ge/api/v0"
    headers = {"Authorization": f"Bearer {token}"}
    if not token:
        return {"status": "error", "nota": "Falta TRIAGE_TOKEN"}
    try:
        with open(sample, "rb") as f:
            r = requests.post(
                f"{base}/samples",
                headers=headers,
                files={"file": (sample.name, f)},
                timeout=TIMEOUT_UPLOAD,
            )
        r.raise_for_status()
        sid = r.json().get("id")
        if not sid:
            return {"status": "error", "nota": "tria.ge no devolvió id de muestra"}

        for _ in range(POLL_ATTEMPTS):
            st = requests.get(
                f"{base}/samples/{sid}",
                headers=headers,
                timeout=TIMEOUT_STATUS,
            ).json()
            if st.get("status") == "reported":
                break
            time.sleep(POLL_INTERVAL)
        else:
            logger.warning(
                "tria.ge: la muestra %s no llegó a 'reported' tras %s s; "
                "el informe puede estar incompleto",
                sid,
                POLL_ATTEMPTS * POLL_INTERVAL,
            )

        ov = requests.get(
            f"{base}/samples/{sid}/overview.json",
            headers=headers,
            timeout=TIMEOUT_REPORT,
        ).json()
        analysis = ov.get("analysis", {}) or {}
        return {
            "status": "ok",
            "backend": "triage",
            "url": f"https://tria.ge/{sid}",
            "score": ov.get("score", analysis.get("score")),
            "family": analysis.get("family", []),
            "signatures": [s.get("name") for s in ov.get("signatures", [])][:50],
        }
    except Exception as exc:
        logger.warning("tria.ge falló con %s: %s", sample.name, exc, exc_info=True)
        return {"status": "error", "nota": f"tria.ge falló: {exc}"}

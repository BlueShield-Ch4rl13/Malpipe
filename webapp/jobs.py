"""Gestor de trabajos de análisis.

El estático es instantáneo; el dinámico (sandbox) tarda minutos. Por eso cada
subida crea un "job": el estático se resuelve al momento y el dinámico se
completa en segundo plano. El frontend consulta el estado por su id.

Almacén en memoria (suficiente para un despliegue de un solo proceso). Para
escalar a varios workers, sustituir por Redis o una base de datos.
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Literal

from malpipe import analyze_bytes
from malpipe.config import config
from malpipe.models import Report

Status = Literal["procesando", "completado", "error"]

# Cuánto se conserva un job terminado antes de purgarlo (segundos)
_TTL = 1800


@dataclass
class Job:
    id: str
    filename: str
    status: Status = "procesando"
    phase: str = "estático"        # texto para el frontend
    report: Report | None = None
    error: str = ""
    created: float = field(default_factory=time.time)


class JobStore:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def _purge(self) -> None:
        now = time.time()
        dead = [j for j, job in self._jobs.items() if now - job.created > _TTL]
        for j in dead:
            self._jobs.pop(j, None)

    def create(self, filename: str, data: bytes) -> Job:
        with self._lock:
            self._purge()
            job = Job(id=uuid.uuid4().hex, filename=filename)
            self._jobs[job.id] = job

        # Estático ya mismo (rápido, sin ejecutar nada).
        report = analyze_bytes(filename, data, do_dynamic=False)
        with self._lock:
            job.report = report

        if config.dynamic_available:
            job.phase = "dinámico (sandbox)"
            t = threading.Thread(
                target=self._run_dynamic, args=(job.id, filename, data), daemon=True
            )
            t.start()
        else:
            job.status = "completado"
            job.phase = "solo estático (sin sandbox configurado)"
        return job

    def _run_dynamic(self, job_id: str, filename: str, data: bytes) -> None:
        try:
            # Reanaliza con dinámico activado; devuelve informe completo.
            full = analyze_bytes(filename, data, do_dynamic=True)
            with self._lock:
                job = self._jobs.get(job_id)
                if job:
                    job.report = full
                    job.status = "completado"
                    job.phase = "completado"
        except Exception as exc:  # el fallo del sandbox no debe romper el servicio
            with self._lock:
                job = self._jobs.get(job_id)
                if job:
                    job.status = "error"
                    job.error = f"{type(exc).__name__}: {exc}"

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)


store = JobStore()

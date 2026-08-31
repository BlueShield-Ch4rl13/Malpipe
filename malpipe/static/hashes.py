"""Cálculo de hashes del fichero. Fuzzy hashing (ssdeep) es opcional."""
from __future__ import annotations

import hashlib

from ..models import Hashes

try:
    import ssdeep  # type: ignore
    _HAS_SSDEEP = True
except ImportError:
    _HAS_SSDEEP = False


def compute_hashes(data: bytes) -> Hashes:
    """Devuelve los hashes criptográficos del contenido (sin ejecutar nada)."""
    h = Hashes(
        md5=hashlib.md5(data).hexdigest(),
        sha1=hashlib.sha1(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
    )
    if _HAS_SSDEEP:
        try:
            h.ssdeep = ssdeep.hash(data)
        except Exception:
            pass
    return h

"""Orquestación del análisis estático (sin ejecutar la muestra)."""
from __future__ import annotations

from ..config import config
from ..models import StaticResult
from .hashes import compute_hashes
from .pe_info import analyze_pe
from .strings_ex import analyze_strings
from .yara_scan import scan_yara


def _guess_filetype(data: bytes) -> str:
    if data[:2] == b"MZ":
        return "PE / ejecutable Windows"
    if data[:4] == b"\x7fELF":
        return "ELF / ejecutable Linux"
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "ZIP / OOXML"
    if data[:4] == b"%PDF":
        return "PDF"
    if data[:2] == b"\xd0\xcf":
        return "OLE (documento Office antiguo)"
    return "desconocido"


def run_static(filename: str, data: bytes) -> StaticResult:
    ind, interesting = analyze_strings(data, config.max_strings)
    pe = analyze_pe(data)
    res = StaticResult(
        filename=filename,
        size=len(data),
        filetype=_guess_filetype(data),
        hashes=compute_hashes(data),
        pe=pe,
        indicators=ind,
        yara=scan_yara(data, config.yara_rules_dir),
        interesting_strings=interesting,
    )
    res.hashes.imphash = pe.imphash
    return res

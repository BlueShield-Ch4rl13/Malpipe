"""Extracción de strings imprimibles e IOCs (IPs, dominios, URLs, emails)."""
from __future__ import annotations

import re

from ..models import Indicators

# Strings imprimibles ASCII y UTF-16LE de longitud >= 5
_ASCII = re.compile(rb"[\x20-\x7e]{5,}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")

_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_URL = re.compile(r"\bhttps?://[^\s\"'<>]{4,}", re.IGNORECASE)
_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|info|biz|ru|cn|top|xyz|io|co|de|uk|es|eu|online|site|club|tk)\b",
    re.IGNORECASE,
)
_EMAIL = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.IGNORECASE)

# Palabras que hacen a un string "interesante" para el analista
_INTERESTING = re.compile(
    r"(cmd\.exe|powershell|rundll32|regsvr32|schtasks|\\Run\\|CurrentVersion\\Run|"
    r"HKEY_|\.onion|base64|VirtualAlloc|CreateRemoteThread|bitcoin|wallet|ransom|"
    r"\.php\?|/gate\.|/panel|user-agent|mozilla)",
    re.IGNORECASE,
)

# Dominios de ruido que casi nunca son IOC reales
_NOISE_DOMAINS = {
    "microsoft.com", "windows.com", "schemas.microsoft.com", "w3.org",
    "verisign.com", "digicert.com", "example.com",
}


def _extract_strings(data: bytes) -> list[str]:
    out: list[str] = []
    for m in _ASCII.finditer(data):
        out.append(m.group().decode("latin-1", "replace"))
    for m in _UTF16.finditer(data):
        out.append(m.group().decode("utf-16-le", "replace"))
    return out


def analyze_strings(data: bytes, max_strings: int = 40) -> tuple[Indicators, list[str]]:
    strings = _extract_strings(data)
    blob = "\n".join(strings)

    ind = Indicators(
        ips=sorted({ip for ip in _IP.findall(blob) if not ip.startswith(("0.", "127."))}),
        urls=sorted(set(_URL.findall(blob)))[:50],
        emails=sorted(set(_EMAIL.findall(blob)))[:50],
    )
    ind.domains = sorted(
        {d.lower() for d in _DOMAIN.findall(blob) if d.lower() not in _NOISE_DOMAINS}
    )[:50]

    interesting = []
    seen = set()
    for s in strings:
        if _INTERESTING.search(s) and s not in seen:
            interesting.append(s.strip()[:200])
            seen.add(s)
            if len(interesting) >= max_strings:
                break

    return ind, interesting

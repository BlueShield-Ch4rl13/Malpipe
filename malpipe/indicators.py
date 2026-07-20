"""Cadenas, IOCs y firmas YARA de la muestra.

Extrae las cadenas legibles (ASCII y UTF-16, como el clásico `strings` pero
también con las Unicode que Windows usa mucho), saca de ellas indicadores de
compromiso (IPs, dominios, URLs, claves de registro, mutex, rutas…) y escanea
la muestra con un conjunto de reglas YARA.
"""
from __future__ import annotations

import re
from pathlib import Path

# Cadenas ASCII y UTF-16LE de longitud mínima
_ASCII = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

RE_URL = re.compile(r"https?://[^\s\"'<>]{4,}", re.I)
RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                       r"(?:com|net|org|top|xyz|info|ru|cn|io|co|biz|onion|su|cc|pw|club|online)\b", re.I)
RE_MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.I)
RE_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
RE_REG = re.compile(r"\b(?:HKLM|HKCU|HKEY_[A-Z_]+)\\[^\s\"']{3,}", re.I)
RE_PATH = re.compile(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*")
RE_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")


def extract_strings(data: bytes, limit: int = 4000) -> list[str]:
    out = [m.decode("ascii", "replace") for m in _ASCII.findall(data)]
    out += [m.decode("utf-16-le", "replace") for m in _UTF16.findall(data)]
    # Dedupe conservando orden
    seen, uniq = set(), []
    for s in out:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
        if len(uniq) >= limit:
            break
    return uniq


def extract_iocs(strings: list[str]) -> list[dict]:
    """IOCs deduplicados con su tipo, a partir de las cadenas."""
    blob = "\n".join(strings)
    seen: dict[tuple, dict] = {}

    def add(kind, value):
        key = (kind, value.lower())
        if key not in seen:
            seen[key] = {"type": kind, "value": value,
                         "defanged": value.replace("http", "hxxp").replace(".", "[.]")
                         if kind in ("url", "domain", "ipv4") else value}

    for m in RE_URL.findall(blob):
        add("url", m.rstrip(".,);"))
    for m in RE_SHA256.findall(blob):
        add("sha256", m)
    for m in RE_MD5.findall(blob):
        add("md5", m)
    for m in RE_IP.findall(blob):
        parts = m.split(".")
        if all(0 <= int(p) <= 255 for p in parts) and m not in ("0.0.0.0", "127.0.0.1"):
            add("ipv4", m)
    for m in RE_DOMAIN.findall(blob):
        add("domain", m.lower())
    for m in RE_REG.findall(blob):
        add("registry", m)
    for m in RE_EMAIL.findall(blob):
        add("email", m)
    return list(seen.values())


def yara_scan(data: bytes, rules_dir: Path) -> list[dict]:
    """Escanea la muestra con todas las reglas .yar del directorio dado."""
    try:
        import yara
    except ImportError:
        return []
    rule_files = sorted(Path(rules_dir).glob("*.yar")) + sorted(Path(rules_dir).glob("*.yara"))
    if not rule_files:
        return []
    try:
        rules = yara.compile(filepaths={f.stem: str(f) for f in rule_files})
    except yara.Error:
        return []
    matches = []
    for m in rules.match(data=data):
        matches.append({
            "rule": m.rule,
            "tags": list(m.tags),
            "meta": {k: str(v) for k, v in m.meta.items()},
        })
    return matches

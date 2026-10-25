"""Configuracion de njRAT (Bladabindi), por heuristica.

njRAT es .NET y deja su configuracion como cadenas UTF-16 del ensamblado: el
separador de su protocolo ("|'|'|"), el host y el puerto del C2, la campana en
base64 y la version ("0.7d", "0.6.4"...). No se interpreta el formato .NET:
se reconoce el separador y se toman de las cadenas el host, el puerto y la
campana. Por eso la confianza es media: el analista tiene que confirmarlo.
"""
from __future__ import annotations

import base64
import binascii
import re

from ..models import FamilyConfig

SEPARADOR = "|'|'|"
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){2,}")
_IP = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
_HOST = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$", re.I)
_VERSION = re.compile(r"^0\.[0-9](?:\.[0-9])?[a-z]?$")
_RUIDO = ("microsoft.com", "windows.com", "w3.org", "mscorlib", "system.")
_EXTENSIONES = {"exe", "dll", "bat", "cmd", "vbs", "js", "ps1", "tmp", "txt", "lnk", "scr", "log", "dat", "ini"}


def _cadenas(data: bytes) -> list[str]:
    return [m.group().decode("utf-16-le", "replace") for m in _UTF16.finditer(data)]


def _campana(c: str) -> str:
    if len(c) < 4 or len(c) % 4 or not re.fullmatch(r"[A-Za-z0-9+/]+=*", c):
        return ""
    try:
        t = base64.b64decode(c, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return ""
    return t if t.isprintable() and 2 <= len(t) <= 64 else ""


def extraer(data: bytes) -> FamilyConfig | None:
    cadenas = _cadenas(data)
    if SEPARADOR not in cadenas:
        return None
    hosts = [c for c in cadenas
             if (_IP.match(c) or (_HOST.match(c) and c.rsplit(".", 1)[-1].lower() not in _EXTENSIONES))
             and not any(r in c.lower() for r in _RUIDO)]
    puertos = [c for c in cadenas if c.isdigit() and 1 <= int(c) <= 65535 and len(c) >= 2]
    versiones = [c for c in cadenas if _VERSION.match(c)]
    campanas = [t for t in (_campana(c) for c in cadenas) if t]
    c2 = [f"{hosts[0]}:{puertos[0]}"] if hosts and puertos else hosts[:1]
    valores: dict[str, object] = {"separador": SEPARADOR}
    if versiones:
        valores["version"] = versiones[0]
    if campanas:
        valores["campana"] = campanas[0]
    return FamilyConfig(family="njRAT", extractor="njrat", c2=c2, values=valores, confidence="media")

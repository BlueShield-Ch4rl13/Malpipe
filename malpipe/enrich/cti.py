"""Cruce con News CTI (cti.carlosvillalbalagos.com).

Busca los indicadores de la muestra (sus hashes, las IP, dominios y URL de sus
cadenas, los C2 de su configuracion y lo que vio el sandbox en la red) en el
feed publico de News CTI, el mismo data/iocs_latest.json que consumen
DetectionLab y ResponseLab. Un hash que ya esta en el feed es malware conocido;
una IP o un dominio en el feed son infraestructura que alguien ya ha visto
atacar.

El feed se descarga una vez por ejecucion (o se lee de un fichero con
--cti-fichero). En el portal web lo descarga el navegador y se lo pasa al mismo
codigo.
"""
from __future__ import annotations

import ipaddress
import json
import os
import urllib.request
from urllib.parse import urlsplit

from ..models import CtiCheck, CtiMatch, DynamicResult, FamilyConfig, StaticResult

FEED_POR_DEFECTO = "https://raw.githubusercontent.com/BlueShield-Ch4rl13/ScriptNewsCTI/main/data/iocs_latest.json"
TIPOS_HASH = {"filehash-md5": "md5", "filehash-sha1": "sha1", "filehash-sha256": "sha256"}


def cargar_feed(fuente: str = "", timeout: int = 20) -> dict:
    """fuente: URL o ruta de un iocs_latest.json. Vacia: MALPIPE_CTI_URL o el feed publico."""
    fuente = fuente or os.getenv("MALPIPE_CTI_URL", FEED_POR_DEFECTO)
    if os.path.exists(fuente):
        with open(fuente, encoding="utf-8") as f:
            datos = json.load(f)
    else:
        req = urllib.request.Request(fuente, headers={"User-Agent": "malpipe"})
        with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310 - URL de configuracion
            datos = json.load(r)
    datos.setdefault("_fuente", fuente)
    return datos


def _norm(tipo: str, valor: str) -> str:
    valor = valor.strip()
    if tipo == "ip:port":
        return valor.rsplit(":", 1)[0]
    if tipo == "url":
        return valor.rstrip("/")
    return valor.lower()


def _clave_tipo(tipo: str) -> str:
    if tipo in TIPOS_HASH:
        return "hash"
    if tipo in ("ipv4", "ip:port", "ip"):
        return "ip"
    if tipo in ("domain", "hostname"):
        return "dominio"
    return tipo


def indexar(feed: dict) -> dict[tuple[str, str], dict]:
    indice: dict[tuple[str, str], dict] = {}
    for ioc in feed.get("iocs") or []:
        tipo = str(ioc.get("type", ""))
        for v in [ioc.get("value", ""), *(ioc.get("variants") or [])]:
            if v:
                indice.setdefault((_clave_tipo(tipo), _norm(tipo, str(v))), ioc)
    return indice


def _es_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _host_de(c2: str) -> str:
    if "://" in c2:
        return urlsplit(c2).hostname or ""
    return c2.rsplit(":", 1)[0] if c2.count(":") == 1 else c2


def candidatos(static: StaticResult, dynamic: DynamicResult, configs: list[FamilyConfig]) -> list[tuple[str, str]]:
    """(clave de tipo, valor normalizado) de todo lo que la muestra deja ver."""
    vistos: list[tuple[str, str]] = []

    def anadir(clave: str, valor: str) -> None:
        if valor and (clave, valor) not in vistos:
            vistos.append((clave, valor))

    h = static.hashes
    for valor in (h.sha256, h.sha1, h.md5):
        anadir("hash", valor.lower())
    for ip in [*static.indicators.ips, *dynamic.hosts]:
        anadir("ip", ip)
    for d in [*static.indicators.domains, *dynamic.domains]:
        anadir("dominio", d.lower())
    urls = [*static.indicators.urls, *dynamic.urls, *(c for cfg in configs for c in cfg.c2 if "://" in c)]
    for u in urls:
        anadir("url", u.rstrip("/"))
        host = (urlsplit(u).hostname or "").lower()
        anadir("ip" if _es_ip(host) else "dominio", host)
    for cfg in configs:
        for c in cfg.c2:
            host = _host_de(c).lower()
            anadir("ip" if _es_ip(host) else "dominio", host)
    return vistos


def cruzar(static: StaticResult, dynamic: DynamicResult, configs: list[FamilyConfig], feed: dict) -> CtiCheck:
    indice = indexar(feed)
    chk = CtiCheck(checked=True, source=str(feed.get("_fuente", "")), generated=str(feed.get("generated_utc", "")),
                   indicators=len(feed.get("iocs") or []))
    for clave, valor in candidatos(static, dynamic, configs):
        ioc = indice.get((clave, valor))
        if not ioc:
            continue
        chk.matches.append(CtiMatch(
            value=str(ioc.get("value", "")), type=str(ioc.get("type", "")), matched=valor,
            threat=str(ioc.get("threat", "")), level=str(ioc.get("level", "")),
            score=ioc.get("score"), sources=list(ioc.get("sources") or []),
            reference=str(ioc.get("reference", "")), first_seen=str(ioc.get("first_seen", ""))))
    return chk

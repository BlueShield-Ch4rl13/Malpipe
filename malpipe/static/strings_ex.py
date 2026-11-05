"""Extracción de strings imprimibles e IOCs (IPs, dominios, URLs, emails)."""
from __future__ import annotations

import re

from ..models import Indicators

# Strings imprimibles ASCII y UTF-16LE de longitud >= 5
_ASCII = re.compile(rb"[\x20-\x7e]{5,}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")

_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_URL = re.compile(r"\bhttps?://[^\s\"'<>]{4,2048}", re.IGNORECASE)

# Dominios y correos en tiempo lineal. Las expresiones de antes
# (\b(label\.)+tld\b y \b[...]+@[...]+\.[a-z]{2,}\b) volvian a recorrer cada
# trozo desde cada posicion: con "a.a.a.a..." 40 KB tardaban casi un minuto, y
# una muestra preparada asi colgaba el analisis (CLI, webapp y el portal). Ahora
# solo se empieza al principio de cada trozo (lookbehind), sin cuantificadores
# anidados ambiguos, y lo demas se comprueba en Python sobre el trozo.
_TLDS = frozenset(
    "com net org info biz ru cn top xyz io co de uk es eu online site club tk".split()
)
_TROZO = re.compile(r"(?<![a-z0-9-])[a-z0-9-]+(?:\.[a-z0-9-]+)+", re.IGNORECASE)
_EMAIL = re.compile(
    r"(?<![a-z0-9._%+-])[a-z0-9._%+-]{1,64}@"
    r"[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})*\.[a-z]{2,63}(?![a-z0-9_])",
    re.IGNORECASE,
)
_ETIQUETA = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.IGNORECASE)
_MAX_DOMINIO = 253


def _primera_etiqueta(etiqueta: str, tras_palabra: bool) -> str:
    """Donde empezaria \\b dentro de la primera etiqueta: al principio (si no va
    pegada a una letra o a "_") o justo detras de un guion; la de mas a la izquierda
    que sea una etiqueta valida, o "" si ninguna lo es."""
    inicios = ([] if tras_palabra else [0]) + [k + 1 for k, c in enumerate(etiqueta) if c == "-"]
    for k in inicios:
        if _ETIQUETA.fullmatch(etiqueta[k:]):
            return etiqueta[k:]
    return ""


def _dominios(trozo: str, tras_palabra: bool = False):
    """Los dominios de un trozo a.b.c...: cada tramo de etiquetas validas que acaba
    en uno de los TLD de la lista, lo mas largo posible, como hacia la expresion
    (y como ella, un guion corta: evil.com-x da evil.com, y -evil.com da evil.com)."""
    etiquetas = trozo.split(".")
    i = 0
    while i < len(etiquetas):
        primera = _primera_etiqueta(etiquetas[i], tras_palabra and i == 0)
        if not primera:
            i += 1
            continue
        tramo, mejor = [primera], []
        j = i + 1
        while j < len(etiquetas):
            e = etiquetas[j]
            cabeza = e.split("-", 1)[0]
            if "-" in e and cabeza.lower() in _TLDS and _ETIQUETA.fullmatch(cabeza):
                mejor = tramo + [cabeza]
            if not _ETIQUETA.fullmatch(e):
                break
            tramo.append(e)
            if e.lower() in _TLDS:
                mejor = list(tramo)
            j += 1
        if len(mejor) >= 2:
            dominio = ".".join(mejor)
            if len(dominio) <= _MAX_DOMINIO:
                yield dominio
        i = max(j, i + 1)


def _correos(texto: str):
    for m in _EMAIL.finditer(texto):
        local, _, dominio = m.group().partition("@")
        # Como \b: el correo empieza en la primera letra, cifra o "_" del trozo
        local = local.lstrip(".%+-")
        if local and len(dominio) <= _MAX_DOMINIO:
            yield f"{local}@{dominio}"


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
        emails=sorted(set(_correos(blob)))[:50],
    )
    ind.domains = sorted(
        {d.lower() for m in _TROZO.finditer(blob)
         for d in _dominios(m.group(), m.start() > 0 and blob[m.start() - 1] == "_")
         if d.lower() not in _NOISE_DOMAINS}
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

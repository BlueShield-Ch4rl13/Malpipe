"""Configuracion de Remcos RAT.

Remcos guarda su configuracion en un recurso RT_RCDATA llamado SETTINGS: el
primer byte es la longitud de la clave, despues la clave y despues la
configuracion cifrada con RC4. En claro, los campos van separados por
"|\\x1e\\x1e\\x1f|" y el primero es la lista de C2 (host:puerto:tls, separados por
\\x1e). Es el formato que describen los analisis publicos de Remcos 3.x y 4.x.
"""
from __future__ import annotations

import re

from ..models import FamilyConfig

try:
    import pefile  # type: ignore
except ImportError:  # pragma: no cover - pefile es dependencia del nucleo
    pefile = None

SEPARADORES = (b"|\x1e\x1e\x1f|", b"\x1e\x1e\x1f")
MUTEX = re.compile(r"^(Rmc-[A-Z0-9]{6}|Remcos_Mutex_Inj)$")


def rc4(clave: bytes, datos: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + clave[i % len(clave)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    salida = bytearray()
    for b in datos:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        salida.append(b ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(salida)


def recurso_settings(data: bytes) -> bytes | None:
    if pefile is None or data[:2] != b"MZ":
        return None
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    except pefile.PEFormatError:
        return None
    raiz = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    for tipo in raiz.entries if raiz else []:
        if tipo.id != pefile.RESOURCE_TYPE["RT_RCDATA"] or not hasattr(tipo, "directory"):
            continue
        for nombre in tipo.directory.entries:
            if not nombre.name or str(nombre.name).upper() != "SETTINGS" or not hasattr(nombre, "directory"):
                continue
            for idioma in nombre.directory.entries:
                d = idioma.data.struct
                return pe.get_data(d.OffsetToData, d.Size)
    return None


def descifrar(blob: bytes) -> bytes | None:
    if len(blob) < 3:
        return None
    largo = blob[0]
    if not 1 <= largo < len(blob) - 1:
        return None
    return rc4(blob[1:1 + largo], blob[1 + largo:])


def extraer(data: bytes) -> FamilyConfig | None:
    blob = recurso_settings(data)
    if not blob:
        return None
    claro = descifrar(blob)
    if not claro:
        return None
    sep = next((s for s in SEPARADORES if s in claro), None)
    if sep is None:
        return None
    campos = [c.decode("latin-1", "replace").strip("\x00") for c in claro.split(sep)]
    c2 = []
    for entrada in re.split(r"[\x1e|]", campos[0]):
        partes = entrada.split(":")
        if len(partes) >= 2 and partes[0] and partes[1].isdigit():
            c2.append(f"{partes[0]}:{partes[1]}")
    if not c2:
        return None
    valores: dict[str, object] = {"nombre_asignado": campos[1] if len(campos) > 1 else "",
                                  "campos": len(campos)}
    tls = [e.split(":")[2] for e in re.split(r"[\x1e|]", campos[0]) if e.count(":") >= 2]
    if tls:
        valores["tls"] = tls
    mutex = next((c for c in campos if MUTEX.match(c)), "")
    if mutex:
        valores["mutex"] = mutex
    return FamilyConfig(family="Remcos", extractor="remcos", c2=c2, values=valores, confidence="alta")

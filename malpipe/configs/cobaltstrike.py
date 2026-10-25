"""Configuracion de un beacon de Cobalt Strike.

El beacon guarda su configuracion como una tabla TLV (id, tipo, longitud, valor;
enteros en big endian) cifrada con un XOR de un byte: 0x69 en la version 3 y
0x2e en la 4. Se reconoce por el principio, que siempre es el ajuste 1
(BeaconType, tipo short, longitud 2): 00 01 00 01 00 02.

Es el formato que leen las herramientas publicas (1768.py de Didier Stevens,
CobaltStrikeParser de SentinelOne). Sale en claro en un beacon sin cifrar o en
un volcado de memoria; en un stager o en un beacon con la configuracion
ofuscada por un "sleep mask" no se encuentra.
"""
from __future__ import annotations

import struct

from ..models import FamilyConfig

CABECERA = b"\x00\x01\x00\x01\x00\x02"
CLAVES_XOR = (0x2E, 0x69, 0x00)
TAMANO_MAXIMO = 6144          # 4096 en la version 3, 6144 en la 4

# Solo los ajustes cuyo significado esta bien documentado; el resto sale como
# "ajuste_<n>" para que el analista lo vea sin inventarle un nombre.
AJUSTES = {
    1: "BeaconType", 2: "Port", 3: "SleepTime", 4: "MaxGetSize", 5: "Jitter", 6: "MaxDNS",
    7: "PublicKey", 8: "C2Server", 9: "UserAgent", 10: "HttpPostUri", 15: "PipeName",
    19: "DNS_Idle", 20: "DNS_Sleep", 26: "HttpGet_Verb", 27: "HttpPost_Verb", 28: "HttpPostChunk",
    29: "Spawnto_x86", 30: "Spawnto_x64", 31: "CryptoScheme", 37: "Watermark", 40: "KillDate",
}
TIPOS_BEACON = {0: "HTTP", 1: "Hybrid HTTP DNS", 2: "SMB", 4: "TCP", 8: "HTTPS", 16: "Bind TCP"}
SIN_MOSTRAR = {7, 11, 12, 13}  # clave publica y bloques de Malleable C2: binarios largos


def _xor(datos: bytes, clave: int) -> bytes:
    return datos if clave == 0 else bytes(b ^ clave for b in datos)


def _tlv(bloque: bytes) -> dict[int, object]:
    ajustes: dict[int, object] = {}
    pos = 0
    while pos + 6 <= len(bloque):
        ident, tipo, largo = struct.unpack_from(">HHH", bloque, pos)
        pos += 6
        if ident == 0:
            break
        if tipo not in (1, 2, 3) or pos + largo > len(bloque) or ident > 128:
            break                                    # ya no es la tabla
        valor = bloque[pos:pos + largo]
        pos += largo
        if tipo == 1 and largo >= 2:
            ajustes[ident] = struct.unpack(">H", valor[:2])[0]
        elif tipo == 2 and largo >= 4:
            ajustes[ident] = struct.unpack(">I", valor[:4])[0]
        else:
            ajustes[ident] = valor
    return ajustes


def _texto(v: object) -> str:
    if isinstance(v, bytes):
        return v.split(b"\x00", 1)[0].decode("latin-1", "replace")
    return str(v)


def extraer(data: bytes) -> FamilyConfig | None:
    for clave in CLAVES_XOR:
        marca = _xor(CABECERA, clave)
        inicio = data.find(marca)
        while inicio != -1:
            ajustes = _tlv(_xor(data[inicio:inicio + TAMANO_MAXIMO], clave))
            if 1 in ajustes and 2 in ajustes and (8 in ajustes or ajustes.get(1) in (2, 4, 16)):
                return _configuracion(ajustes, clave)
            inicio = data.find(marca, inicio + 1)
    return None


def _configuracion(ajustes: dict[int, object], clave: int) -> FamilyConfig:
    tipo = ajustes.get(1)
    puerto = ajustes.get(2)
    valores: dict[str, object] = {"xor": f"0x{clave:02x}",
                                  "version": {0x2E: "4.x", 0x69: "3.x"}.get(clave, "sin cifrar")}
    for ident, v in sorted(ajustes.items()):
        if ident in SIN_MOSTRAR:
            continue
        nombre = AJUSTES.get(ident, f"ajuste_{ident}")
        valores[nombre] = _texto(v)
    valores["BeaconType"] = TIPOS_BEACON.get(tipo, str(tipo))

    c2: list[str] = []
    servidores = _texto(ajustes.get(8, b"")).split(",")
    esquema = "https" if tipo == 8 else "http"
    uris = servidores[1::2] + [""] * len(servidores)
    for host, uri in zip(servidores[0::2], uris[:len(servidores[0::2])], strict=True):
        host = host.strip()
        if host:
            c2.append(f"{esquema}://{host}:{puerto}{uri.strip()}" if tipo in (0, 1, 8) else f"{host}:{puerto}")
    return FamilyConfig(family="Cobalt Strike", extractor="cobaltstrike", c2=c2, values=valores,
                        confidence="alta")

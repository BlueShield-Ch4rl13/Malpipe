"""Muestras sinteticas que reproducen el formato de cada familia.

No son malware: son bytes construidos a mano con la misma estructura que el
extractor espera (la tabla TLV de Cobalt Strike, el recurso SETTINGS de Remcos,
las cadenas de njRAT). Sirven para probar que el extractor entiende el formato,
no que detecte una muestra real.
"""
from __future__ import annotations

import os
import struct

from malpipe.configs.remcos import rc4


def beacon_cobaltstrike(clave: int = 0x2E) -> bytes:
    def corto(i, v):
        return struct.pack(">HHHH", i, 1, 2, v)

    def entero(i, v):
        return struct.pack(">HHHI", i, 2, 4, v)

    def datos(i, v: bytes, largo: int):
        return struct.pack(">HHH", i, 3, largo) + v.ljust(largo, b"\x00")

    tabla = (corto(1, 8) + corto(2, 443) + entero(3, 60000) + corto(5, 20)
             + datos(8, b"cdn.ejemplo-malo.test,/jquery-3.3.1.min.js", 256)
             + datos(9, b"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", 128)
             + datos(10, b"/submit.php", 64) + entero(37, 305419896) + b"\x00" * 6)
    cifrada = bytes(b ^ clave for b in tabla)
    return os.urandom(3000) + cifrada.ljust(4096, bytes([clave])) + os.urandom(2000)


def _directorio(nombrados: int, por_id: int) -> bytes:
    return struct.pack("<IIHHHH", 0, 0, 0, 0, nombrados, por_id)


def pe_con_recurso(nombre: str, contenido: bytes, tipo: int = 10) -> bytes:
    """PE32 minimo con un unico recurso <tipo>/<nombre>/0x409 (por defecto RT_RCDATA)."""
    rva = 0x1000
    nombre_utf16 = struct.pack("<H", len(nombre)) + nombre.encode("utf-16-le")
    off_l2, off_l3, off_entrada, off_nombre = 24, 48, 72, 88
    off_datos = (off_nombre + len(nombre_utf16) + 3) & ~3
    rsrc = bytearray()
    rsrc += _directorio(0, 1) + struct.pack("<II", tipo, 0x80000000 | off_l2)
    rsrc += _directorio(1, 0) + struct.pack("<II", 0x80000000 | off_nombre, 0x80000000 | off_l3)
    rsrc += _directorio(0, 1) + struct.pack("<II", 0x409, off_entrada)
    rsrc += struct.pack("<IIII", rva + off_datos, len(contenido), 0, 0)
    rsrc += nombre_utf16
    rsrc += b"\x00" * (off_datos - len(rsrc)) + contenido
    crudo = (len(rsrc) + 0x1FF) & ~0x1FF

    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    directorios = [(0, 0)] * 16
    directorios[2] = (rva, len(rsrc))
    opcional = struct.pack("<HBBIIIIII", 0x10B, 0, 0, 0, crudo, 0, rva, rva, rva)
    opcional += struct.pack("<IIIHHHHHHIIIIHHIIIIII", 0x400000, 0x1000, 0x200, 4, 0, 0, 0, 4, 0, 0,
                            0x2000, 0x200, 0, 2, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opcional += b"".join(struct.pack("<II", *d) for d in directorios)
    seccion = b".rsrc\x00\x00\x00" + struct.pack("<IIIIIIHHI", len(rsrc), rva, crudo, 0x200, 0, 0, 0, 0, 0x40000040)
    cabeceras = (dos + b"PE\x00\x00" + coff + opcional + seccion).ljust(0x200, b"\x00")
    return cabeceras + bytes(rsrc).ljust(crudo, b"\x00")


def remcos(c2: str = "c2.ejemplo-malo.test:2404:1\x1e198.51.100.7:8080:0") -> bytes:
    sep = b"|\x1e\x1e\x1f|"
    campos = [c2.encode(), b"RemoteHost", b"1", b"0", b"Rmc-ABC123", b"0"]
    clave = b"clave-de-prueba-rc4"
    blob = bytes([len(clave)]) + clave + rc4(clave, sep.join(campos))
    return pe_con_recurso("SETTINGS", blob)


def njrat() -> bytes:
    cadenas = ["HacKed", "|'|'|", "SGFjS2Vk", "0.7d", "server.exe", "rat.ejemplo-malo.test", "5552", "TEMP"]
    cuerpo = b"".join(c.encode("utf-16-le") + b"\x00\x00" for c in cadenas)
    return b"MZ" + os.urandom(400) + cuerpo + os.urandom(200)

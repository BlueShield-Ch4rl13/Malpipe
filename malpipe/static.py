"""Análisis estático de una muestra: identidad, estructura y anomalías.

Sin ejecutar nada, extrae todo lo que se puede saber de un binario mirándolo:
tipo de fichero, hashes (incluido imphash y hash difuso para agrupar familias),
entropía (delata empaquetado/cifrado), y la estructura del ejecutable (secciones,
imports, exports, recursos, firma). Marca además anomalías típicas de malware
como secciones con permiso de escritura + ejecución o un número sospechosamente
bajo de imports (indicio de packer).

Formato principal: PE (Windows), con pefile. ELF (Linux) de forma best-effort
con LIEF. Cualquier otro tipo se analiza igualmente por hashes, strings y YARA.
"""
from __future__ import annotations

import hashlib
import math
from pathlib import Path

import pefile
import ppdeep

try:
    import magic  # python-magic (libmagic)
except Exception:  # pragma: no cover
    magic = None
try:
    import lief
    lief.logging.disable()
except Exception:  # pragma: no cover
    lief = None

# Nombres de sección estándar de compiladores; los que no estén levantan sospecha
STD_SECTIONS = {".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".pdata",
                ".rsrc", ".reloc", ".tls", ".debug", ".CRT", ".gfids", ".didat"}


def shannon_entropy(data: bytes) -> float:
    """Entropía de Shannon (0-8). >7 sugiere cifrado o compresión (packer)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 3)


def hashes(data: bytes) -> dict:
    """Hashes criptográficos + hash difuso para agrupar variantes de una familia."""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "ssdeep": ppdeep.hash(data),
    }


def identify(path: Path, data: bytes) -> dict:
    """Identidad de la muestra: tamaño, tipo, hashes y entropía global."""
    ftype = "desconocido"
    if magic:
        try:
            ftype = magic.from_buffer(data)
        except Exception:
            pass
    info = {
        "filename": path.name,
        "size": len(data),
        "type": ftype,
        "entropy": shannon_entropy(data),
        **hashes(data),
    }
    # Formato de alto nivel
    if data[:2] == b"MZ":
        info["format"] = "PE"
    elif data[:4] == b"\x7fELF":
        info["format"] = "ELF"
    elif data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        info["format"] = "Mach-O"
    else:
        info["format"] = "otro"
    return info


# ---------------------------------------------------------------- PE
def analyze_pe(data: bytes) -> dict:
    """Estructura de un PE: cabeceras, secciones, imports/exports, firma, TLS."""
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError as exc:
        return {"error": f"PE no válido: {exc}"}

    out: dict = {}
    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    out["is_dll"] = bool(fh.Characteristics & 0x2000)
    out["machine"] = pefile.MACHINE_TYPE.get(fh.Machine, hex(fh.Machine))
    out["compile_timestamp"] = _ts(fh.TimeDateStamp)
    out["subsystem"] = pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, str(oh.Subsystem))
    out["entrypoint"] = hex(oh.AddressOfEntryPoint)
    try:
        out["imphash"] = pe.get_imphash()
    except Exception:
        out["imphash"] = ""

    # Secciones con entropía y permisos
    sections = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
        ch = s.Characteristics
        sections.append({
            "name": name,
            "vsize": s.Misc_VirtualSize,
            "rsize": s.SizeOfRawData,
            "entropy": round(s.get_entropy(), 3),
            "exec": bool(ch & 0x20000000),
            "write": bool(ch & 0x80000000),
        })
    out["sections"] = sections

    # Imports (dll -> [funciones])
    imports: dict[str, list[str]] = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("latin-1", "replace") if entry.dll else "?"
            funcs = [imp.name.decode("latin-1", "replace") for imp in entry.imports if imp.name]
            imports.setdefault(dll, []).extend(funcs)
    out["imports"] = imports
    out["import_count"] = sum(len(v) for v in imports.values())

    # Exports (relevante en DLLs maliciosas)
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode("latin-1", "replace"))
    out["exports"] = exports

    # Recursos, firma embebida y callbacks TLS
    out["resource_count"] = len(getattr(getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None), "entries", []) or [])
    out["has_signature"] = oh.DATA_DIRECTORY[4].VirtualAddress != 0  # solo presencia, no validez
    out["tls_callbacks"] = hasattr(pe, "DIRECTORY_ENTRY_TLS")

    out["anomalies"] = _pe_anomalies(out)
    pe.close()
    return out


def _pe_anomalies(pe: dict) -> list[str]:
    """Señales estructurales sospechosas (no concluyentes por sí solas)."""
    a = []
    for s in pe["sections"]:
        if s["exec"] and s["write"]:
            a.append(f"Sección {s['name']} con escritura + ejecución (RWX)")
        if s["entropy"] >= 7.2 and s["rsize"] > 0:
            a.append(f"Sección {s['name']} con entropía muy alta ({s['entropy']}) — posible empaquetado")
        if s["name"] not in STD_SECTIONS and s["name"]:
            a.append(f"Nombre de sección no estándar: {s['name']}")
        if s["vsize"] > 0 and s["rsize"] == 0:
            a.append(f"Sección {s['name']} virtual sin datos en disco")
    if pe["import_count"] <= 5:
        a.append(f"Muy pocos imports ({pe['import_count']}) — típico de binarios empaquetados")
    if not pe.get("imphash"):
        a.append("Sin tabla de imports resoluble")
    return a


def _ts(t: int) -> str:
    from datetime import datetime, timezone
    if not t:
        return ""
    try:
        return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


# ---------------------------------------------------------------- ELF
def analyze_elf(path: Path) -> dict:
    """Estructura básica de un ELF con LIEF (best-effort)."""
    if lief is None:
        return {"error": "LIEF no disponible"}
    try:
        b = lief.parse(str(path))
        if b is None:
            return {"error": "ELF no parseable"}
    except Exception as exc:
        return {"error": f"ELF ilegible: {exc}"}
    sections = [{"name": s.name, "size": s.size, "entropy": round(getattr(s, "entropy", 0.0), 3)}
                for s in b.sections]
    imported = []
    for attr in ("imported_functions", "symbols"):
        try:
            vals = getattr(b, attr)
            imported = [str(getattr(f, "name", f)) for f in vals][:500]
            if imported:
                break
        except Exception:
            continue
    return {"sections": sections, "imports": {"": imported}, "import_count": len(imported),
            "anomalies": []}

"""Análisis estático de la cabecera PE (Windows). Usa pefile. No ejecuta la muestra."""
from __future__ import annotations

from datetime import datetime, timezone

from ..models import PeInfo, PeSection

try:
    import pefile  # type: ignore
    _HAS_PEFILE = True
except ImportError:
    _HAS_PEFILE = False


# APIs de Windows que suelen aparecer en malware. No prueban nada por sí solas,
# pero orientan al analista y alimentan el mapeo ATT&CK.
SUSPICIOUS_APIS = {
    "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
    "NtUnmapViewOfSection", "QueueUserAPC", "SetWindowsHookEx",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "GetTickCount", "URLDownloadToFile", "InternetOpen", "WinHttpOpen",
    "WSASocket", "connect", "RegSetValueEx", "RegCreateKeyEx",
    "CreateServiceA", "CreateServiceW", "StartServiceCtrlDispatcher",
    "CryptEncrypt", "CryptGenKey", "AdjustTokenPrivileges", "OpenProcessToken",
    "ShellExecute", "WinExec", "CreateProcess", "LoadLibrary", "GetProcAddress",
}

MACHINE = {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0xaa64: "ARM64"}
SUBSYSTEM = {1: "native", 2: "GUI", 3: "console", 9: "WinCE", 10: "EFI"}


def analyze_pe(data: bytes) -> PeInfo:
    info = PeInfo()
    if not _HAS_PEFILE:
        return info
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except Exception:
        return info  # no es un PE válido

    info.is_pe = True
    info.machine = MACHINE.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
    info.is_dll = bool(pe.is_dll())
    info.subsystem = SUBSYSTEM.get(
        pe.OPTIONAL_HEADER.Subsystem, str(pe.OPTIONAL_HEADER.Subsystem)
    )

    ts = pe.FILE_HEADER.TimeDateStamp
    if ts:
        info.compile_time = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

    try:
        info.imphash = pe.get_imphash()
    except Exception:
        info.imphash = ""

    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
        info.sections.append(
            PeSection(
                name=name,
                virtual_size=s.Misc_VirtualSize,
                raw_size=s.SizeOfRawData,
                entropy=round(s.get_entropy(), 2),
            )
        )

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("latin-1", "replace")
            info.imported_dlls.append(dll)
            for imp in entry.imports:
                if not imp.name:
                    continue
                api = imp.name.decode("latin-1", "replace")
                if api in SUSPICIOUS_APIS:
                    info.suspicious_imports.append(api)

    info.imported_dlls = sorted(set(info.imported_dlls))
    info.suspicious_imports = sorted(set(info.suspicious_imports))
    pe.close()
    return info

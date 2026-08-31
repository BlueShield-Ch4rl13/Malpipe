"""Mapeo heurístico a MITRE ATT&CK.

Combina dos fuentes:
  - Imports sospechosos del análisis estático  -> técnica probable.
  - Palabras clave de las firmas del sandbox    -> técnica probable.

Es una heurística orientativa para el analista, no un veredicto definitivo.
"""
from __future__ import annotations

from ..models import AttackTechnique, DynamicResult, StaticResult

# API de Windows -> (técnica, nombre, táctica)
_IMPORT_MAP: dict[str, tuple[str, str, str]] = {
    "VirtualAlloc": ("T1055", "Process Injection", "Defense Evasion"),
    "VirtualProtect": ("T1055", "Process Injection", "Defense Evasion"),
    "WriteProcessMemory": ("T1055", "Process Injection", "Defense Evasion"),
    "CreateRemoteThread": ("T1055.003", "Thread Execution Hijacking", "Defense Evasion"),
    "NtUnmapViewOfSection": ("T1055.012", "Process Hollowing", "Defense Evasion"),
    "QueueUserAPC": ("T1055.004", "APC Injection", "Defense Evasion"),
    "SetWindowsHookEx": ("T1056.004", "Credential API Hooking", "Collection"),
    "IsDebuggerPresent": ("T1622", "Debugger Evasion", "Defense Evasion"),
    "CheckRemoteDebuggerPresent": ("T1622", "Debugger Evasion", "Defense Evasion"),
    "NtQueryInformationProcess": ("T1622", "Debugger Evasion", "Defense Evasion"),
    "GetTickCount": ("T1497.003", "Time Based Evasion", "Defense Evasion"),
    "URLDownloadToFile": ("T1105", "Ingress Tool Transfer", "Command and Control"),
    "InternetOpen": ("T1071.001", "Web Protocols", "Command and Control"),
    "WinHttpOpen": ("T1071.001", "Web Protocols", "Command and Control"),
    "WSASocket": ("T1095", "Non-Application Layer Protocol", "Command and Control"),
    "RegSetValueEx": ("T1547.001", "Registry Run Keys / Startup Folder", "Persistence"),
    "RegCreateKeyEx": ("T1112", "Modify Registry", "Defense Evasion"),
    "CreateServiceA": ("T1543.003", "Windows Service", "Persistence"),
    "CreateServiceW": ("T1543.003", "Windows Service", "Persistence"),
    "CryptEncrypt": ("T1486", "Data Encrypted for Impact", "Impact"),
    "CryptGenKey": ("T1486", "Data Encrypted for Impact", "Impact"),
    "AdjustTokenPrivileges": ("T1134", "Access Token Manipulation", "Privilege Escalation"),
    "OpenProcessToken": ("T1134", "Access Token Manipulation", "Privilege Escalation"),
    "ShellExecute": ("T1059", "Command and Scripting Interpreter", "Execution"),
    "WinExec": ("T1059", "Command and Scripting Interpreter", "Execution"),
    "CreateProcess": ("T1059", "Command and Scripting Interpreter", "Execution"),
    "LoadLibrary": ("T1129", "Shared Modules", "Execution"),
}

# Subcadena en la firma del sandbox -> (técnica, nombre, táctica)
_SIGNATURE_MAP: list[tuple[str, tuple[str, str, str]]] = [
    ("persistence", ("T1547.001", "Registry Run Keys / Startup Folder", "Persistence")),
    ("run key", ("T1547.001", "Registry Run Keys / Startup Folder", "Persistence")),
    ("scheduled task", ("T1053.005", "Scheduled Task", "Persistence")),
    ("service", ("T1543.003", "Windows Service", "Persistence")),
    ("injection", ("T1055", "Process Injection", "Defense Evasion")),
    ("hollow", ("T1055.012", "Process Hollowing", "Defense Evasion")),
    ("debugger", ("T1622", "Debugger Evasion", "Defense Evasion")),
    ("anti-vm", ("T1497", "Virtualization/Sandbox Evasion", "Defense Evasion")),
    ("sandbox", ("T1497", "Virtualization/Sandbox Evasion", "Defense Evasion")),
    ("credential", ("T1555", "Credentials from Password Stores", "Credential Access")),
    ("keylog", ("T1056.001", "Keylogging", "Collection")),
    ("ransom", ("T1486", "Data Encrypted for Impact", "Impact")),
    ("encrypt", ("T1486", "Data Encrypted for Impact", "Impact")),
    ("download", ("T1105", "Ingress Tool Transfer", "Command and Control")),
    ("c2", ("T1071", "Application Layer Protocol", "Command and Control")),
    ("powershell", ("T1059.001", "PowerShell", "Execution")),
    ("defender", ("T1562.001", "Disable or Modify Tools", "Defense Evasion")),
    ("shadow", ("T1490", "Inhibit System Recovery", "Impact")),
]


def map_attack(
    static: StaticResult, dynamic: DynamicResult
) -> list[AttackTechnique]:
    found: dict[str, AttackTechnique] = {}

    for api in static.pe.suspicious_imports:
        if api in _IMPORT_MAP:
            tid, name, tactic = _IMPORT_MAP[api]
            found[tid] = AttackTechnique(tid, name, tactic, source="static")

    for sig in dynamic.signatures:
        low = sig.lower()
        for needle, (tid, name, tactic) in _SIGNATURE_MAP:
            if needle in low:
                # el dinámico "gana" como fuente si ya existía por estático
                found[tid] = AttackTechnique(tid, name, tactic, source="dynamic")

    return sorted(found.values(), key=lambda t: t.id)

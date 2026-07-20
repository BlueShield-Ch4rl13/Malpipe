"""Detección de capacidades a partir de imports y cadenas.

Traduce el "qué APIs usa y qué cadenas contiene" a "qué sabe hacer": inyección
de código, persistencia, keylogging, evasión, descarga, cifrado… Cada capacidad
lleva su técnica MITRE ATT&CK y la evidencia concreta que la disparó, para que
el informe sea auditable (el mismo enfoque que la herramienta capa de Mandiant).
"""
from __future__ import annotations

# Cada regla: nombre -> (táctica, técnica ATT&CK, APIs [minúsculas], subcadenas)
# Basta con que aparezca una API o una cadena para marcar la capacidad.
RULES = {
    "Inyección de código": ("Defense Evasion", "T1055",
        ["virtualallocex", "writeprocessmemory", "createremotethread", "ntunmapviewofsection",
         "queueuserapc", "setthreadcontext", "ntwritevirtualmemory", "rtlcreateuserthread"], []),
    "Hollowing / mapeo de secciones": ("Defense Evasion", "T1055.012",
        ["ntmapviewofsection", "ntcreatesection", "zwunmapviewofsection"], []),
    "Ejecución de procesos": ("Execution", "T1059",
        ["createprocess", "createprocessa", "createprocessw", "winexec", "shellexecute",
         "shellexecutea", "shellexecutew", "system"], []),
    "Resolución dinámica de API": ("Defense Evasion", "T1027.007",
        ["getprocaddress", "loadlibrarya", "loadlibraryw", "loadlibraryexa", "ldrloaddll"], []),
    "Persistencia en registro": ("Persistence", "T1547.001",
        ["regsetvalueexa", "regsetvalueexw", "regcreatekeyexa", "regcreatekeyexw"],
        ["\\currentversion\\run", "currentversion\\runonce", "userinit", "\\winlogon"]),
    "Persistencia por servicio": ("Persistence", "T1543.003",
        ["createservicea", "createservicew", "openscmanagera", "startservicea"], []),
    "Persistencia por tarea programada": ("Persistence", "T1053.005",
        ["itaskscheduler", "itaskservice"], ["schtasks", "\\microsoft\\windows\\"]),
    "Keylogging": ("Collection", "T1056.001",
        ["setwindowshookexa", "setwindowshookexw", "getasynckeystate", "getkeystate",
         "getkeyboardstate", "registerrawinputdevices"], []),
    "Captura de pantalla": ("Collection", "T1113",
        ["bitblt", "getdc", "getdesktopwindow", "createcompatiblebitmap", "printwindow"], []),
    "Descarga de ficheros": ("Command and Control", "T1105",
        ["urldownloadtofilea", "urldownloadtofilew", "internetopena", "internetopenurla",
         "internetreadfile", "winhttpopen", "winhttpsendrequest", "httpsendrequest"],
        ["http://", "https://", "ftp://"]),
    "Comunicación por sockets": ("Command and Control", "T1095",
        ["wsastartup", "connect", "send", "recv", "socket", "gethostbyname", "inet_addr"], []),
    "Anti-debug": ("Defense Evasion", "T1622",
        ["isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
         "outputdebugstringa", "ntsetinformationthread"], []),
    "Anti-VM / anti-sandbox": ("Defense Evasion", "T1497",
        ["cpuid", "getmodulehandlea"],
        ["vmware", "virtualbox", "vbox", "qemu", "sandbox", "sbiedll", "\\\\.\\pipe\\cuckoo",
         "vmtoolsd", "wine_get_unix_file_name"]),
    "Cifrado (posible ransomware)": ("Impact", "T1486",
        ["cryptencrypt", "cryptacquirecontexta", "cryptgenkey", "bcryptencrypt",
         "cryptimportkey", "cryptderivekey"],
        ["your files have been encrypted", ".onion", "bitcoin", "readme.txt", "how_to_decrypt"]),
    "Robo de credenciales": ("Credential Access", "T1003",
        ["lsaenumeratelogonsessions", "samconnect", "credenumeratea", "cryptunprotectdata"],
        ["sekurlsa", "logonpasswords", "\\login data", "wallet.dat"]),
    "Descubrimiento del sistema": ("Discovery", "T1082",
        ["getcomputernamea", "getcomputernamew", "getusernamea", "getsysteminfo",
         "getnativesysteminfo", "gethostname"], []),
    "Manipulación de ficheros / borrado": ("Impact", "T1485",
        ["deletefilea", "deletefilew", "movefileexa", "setfileattributesa"],
        ["vssadmin delete", "cipher /w", "wbadmin delete", "bcdedit"]),
    "Evasión: deshabilitar defensas": ("Defense Evasion", "T1562.001",
        [], ["defender", "amsi.dll", "amsiscanbuffer", "set-mppreference", "disableantispyware"]),
    "Ofuscación / cadenas cifradas": ("Defense Evasion", "T1027",
        ["cryptstringtobinarya"], ["frombase64string", "-encodedcommand", "iex ", "invoke-expression"]),
}


def detect(imports: dict[str, list[str]], strings: list[str]) -> list[dict]:
    """Devuelve las capacidades detectadas con su técnica ATT&CK y evidencia."""
    api_set = {f.lower() for funcs in (imports or {}).values() for f in funcs}
    blob = "\n".join(strings).lower() if strings else ""

    found: list[dict] = []
    for name, (tactic, attack, apis, subs) in RULES.items():
        evidence: list[str] = []
        for a in apis:
            if a in api_set or a in blob:  # import table o resuelta dinámicamente (string)
                evidence.append(f"API {a}")
        for s in subs:
            if s in blob:
                evidence.append(f'cadena "{s}"')
        if evidence:
            found.append({"capability": name, "tactic": tactic, "attack": attack,
                          "evidence": evidence[:6]})
    return found

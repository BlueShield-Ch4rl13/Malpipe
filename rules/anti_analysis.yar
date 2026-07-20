/* Anti-debug / anti-VM / anti-sandbox */
rule AntiDbg_Common { meta: description="Comprobaciones anti-debugging" severity="medium"
  strings: $a="IsDebuggerPresent" $b="CheckRemoteDebuggerPresent" $c="NtQueryInformationProcess" $d="OutputDebugString" $e="NtSetInformationThread"
  condition: 2 of them }
rule AntiVM_Strings { meta: description="Detección de entorno virtual" severity="medium"
  strings: $= "VMware" nocase wide ascii $= "VirtualBox" nocase wide ascii $= "VBOX" nocase $= "qemu" nocase $= "Xen" fullword $= "vmtoolsd" nocase
  condition: 2 of them }
rule AntiSandbox_Artifacts { meta: description="Artefactos de sandbox conocidos" severity="high"
  strings: $= "SbieDll.dll" nocase $= "cuckoomon" nocase $= "\\\\.\\pipe\\cuckoo" $= "sandboxie" nocase $= "sample.exe" $= "wine_get_unix_file_name"
  condition: any of them }
rule AntiVM_MAC_Address { meta: description="MACs de hipervisores" severity="medium"
  strings: $= "00:05:69" $= "00:0C:29" $= "00:50:56" $= "08:00:27" condition: any of them }
rule AntiSandbox_Usernames { meta: description="Nombres de usuario típicos de sandbox" severity="medium"
  strings: $= "malware" nocase $= "sandbox" nocase $= "virus" nocase $= "maltest" $= "currentuser" nocase $= "john doe" nocase
  condition: 2 of them }
rule Evasion_Sleep_Timing { meta: description="Evasión por tiempo/sleep" severity="low"
  strings: $a="GetTickCount" $b="QueryPerformanceCounter" $c="timeGetTime" $d="NtDelayExecution"
  condition: 2 of them }
rule Evasion_Disable_AMSI { meta: description="Manipulación de AMSI/Defender" severity="high"
  strings: $= "AmsiScanBuffer" $= "amsi.dll" nocase $= "Set-MpPreference" nocase $= "DisableRealtimeMonitoring" nocase $= "DisableAntiSpyware" nocase
  condition: any of them }

/* Robo de credenciales y acceso a LSASS */
rule Cred_Mimikatz { meta: description="Mimikatz" severity="high" ref="public"
  strings: $a="sekurlsa" nocase $b="logonpasswords" nocase $c="kerberos::" nocase $d="gentilkiwi" nocase $e="mimikatz" nocase $f="wdigest" nocase
  condition: 2 of them }
rule Cred_LSASS_Dump { meta: description="Volcado de memoria de LSASS" severity="high"
  strings: $a="lsass.exe" nocase $b="MiniDumpWriteDump" $c="comsvcs.dll, MiniDump" nocase $d="SeDebugPrivilege"
  condition: 2 of them }
rule Cred_SAM_Access { meta: description="Acceso a hives SAM/SYSTEM/SECURITY" severity="high"
  strings: $a="\\config\\SAM" nocase $b="\\config\\SYSTEM" nocase $c="reg save hklm\\sam" nocase $d="reg save hklm\\system" nocase
  condition: 2 of them }
rule Cred_DPAPI { meta: description="Abuso de DPAPI" severity="medium"
  strings: $a="CryptUnprotectData" $b="\\Microsoft\\Protect\\" nocase $c="masterkey" nocase condition: 2 of them }
rule Cred_Kerberoast { meta: description="Kerberoasting / abuso de tickets" severity="high"
  strings: $a="kerberoast" nocase $b="GetUserSPNs" nocase $c="asktgt" nocase $d="Rubeus" nocase condition: any of them }

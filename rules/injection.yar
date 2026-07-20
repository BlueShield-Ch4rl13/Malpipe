/* Inyeccion de codigo y evasion en memoria */
rule Inj_Classic_RemoteThread { meta: description="Inyeccion clasica en proceso remoto" severity="high"
  strings: $a="VirtualAllocEx" $b="WriteProcessMemory" $c="CreateRemoteThread" condition: all of them }
rule Inj_Process_Hollowing { meta: description="Process hollowing (RunPE)" severity="high"
  strings: $a="NtUnmapViewOfSection" $b="ZwUnmapViewOfSection" $c="SetThreadContext" $d="ResumeThread" $e="CreateProcess" nocase
  condition: ($a or $b) and $c and $d and $e }
rule Inj_APC_QueueUserAPC { meta: description="Inyeccion por APC" severity="high"
  strings: $a="QueueUserAPC" $b="NtQueueApcThread" $c="VirtualAllocEx" condition: ($a or $b) and $c }
rule Inj_Reflective_DLL { meta: description="Carga reflectiva de DLL" severity="high"
  strings: $a="ReflectiveLoader" nocase $b="LoadRemoteLibraryR" condition: any of them }
rule Inj_SetWindowsHook { meta: description="Inyeccion por hook global" severity="medium"
  strings: $a="SetWindowsHookEx" $b="CallNextHookEx" condition: all of them }
rule Inj_Doppelganging { meta: description="Process Doppelganging (TxF)" severity="high"
  strings: $a="CreateTransaction" $b="CreateFileTransacted" $c="NtCreateProcessEx" $d="RollbackTransaction"
  condition: 3 of them }
rule Inj_EarlyBird { meta: description="Early Bird APC injection" severity="high"
  strings: $a="NtQueueApcThread" $b="CreateProcess" nocase $c="CREATE_SUSPENDED" condition: all of them }
rule Inj_DynamicAPI_Resolution { meta: description="Resolucion dinamica de APIs (evasion)" severity="medium"
  strings: $a="GetProcAddress" $b="LoadLibrary" $c="GetModuleHandle" condition: all of them }

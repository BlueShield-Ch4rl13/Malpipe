/* Documentos maliciosos */
rule Maldoc_VBA_AutoExec { meta: description="Macro VBA con auto-ejecución" severity="high"
  strings: $= "Auto_Open" nocase $= "AutoOpen" nocase $= "Document_Open" nocase $= "Workbook_Open" nocase $= "Auto_Close" nocase
  condition: any of them }
rule Maldoc_VBA_Shell { meta: description="Macro VBA que ejecuta comandos" severity="high"
  strings: $a= "Shell(" nocase $b= "WScript.Shell" nocase $c= "CreateObject" nocase $d= "powershell" nocase $e= "cmd.exe" nocase
  condition: (1 of ($a,$b)) and (1 of ($c,$d,$e)) }
rule Maldoc_RTF_EquationEditor { meta: description="RTF con exploit de Equation Editor (CVE-2017-11882)" severity="high" ref="public"
  strings: $= "\\objupdate" $= "Equation.3" $= "0x2332C" condition: 2 of them }
rule Maldoc_Excel4_Macro { meta: description="Macro Excel 4.0 (XLM)" severity="high"
  strings: $= "=CALL(" nocase $= "=EXEC(" nocase $= "=REGISTER(" nocase $= "Auto_Open" nocase condition: 2 of them }
rule Maldoc_DDE { meta: description="Ataque por DDE en documento" severity="medium"
  strings: $= "DDEAUTO" nocase $= "DDE " $= "!cmd" condition: any of them }
rule Maldoc_OLE_Header { meta: description="Documento OLE con VBA embebido" severity="low"
  strings: $ole = { D0 CF 11 E0 A1 B1 1A E1 } $vba= "VBA" condition: $ole at 0 and $vba }

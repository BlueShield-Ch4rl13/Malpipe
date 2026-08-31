/*
   Regla de ejemplo para malpipe.
   Añade aquí tus propias reglas (.yar / .yara). Se compilan y aplican todas.
*/

rule Ejemplo_Persistencia_RunKey
{
    meta:
        author      = "Carlos Villalba Lagos"
        description = "Indicadores genéricos de persistencia por clave Run del registro"
        reference   = "MITRE ATT&CK T1547.001"
        severity    = "medium"

    strings:
        $run1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $run2 = "CurrentVersion\\RunOnce" ascii wide nocase
        $api1 = "RegSetValueEx" ascii
        $api2 = "RegCreateKeyEx" ascii

    condition:
        // un PE que referencia la clave Run y además importa APIs de escritura de registro
        uint16(0) == 0x5A4D and 1 of ($run*) and 1 of ($api*)
}

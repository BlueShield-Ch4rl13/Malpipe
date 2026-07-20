/* Ofuscacion y codificacion */
rule Obf_Encoded_PowerShell { meta: description="PowerShell codificado en base64" severity="high"
  strings: $a="-EncodedCommand" nocase $b="-enc " nocase $c="FromBase64String" nocase $d="-e JAB" $e="powershell -nop -w hidden" nocase condition: any of them }
rule Obf_Base64_PE { meta: description="Ejecutable PE codificado en base64" severity="high"
  strings: $a="TVqQAAMAAAAEAAA" $b="TVpQAAIAAAAEAA8" condition: any of them }
rule Obf_Long_Base64_Blob { meta: description="Bloque base64 largo (payload embebido)" severity="medium"
  strings: $a = /[A-Za-z0-9+\/]{200,}={0,2}/ condition: $a }
rule Obf_XOR_Decode_Stub { meta: description="Stub de descifrado XOR sobre memoria ejecutable" severity="low"
  strings: $api="VirtualProtect" $stub = { 8b ?? ?? 30 ?? 40 } condition: $api and $stub }
rule Obf_String_Stacking { meta: description="Construccion de cadenas en pila (evasion de strings)" severity="low"
  strings: $s = { c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? } condition: $s }
rule Obf_Hex_Encoded_Command { meta: description="Comando codificado en hex con certutil" severity="medium"
  strings: $a="-decode" nocase $b="certutil -f -decodehex" nocase condition: any of them }

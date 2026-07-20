/* Ransomware — indicadores genericos y de familia (fuentes publicas) */
rule Ransom_Note_Generic { meta: description="Nota de rescate generica" severity="high"
  strings: $a="your files have been encrypted" nocase $b="all your files" nocase $c="how to decrypt" nocase $d="decryptor" nocase $e="pay the ransom" nocase $f=".onion" $g="bitcoin" nocase
  condition: 3 of them }
rule Ransom_Shadow_Deletion { meta: description="Borrado de copias de sombra (anti-recuperacion)" severity="high"
  strings: $a="vssadmin delete shadows" nocase $b="wmic shadowcopy delete" nocase $c="bcdedit /set" nocase $d="wbadmin delete catalog" nocase $e="Delete-VssSnapshot" nocase
  condition: any of them }
rule Ransom_Crypto_APIs { meta: description="APIs de cifrado + enumeracion de ficheros" severity="medium"
  strings: $a="CryptEncrypt" $b="CryptGenKey" $c="CryptAcquireContext" $d="FindFirstFile" $e="FindNextFile" $f="BCryptEncrypt"
  condition: (1 of ($a,$b,$c,$f)) and $d and $e }
rule Ransom_WannaCry { meta: description="Indicadores de WannaCry" severity="high" ref="public"
  strings: $a="WanaCrypt0r" nocase $b="WNcry@2ol7" $c="taskdl.exe" $d="@WanaDecryptor@" nocase $e="mssecsvc.exe"
  condition: any of them }
rule Ransom_LockBit { meta: description="Indicadores de LockBit" severity="high" ref="public"
  strings: $a="LockBit" nocase $b="Restore-My-Files.txt" nocase $c=".lockbit" $d="lockbitsupp" nocase
  condition: any of them }
rule Ransom_Conti { meta: description="Indicadores de Conti" severity="high" ref="public"
  strings: $a="CONTI_README.txt" nocase $b="R3ADM3.txt" $c=".CONTI" condition: any of them }
rule Ransom_REvil { meta: description="Indicadores de REvil/Sodinokibi" severity="high" ref="public"
  strings: $a="Sodinokibi" nocase $b="-nolan" $c="revil" nocase condition: any of them }
rule Ransom_BlackCat { meta: description="Indicadores de BlackCat/ALPHV" severity="high" ref="public"
  strings: $a="ALPHV" $b="RECOVER-" $c="blackcat" nocase $d="access-token" condition: 2 of them }
rule Ransom_Phobos { meta: description="Indicadores de Phobos" severity="high" ref="public"
  strings: $a=".phobos" $b="info.hta" $c="Phobos" nocase condition: any of them }
rule Ransom_STOP_Djvu { meta: description="Indicadores de STOP/Djvu" severity="high" ref="public"
  strings: $a="_readme.txt" $b="djvu" nocase $c="personal ID" nocase condition: 2 of them }

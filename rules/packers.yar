/* Empaquetadores y protectores — malpipe · uso defensivo */
rule Packer_UPX { meta: description="UPX packer" severity="low"
  strings: $a="UPX0" $b="UPX1" $c="UPX!" condition: 2 of them }
rule Packer_ASPack { meta: description="ASPack packer" severity="low"
  strings: $a=".aspack" $b=".adata" condition: any of them }
rule Packer_Themida { meta: description="Themida/WinLicense protector" severity="medium"
  strings: $a="Themida" nocase wide ascii $b=".themida" $c="WinLicense" nocase condition: any of them }
rule Packer_VMProtect { meta: description="VMProtect virtualizer" severity="medium"
  strings: $a=".vmp0" $b=".vmp1" $c="VMProtect" nocase condition: any of them }
rule Packer_MPRESS { meta: description="MPRESS packer" severity="low"
  strings: $a=".MPRESS1" $b=".MPRESS2" condition: any of them }
rule Packer_PECompact { meta: description="PECompact packer" severity="low"
  strings: $a="PEC2" $b="PECompact2" condition: any of them }
rule Packer_Enigma { meta: description="Enigma Protector" severity="medium"
  strings: $a="Enigma" nocase $b=".enigma1" condition: any of them }
rule Packer_FSG { meta: description="FSG packer" severity="low"
  strings: $a="FSG!" condition: any of them }
rule Packer_NsPack { meta: description="NsPack packer" severity="low"
  strings: $a=".nsp0" $b=".nsp1" $c="NsPacK" condition: any of them }
rule Packer_Obsidium { meta: description="Obsidium protector" severity="medium"
  strings: $a="Obsidium" nocase condition: any of them }
rule Packer_DotNet_ConfuserEx { meta: description=".NET ConfuserEx obfuscator" severity="medium"
  strings: $a="ConfusedByAttribute" $b="ConfuserEx" nocase condition: any of them }
rule Packer_DotNet_SmartAssembly { meta: description=".NET SmartAssembly" severity="low"
  strings: $a="SmartAssembly.Attributes" $b="PoweredByAttribute" condition: any of them }

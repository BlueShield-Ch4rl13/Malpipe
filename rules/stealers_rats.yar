/* Infostealers y RATs — indicadores públicos */
rule Stealer_Browser_Paths { meta: description="Robo de credenciales de navegadores" severity="high"
  strings: $= "\\Google\\Chrome\\User Data" $= "Login Data" $= "\\Mozilla\\Firefox\\Profiles" $= "logins.json" $= "cookies.sqlite" $= "\\Microsoft\\Edge\\User Data"
  condition: 2 of them }
rule Stealer_Crypto_Wallets { meta: description="Robo de carteras de criptomonedas" severity="high"
  strings: $= "wallet.dat" nocase $= "\\Electrum\\wallets" $= "\\Exodus\\" $= "\\Ethereum\\keystore" $= "metamask" nocase $= "\\Bitcoin\\"
  condition: 2 of them }
rule Stealer_Discord_Token { meta: description="Robo de tokens de Discord" severity="high"
  strings: $= "\\discord\\Local Storage\\leveldb" nocase $= "Authorization" $= "discord.com/api" nocase condition: 2 of them }
rule RAT_AsyncRAT { meta: description="AsyncRAT" severity="high" ref="public"
  strings: $= "AsyncRAT" nocase $= "Pastebin" nocase $= "aRAT" $= "Stub.exe" condition: 2 of them }
rule RAT_njRAT { meta: description="njRAT/Bladabindi" severity="high" ref="public"
  strings: $= "njrat" nocase $= "netsh firewall add" nocase $= "cmd.exe /c ping" $= "|'|'|" condition: any of them }
rule RAT_Remcos { meta: description="Remcos RAT" severity="high" ref="public"
  strings: $= "Remcos" nocase wide ascii $= "remcos_" $= "Breaking-Security" nocase condition: any of them }
rule RAT_QuasarRAT { meta: description="Quasar RAT" severity="high" ref="public"
  strings: $= "Quasar" nocase $= "get_Keylogger" $= "DoUploadAndExecute" condition: any of them }
rule RAT_NanoCore { meta: description="NanoCore RAT" severity="high" ref="public"
  strings: $= "NanoCore" nocase $= "ClientPlugin" $= "PluginCommand" condition: 2 of them }
rule Stealer_RedLine { meta: description="RedLine Stealer" severity="high" ref="public"
  strings: $= "RedLine" nocase $= "ScanBrowsers" $= "ScannedWallets" condition: 2 of them }
rule Stealer_AgentTesla { meta: description="Agent Tesla" severity="high" ref="public"
  strings: $= "AgentTesla" nocase $= "get_KeyLoggerEnabled" $= "smtp" nocase $= "IELibrary.dll" condition: 2 of them }
rule Stealer_Lumma_Vidar { meta: description="Lumma/Vidar stealer" severity="high" ref="public"
  strings: $= "lumma" nocase $= "vidar" nocase $= "c2sock" $= "\\soft\\" condition: any of them }

/* Descargadores, cradles y frameworks C2 */
rule C2_PowerShell_Download_Cradle { meta: description="Cradle de descarga en PowerShell" severity="high"
  strings: $a="DownloadString" nocase $b="DownloadFile" nocase $c="Net.WebClient" nocase $d="Invoke-WebRequest" nocase $e="IEX" nocase $f="Invoke-Expression" nocase
  condition: 2 of them }
rule C2_LOLBins_Download { meta: description="Descarga con binarios legitimos (LOLBins)" severity="high"
  strings: $a="certutil -urlcache" nocase $b="bitsadmin /transfer" nocase $c="mshta http" nocase $d="regsvr32 /s /u /i:http" nocase $e="curl http" nocase
  condition: any of them }
rule C2_CobaltStrike_Beacon { meta: description="Cobalt Strike Beacon" severity="high" ref="public"
  strings: $a="beacon.dll" nocase $b="%s as %s\\%s: %d" $c="ReflectiveLoader" $d="MZARUH" $e="%s.4%08x%s" condition: 2 of them }
rule C2_Metasploit { meta: description="Payload Metasploit/Meterpreter" severity="high" ref="public"
  strings: $a="metsrv" $b="meterpreter" nocase $c="stdapi_" condition: any of them }
rule C2_Sliver { meta: description="Sliver framework" severity="high" ref="public"
  strings: $a="sliverpb" $b="SliverRPC" $c="{{.Name}}" condition: 2 of them }
rule C2_Havoc { meta: description="Havoc framework (Demon)" severity="high" ref="public"
  strings: $a="Demon" fullword $b="havoc" nocase $c="KaynLib" condition: 2 of them }
rule Downloader_HTTP_UserAgent { meta: description="Descarga HTTP con User-Agent codificado" severity="medium"
  strings: $ua="Mozilla/4.0 (compatible; MSIE" $a="InternetOpenA" $b="InternetOpenUrlA" condition: $ua and (1 of ($a,$b)) }

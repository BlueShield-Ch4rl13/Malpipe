/* Webshells (deteccion de puertas traseras en servidores web) */
rule Webshell_PHP_Eval { meta: description="Webshell PHP con eval de entrada" severity="high"
  strings: $a="eval($_POST" nocase $b="eval($_GET" nocase $c="eval($_REQUEST" nocase $d="assert($_POST" nocase $e="eval(base64_decode($_" nocase
  condition: any of them }
rule Webshell_PHP_System { meta: description="Webshell PHP ejecutando comandos" severity="high"
  strings: $a="$_POST" $b="$_GET" $c="system(" $d="shell_exec(" $e="passthru(" $f="proc_open(" $g="popen("
  condition: (1 of ($a,$b)) and (1 of ($c,$d,$e,$f,$g)) }
rule Webshell_China_Chopper { meta: description="China Chopper webshell" severity="high" ref="public"
  strings: $a="eval(Request.Item[" nocase $b="@eval($_POST[" condition: any of them }
rule Webshell_ASPX { meta: description="Webshell ASP/ASPX" severity="high"
  strings: $a="<%@ Page" nocase $b="Server.CreateObject" $c="WScript.Shell" $d="cmd.exe" nocase $e="Process.Start"
  condition: $a and (1 of ($b,$c,$d,$e)) }
rule Webshell_JSP { meta: description="Webshell JSP" severity="high"
  strings: $a="Runtime.getRuntime().exec" $b="getParameter" $c="ProcessBuilder"
  condition: $b and ($a or $c) }

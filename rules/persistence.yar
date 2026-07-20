/* Mecanismos de persistencia */
rule Persist_Run_Keys { meta: description="Persistencia por claves Run" severity="medium"
  strings: $k1="\\CurrentVersion\\Run" nocase wide ascii $k2="\\CurrentVersion\\RunOnce" nocase wide ascii $api="RegSetValueEx"
  condition: 1 of ($k*) and $api }
rule Persist_Service { meta: description="Persistencia por servicio" severity="medium"
  strings: $a="CreateServiceA" $b="CreateServiceW" $c="OpenSCManager" $d="\\CurrentControlSet\\Services"
  condition: (($a or $b) and $c) or $d }
rule Persist_Scheduled_Task { meta: description="Persistencia por tarea programada" severity="medium"
  strings: $a="schtasks /create" nocase $b="ITaskService" $c="\\Microsoft\\Windows\\" $d="Register-ScheduledTask" nocase condition: any of them }
rule Persist_WMI_Subscription { meta: description="Persistencia por suscripcion WMI" severity="high"
  strings: $a="__EventFilter" $b="CommandLineEventConsumer" $c="__FilterToConsumerBinding" $d="root\\subscription" nocase condition: 2 of them }
rule Persist_Startup_Folder { meta: description="Persistencia por carpeta de inicio" severity="low"
  strings: $a="\\Start Menu\\Programs\\Startup" nocase wide ascii condition: any of them }
rule Persist_Winlogon { meta: description="Persistencia por Winlogon (Userinit/Shell)" severity="high"
  strings: $a="\\Winlogon" nocase $b="Userinit" nocase $c="\\Shell" condition: 2 of them }
rule Persist_AppInit_IFEO { meta: description="Persistencia AppInit_DLLs / IFEO" severity="high"
  strings: $a="AppInit_DLLs" nocase $b="Image File Execution Options" nocase $c="Debugger" condition: any of them }

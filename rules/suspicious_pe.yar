import "pe"
/* Rasgos de PE sospechosos (modulo pe de YARA) */
rule PE_Section_RWX { meta: description="Seccion con escritura + ejecucion (RWX)" severity="high"
  condition: pe.is_pe and for any s in pe.sections : ( (s.characteristics & pe.SECTION_MEM_WRITE) and (s.characteristics & pe.SECTION_MEM_EXECUTE) ) }
rule PE_Few_Imports { meta: description="Tabla de imports minima (indicio de packer)" severity="medium"
  condition: pe.is_pe and pe.number_of_imported_functions < 6 }
rule PE_DynamicResolve_LowImports { meta: description="Resolucion dinamica: LoadLibrary + pocos imports" severity="medium"
  condition: pe.is_pe and pe.imports("kernel32.dll","LoadLibraryA") and pe.number_of_imported_functions < 15 }
rule PE_Injection_Imports { meta: description="Combinacion de imports de inyeccion" severity="high"
  condition: pe.is_pe and pe.imports("kernel32.dll","VirtualAllocEx") and pe.imports("kernel32.dll","WriteProcessMemory") and pe.imports("kernel32.dll","CreateRemoteThread") }
rule PE_Overlay_Present { meta: description="Overlay tras la ultima seccion (datos anexos)" severity="low"
  condition: pe.is_pe and pe.overlay.size > 0 }
rule PE_Fake_Microsoft { meta: description="Se hace pasar por Microsoft sin firma" severity="medium"
  strings: $ms="Microsoft Corporation" wide ascii
  condition: pe.is_pe and $ms and pe.number_of_signatures == 0 }

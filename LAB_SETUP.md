# 🧪 Cómo montar un laboratorio aislado de análisis de malware

Guía paso a paso para crear un entorno (sandbox) donde detonar y analizar malware
**sin riesgo de contagio**. Es el mismo enfoque que enseña SANS FOR610 y el que usa
un analista de malware profesional. Complementa al pipeline `malpipe`: el análisis
estático es seguro y no necesita lab; el **dinámico** (ejecutar la muestra) va
siempre aquí dentro.

> ⚠️ Trata TODA muestra como peligrosa. Un fallo de aislamiento puede cifrar tus
> datos, propagarse por tu red o exfiltrar información. Sigue todos los pasos.

---

## Fase 0 — Los 4 principios de aislamiento

1. **Red aislada**: la VM de detonación nunca toca Internet real ni tu red. Se
   simula Internet para que el malware revele su comportamiento sin salir fuera.
2. **Snapshots**: partes siempre de un estado limpio y reviertes tras cada muestra.
3. **Sin datos reales**: nada de credenciales, documentos ni acceso a recursos
   corporativos dentro del lab.
4. **Transferencia con cuidado**: la muestra viaja cifrada (ZIP con contraseña
   `infected`), sin extensión ejecutable hasta el momento de detonar.

---

## Fase 1 — El host (equipo anfitrión)

- Usa un **equipo dedicado** o, como mínimo, un usuario/disco separado que no
  contenga datos importantes ni acceso a la red de trabajo.
- Instala un **hipervisor**: VirtualBox (gratis) o VMware Workstation/Fusion.
  > No uses contenedores (Docker) para malware Windows real: el kernel es
  > compartido con el host. Necesitas VMs completas.
- En la configuración de las VMs, **deshabilita**: carpetas compartidas,
  portapapeles compartido y arrastrar-y-soltar entre host y VM (son vías de fuga).
- Mantén el hipervisor y el host actualizados (los escapes de VM existen).

---

## Fase 2 — La red aislada (la parte crítica)

El objetivo: que el malware "crea" que tiene Internet, pero todo su tráfico se
quede dentro del lab y quede registrado.

**Opción A — Simple (una sola VM):**
- Crea una red **host-only** o **internal network** en el hipervisor (sin NAT ni
  bridge → sin salida real).
- La VM Windows no tendrá Internet. Verás intentos de conexión pero no respuestas.

**Opción B — Recomendada (dos VMs, Internet simulada):**
- Dos VMs en la **misma red interna aislada**:
  - VM **Windows** (víctima / análisis).
  - VM **REMnux** (Linux) actuando de gateway falso.
- En la REMnux corres **INetSim** (o usas **FakeNet-NG** dentro de la propia VM
  Windows). Simula DNS, HTTP, HTTPS, FTP, SMTP, IRC… y responde a todo.
- Configura la VM Windows para usar la IP de la REMnux como **gateway y DNS**.
- Resultado: el malware resuelve su dominio C2, "descarga" su payload y "reporta"
  a su servidor — pero todo lo sirve INetSim y lo capturas con Wireshark. Ves su
  comportamiento de red sin que nada salga a Internet.

> Comprobación: desde la VM Windows, `ping` y navegar a cualquier dominio debe
> responder (lo simula INetSim), pero un `tracert` no debe salir de la red interna.

---

## Fase 3 — La VM de análisis (Windows)

- Instala **Windows 10/11** en una VM. Dale 2-4 vCPU y 4-8 GB de RAM.
- Instala **FLARE-VM** (Mandiant): un script que instala de golpe decenas de
  herramientas de análisis. Incluye:
  - **Estático**: PEStudio, Detect It Easy (DIE), PE-bear, CFF Explorer, capa,
    FLOSS (extracción de strings ofuscadas), YARA.
  - **Dinámico**: Procmon, Process Hacker / Process Explorer, Regshot, Autoruns,
    API Monitor, Noriben.
  - **Red**: Wireshark, Fiddler.
  - **Debugging / reversing**: x64dbg, Ghidra, IDA Free.
- Configura el Windows:
  - Muestra extensiones de archivo y ficheros ocultos.
  - **Deshabilita Windows Defender** y SmartScreen (si no, borran la muestra).
  - Deshabilita actualizaciones automáticas y telemetría.
  - Deja Sysmon instalado con una buena config (p. ej. la de SwiftOnSecurity) para
    ver la telemetría como en un SOC real.

---

## Fase 4 — La VM REMnux (Linux)

- **REMnux** es una distro Linux con todo listo para análisis de malware.
- Úsala para: correr INetSim, capturar tráfico, analizar documentos maliciosos
  (oletools, olevba), analizar PDFs (peepdf), y correr tu **malpipe** y YARA
  sobre las muestras.
- Es también donde guardas el repositorio de muestras y las herramientas.

---

## Fase 5 — Snapshots (el botón de deshacer)

1. Con las dos VMs instaladas, configuradas y **limpias** (antes de tocar ninguna
   muestra), apágalas y toma un **snapshot** llamado `clean`.
2. Tras analizar cada muestra, **revierte** al snapshot `clean`. Nunca reutilices
   una VM que ya ha ejecutado malware para otra muestra.

---

## Fase 6 — Transferir la muestra con seguridad

1. Descarga la muestra en el host dentro de un **ZIP con contraseña `infected`**
   (es el estándar del sector; evita que el AV del host la borre y que se ejecute
   por accidente).
2. Pásala a la VM por un **ISO de solo lectura**, un disco secundario, o una
   carpeta compartida que **desactivas justo después**.
3. Dentro de la VM, extráela y **renómbrala sin extensión ejecutable**
   (`muestra.exe` → `muestra.mal`) hasta el momento de detonarla.
4. Nunca hagas doble clic por inercia.

---

## Fase 7 — El flujo de análisis

**1) Estático primero (decide si merece detonar):**
   - `python analyze.py muestra.mal` → hashes, imports, capacidades ATT&CK, YARA,
     entropía, IOCs. Complementa con DIE (¿empaquetado?) y FLOSS (strings ocultas).
   - Si está empaquetado, quizá necesites desempaquetarlo (dinámico o manual).

**2) Prepara los monitores (antes de ejecutar):**
   - **Regshot**: toma la 1ª foto del sistema (registro + ficheros).
   - **Procmon**: con filtros para reducir ruido (por nombre de proceso).
   - **Wireshark**: captura en la interfaz (o en la REMnux).
   - **Process Hacker**: para ver procesos hijos, inyecciones y conexiones.

**3) Detona** en la VM Windows y observa 1-3 minutos:
   - Procesos creados, inyecciones, conexiones (contra INetSim), persistencia.

**4) Captura el resultado:**
   - **Regshot**: 2ª foto → **diff** (qué claves/ficheros cambiaron).
   - Guarda el **pcap**, el log de Procmon y, si hace falta, un **volcado de
     memoria** para analizarlo con **Volatility**.

**5) Extrae IOCs y comportamiento → informe.** Mapea a MITRE ATT&CK. Aquí encaja
   automatizar con `malpipe --dynamic` (Fase 8).

**6) Revierte el snapshot.**

---

## Fase 8 — Automatizar con CAPEv2

Para no hacer todo a mano en cada muestra, monta un **sandbox automatizado**:

- **CAPEv2** (open-source): un "host" Linux orquesta uno o varios "guests" Windows
  con un agente. Detona la muestra, captura comportamiento, hace **unpacking**
  automático y extrae la **configuración** de familias conocidas, y genera un
  informe JSON completo.
- `malpipe` se conecta a su API:
  ```bash
  export MALPIPE_SANDBOX=cape CAPE_URL=http://tu-cape:8000 CAPE_TOKEN=...
  python analyze.py muestra.mal --dynamic
  ```
- Requisitos: bastante RAM/CPU, virtualización anidada (KVM/VirtualBox), y
  paciencia con la instalación. Alternativa cloud sin montar nada: la API de
  **tria.ge** (`MALPIPE_SANDBOX=triage`).

---

## Fase 9 — Dónde conseguir muestras (para practicar)

Con TODAS las precauciones anteriores:

- **MalwareBazaar** (abuse.ch), **MalShare**, **VirusShare**, **theZoo**,
  **vx-underground**.
- Empieza por **EICAR** (fichero de prueba benigno) y muestras "de laboratorio"
  antes de tocar nada real.

---

## Checklist rápido antes de detonar

- [ ] VMs en red **aislada** (host-only / internal), sin bridge ni NAT.
- [ ] INetSim/FakeNet **activo** simulando Internet.
- [ ] Carpetas compartidas y portapapeles **deshabilitados**.
- [ ] Snapshot `clean` **tomado**.
- [ ] Defender/SmartScreen **desactivados** en la VM de análisis.
- [ ] Monitores (Procmon, Wireshark, Regshot, Process Hacker) **preparados**.
- [ ] Muestra **renombrada** y lista, sin doble clic accidental.
- [ ] Análisis **estático hecho** (¿merece la pena detonar?).

Cuando termines: extrae IOCs, escribe el informe, **revierte el snapshot**.

# 🧪 malpipe — Pipeline de análisis de malware (estático + dinámico)

Analiza una muestra de forma automatizada y genera un informe con veredicto,
capacidades mapeadas a **MITRE ATT&CK**, IOCs y coincidencias YARA. La parte
estática funciona sin ejecutar el fichero; la dinámica coordina la detonación en
un **sandbox aislado** y normaliza su informe de comportamiento.

> ⚠️ **Uso exclusivamente defensivo.** Trata toda muestra como peligrosa. El
> análisis estático es seguro (no ejecuta nada). El dinámico **solo** en una VM
> aislada, con red simulada y snapshots — nunca en tu equipo.

## Qué hace

**Estático (sin ejecutar):**
- Identidad: tipo, tamaño, entropía, hashes MD5/SHA1/SHA256, **imphash** y **hash difuso ssdeep** (agrupa variantes de una familia).
- PE (pefile): cabeceras, secciones con entropía y permisos, imports/exports, recursos, firma, TLS, y **anomalías** (secciones RWX, entropía alta, pocos imports = packer).
- ELF (LIEF) de forma best-effort.
- **Capacidades → MITRE ATT&CK**: traduce imports y cadenas a capacidades (inyección, persistencia, keylogging, anti-debug, anti-VM, descarga, cifrado/ransomware, robo de credenciales…), cada una con su técnica y evidencia — el enfoque de la herramienta `capa`.
- **YARA**: escaneo con reglas propias (ampliables).
- **IOCs**: URLs, IPs, dominios, hashes, claves de registro, rutas, correos.
- **Puntuación 0-100** con veredicto (benigno / sospechoso / probable / malicioso).

**Dinámico (en sandbox aislado):**
- Conector para **CAPEv2** (self-hosted) o **tria.ge** (API cloud): envía la muestra, espera el informe y normaliza procesos, red, comportamientos ATT&CK y firmas.

## Instalación

```bash
git clone https://github.com/BlueShield-Ch4rl13/malpipe
cd malpipe
pip install -r requirements.txt   # necesita libmagic (python-magic)
```

## Uso

```bash
# Análisis estático (seguro)
python analyze.py muestra.bin
python analyze.py muestra.bin --output ./caso --rules ./rules

# Con análisis dinámico (requiere sandbox configurado por variables de entorno)
export MALPIPE_SANDBOX=cape CAPE_URL=http://tu-cape:8000 CAPE_TOKEN=...
python analyze.py muestra.bin --dynamic
```

Genera `report.html` (informe navegable autocontenido) y `report.json`.

## Montar el sandbox dinámico (isolation-first)

1. VM Windows dedicada en **red aislada** (host-only) con **INetSim/FakeNet** simulando Internet.
2. **Snapshot** limpio: se revierte tras cada muestra.
3. Sin credenciales ni datos reales; portapapeles y carpetas compartidas **deshabilitados**.
4. Instala [CAPEv2](https://github.com/kevoreilly/CAPEv2) o usa la API de [tria.ge](https://tria.ge).
5. Las muestras se transportan en ZIP con contraseña `infected`.

## Estructura

```
malpipe/
├── analyze.py            # CLI y orquestación
├── malpipe/
│   ├── static.py         # identidad, hashes, entropía, PE/ELF, anomalías
│   ├── capabilities.py   # imports/cadenas → capacidades + MITRE ATT&CK
│   ├── indicators.py     # cadenas, IOCs y YARA
│   ├── score.py          # puntuación y veredicto
│   ├── sandbox.py        # conector dinámico (CAPE / tria.ge)
│   └── report.py         # informe HTML + JSON
├── rules/malware.yar     # reglas YARA de arranque
└── requirements.txt
```

## Limitaciones y siguiente paso

- El parseo profundo de PE es el foco; ELF/Mach-O es básico.
- El veredicto estático es una **priorización**, no un antivirus: sirve para decidir qué muestra merece detonación o reversing.
- La detección de capacidades es heurística (imports/cadenas); un packer fuerte las oculta hasta descomprimir en memoria — ahí entra el análisis dinámico.
- Roadmap: unpacking automático, extracción de configuración de familias conocidas, y subir el informe al dashboard DFIR para correlacionar con casos.

## Licencia

MIT. Uso exclusivamente para investigación defensiva y respuesta a incidentes.

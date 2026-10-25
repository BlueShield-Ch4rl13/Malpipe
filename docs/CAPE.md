# Detonar en tu propio CAPEv2

Con tria.ge la muestra sale de tu red y, en una cuenta gratuita, el análisis es
público. Con [CAPEv2](https://github.com/kevoreilly/CAPEv2) la muestra se
detona en una máquina tuya, aislada, y además CAPE extrae la configuración de
muchas familias desde el volcado de memoria, que es justo lo que el análisis
estático no ve cuando la muestra está empaquetada. malpipe la recoge y la cruza
con News CTI como cualquier otra.

Esta guía es para el servidor del laboratorio (Proxmox con VLAN y pfSense, como
en Infra-SocAnalyst). El conector de malpipe está probado con respuestas
simuladas que siguen la API v2 de CAPE (`tests/test_cape.py`); contra una
instancia real se comprueba con el apartado 5.

## 1. Dónde va

```
VLAN 50 Sandbox (sin ruta a ninguna otra VLAN)
  CAPE 10.0.50.10:8000  ── KVM ──►  Windows 10 (192.168.122.105, red interna de libvirt)

VLAN 30 SOC: el equipo que ejecuta malpipe  ──►  10.0.50.10:8000 (API de CAPE)
```

| Recurso | CAPE (con un invitado Windows 10) |
|---|---|
| vCPU | 4, tipo `host` (hace falta virtualización anidada) |
| RAM | 12–16 GB (4 GB para el invitado) |
| Disco | 150 GB |
| Sistema | Ubuntu Server 24.04 LTS, el que usan los scripts de instalación de CAPE |

Virtualización anidada en el host de Proxmox:

```bash
cat /sys/module/kvm_intel/parameters/nested      # Y = activada (AMD: kvm_amd)
echo "options kvm-intel nested=Y" > /etc/modprobe.d/kvm-intel.conf   # si sale N, y reiniciar
qm set <id-vm-cape> --cpu host
```

## 2. Instalar CAPE

Con los scripts oficiales de `installer/` del repositorio de CAPEv2 (lee antes
su [documentación](https://capev2.readthedocs.io/en/latest/installation/host/index.html):
cambian a menudo):

```bash
git clone https://github.com/kevoreilly/CAPEv2 && cd CAPEv2/installer
sudo ./kvm-qemu.sh all <tu-usuario> | tee kvm-qemu.log     # QEMU y SeaBIOS con anti-detección, libvirt
# edita NETWORK_IFACE, IFACE_IP y PASSWD al principio de cape2.sh
sudo ./cape2.sh base 10.0.50.10 | tee cape2.log            # CAPE, dependencias y servicios
```

## 3. El invitado Windows

1. Windows 10 x64 en libvirt, en la red interna `192.168.122.0/24` con IP fija
   `192.168.122.105`.
2. Defender, actualizaciones y cortafuegos desactivados (`installer/win10_disabler.ps1`).
3. Python 3 de 32 bits y `agent/agent.py` del repositorio, arrancando al inicio.
4. Con el agente en marcha, una instantánea en caliente (`clean`).
5. En `conf/kvm.conf` de CAPE: la máquina (`label`, `platform = windows`,
   `ip = 192.168.122.105`, `snapshot = clean`).

## 4. Red y acceso

- **Salida del invitado.** En `conf/routing.conf`, `route = none` por defecto:
  la muestra no habla con nadie. Para ver su tráfico de mando y control sin
  dejarle salir, InetSim; para dejarla salir de verdad, una VPN o Tor, nunca la
  línea de casa.
- **pfSense.** La VLAN 50 no tiene ruta a ninguna otra. Solo una regla de
  entrada: del equipo que ejecuta malpipe a `10.0.50.10:8000/tcp`.
- **API con token.** En `conf/api.conf`, `token_auth_enabled = yes`. Crea un
  usuario en la web de CAPE y saca su token:

  ```bash
  curl -d "username=<usuario>&password=<clave>" http://10.0.50.10:8000/apiv2/api-token-auth/
  ```

## 5. Conectar malpipe

En el `.env` del equipo que ejecuta malpipe:

```ini
CAPE_URL=http://10.0.50.10:8000
CAPE_TOKEN=                        # el token del apartado 4
CAPE_OPCIONES=route=none
MALPIPE_DYNAMIC_TIMEOUT=900       # una detonación con procesado tarda varios minutos
```

Comprueba que llega y que el token vale:

```bash
curl -H "Authorization: Token $CAPE_TOKEN" $CAPE_URL/apiv2/cuckoo/status/
```

Y analiza:

```bash
python -m malpipe muestra.exe --cti --stix --misp
```

El informe dirá `dinámico: CAPEv2 — ok`, con la puntuación de CAPE (malscore),
la familia, las firmas con sus técnicas ATT&CK, la red que vio y las
configuraciones que extrajo (como `extractor: cape`). Si hay CAPE y también clave
de tria.ge, manda CAPE; `MALPIPE_SANDBOX=triage` fuerza tria.ge.

## Lo que se queda fuera

- El portal del navegador (box.carlosvillalbalagos.com) no detona: no tiene
  servidor ni debe tener la llave de tu CAPE. El portal con servidor
  (`webapp/`) sí puede usar CAPE con `MALPIPE_WEB_DYNAMIC=1`, solo dentro de tu
  red.
- Con una muestra que detecta máquinas virtuales, CAPE puede no ver nada. El
  `kvm-qemu.sh` de CAPE quita muchas huellas de QEMU, no todas.

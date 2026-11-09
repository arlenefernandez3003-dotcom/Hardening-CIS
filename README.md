# Hardening CIS de Router y Switch Cisco: Auditoría y Remediación Automatizada

### Arlene Fernández Herrera · Matrícula: 2025-0730

**Seguridad de Redes · ITLA**

---

## 🎥 Video Demostrativo

**[▶ Ver video de demostración](https://youtu.be/TODO_ENLACE_DEL_VIDEO)**

---

> 📚 **Nota:** las contraseñas, secretos y comunidades SNMP de este laboratorio son de práctica. La configuración inicial es **intencionalmente insegura** para poder demostrar el antes y el después del hardening.

---

## 📋 Tabla de Contenido

1. [Propósito del Laboratorio](#1-propósito-del-laboratorio)
2. [Topología y Direccionamiento](#2-topología-y-direccionamiento)
3. [Recomendaciones CIS aplicadas y por qué](#3-recomendaciones-cis-aplicadas-y-por-qué)
4. [Procedimiento paso a paso](#4-procedimiento-paso-a-paso)
   - [Paso 1. PNETLab y equipo auditor](#paso-1-pnetlab-y-equipo-auditor)
   - [Paso 2. Switch SW-CIS: configuración inicial (insegura)](#paso-2-switch-sw-cis-configuración-inicial-insegura)
   - [Paso 3. Router R-CIS: configuración inicial (insegura)](#paso-3-router-r-cis-configuración-inicial-insegura)
   - [Paso 4. Equipo auditor (Admin-PC)](#paso-4-equipo-auditor-admin-pc)
   - [Paso 5. Verificar la conectividad](#paso-5-verificar-la-conectividad)
   - [Paso 6. Análisis CIS inicial con herramienta externa](#paso-6-análisis-cis-inicial-con-herramienta-externa)
   - [Paso 7. Script de hardening: informe sin aplicar cambios](#paso-7-script-de-hardening-informe-sin-aplicar-cambios)
   - [Paso 8. Script de hardening: aplicar reglas e informe póstumo](#paso-8-script-de-hardening-aplicar-reglas-e-informe-póstumo)
   - [Paso 9. Análisis CIS final con herramienta externa](#paso-9-análisis-cis-final-con-herramienta-externa)
   - [Paso 10. Pruebas de las recomendaciones aplicadas](#paso-10-pruebas-de-las-recomendaciones-aplicadas)
   - [Paso 11. Exportar las configuraciones](#paso-11-exportar-las-configuraciones)
5. [El script `cis_hardening.py`](#5-el-script-cis_hardeningpy)
6. [Matriz de cumplimiento de requisitos](#6-matriz-de-cumplimiento-de-requisitos)
7. [Capturas de Pantalla](#7-capturas-de-pantalla)
8. [Estructura del Repositorio](#8-estructura-del-repositorio)

---

## 1. Propósito del Laboratorio

Esta práctica toma una red pequeña con un **Router** y un **Switch** Cisco (IOS en PNETLab), la deja con una configuración **insegura de fábrica**, la **analiza contra el CIS Benchmark de Cisco IOS** y le aplica **hardening** de forma automatizada.

* Se mide el nivel de cumplimiento **antes** y **después** del hardening con una herramienta de análisis CIS y con un script propio.
* Se aplican recomendaciones de los tres planos del benchmark: **Management Plane**, **Control Plane** y **Data Plane**, más controles complementarios de capa 2 en el switch.
* Un **script en Python** escanea los equipos y puede trabajar en dos modos:
  * **`--audit`:** genera un informe **sin aplicar ninguna regla**.
  * **`--apply`:** aplica las reglas que fallan y genera un **informe póstumo** (antes y después).
* Cada recomendación aplicada se **documenta, se justifica y se prueba**.

El objetivo de seguridad es demostrar que la red pasa de una configuración con Telnet, HTTP, SNMP `public` y contraseñas débiles a una con acceso solo por SSH v2 desde el equipo de gestión, registros centralizados y servicios innecesarios apagados, y que ese cambio es medible y repetible.

---

## 2. Topología y Direccionamiento

> Las redes internas son **privadas** y salen todas de `10.7.30.0/24` (matrícula 0730), repartidas con **VLSM**. No se usa la primera IP utilizable de ninguna red: el gateway usa la **segunda**.

### 2.1 Diagrama de Topología

```
                     ┌─────────────────────────┐
                     │         R-CIS           │
                     │         Router          │
                     │  Et0/0  (trunk 802.1Q)  │
                     │  ├ Et0/0.99 10.7.30.2/27│  Gestión
                     │  └ Et0/0.10 10.7.30.34/27│ Usuarios
                     └────────────┬────────────┘
                                  │ trunk · VLAN 10, 99
                     ┌────────────┴────────────┐
                     │         SW-CIS          │
                     │         Switch          │
                     │  Vlan99  10.7.30.3/27   │
                     └──────┬───────────┬──────┘
                          e0/1         e0/2
                       (VLAN 99)     (VLAN 10)
                            │            │
                  ┌─────────┴──────┐ ┌───┴─────────────┐
                  │   Admin-PC     │ │   PC-Usuario    │
                  │ 10.7.30.4/27   │ │  DHCP (.40-.62) │
                  │ Auditor, syslog│ │  Sin acceso a   │
                  │ y script CIS   │ │  la gestión     │
                  └────────────────┘ └─────────────────┘

  Flujo del script:
  Admin-PC ──SSH (TCP 22)──► R-CIS / SW-CIS ──► informe (Markdown + JSON) en reports/
  R-CIS / SW-CIS ──syslog (UDP 514)──► Admin-PC

  Política de gestión (después del hardening):
  ┌───────────────────────────────────────────────────────────────────┐
  │ Admin-PC (10.7.30.4)  → R-CIS / SW-CIS : SSH v2 permitido         │
  │ PC-Usuario            → R-CIS / SW-CIS : SSH/Telnet denegados     │
  │ Telnet, HTTP, SNMP v1/v2c (public/private) : deshabilitados       │
  └───────────────────────────────────────────────────────────────────┘
```

### 2.2 Redes y VLSM sobre `10.7.30.0/24`

| Bloque | Requisito | Red | VLAN | Hosts utilizables | Gateway | Broadcast |
|---|---|---|---|---|---|---|
| Gestión | `/27` | 10.7.30.0/27 | 99 | .1 – .30 (se usan .2, .3 y .4) | 10.7.30.2 (R-CIS) | .31 |
| Usuarios | `/27` | 10.7.30.32/27 | 10 | .33 – .62 | 10.7.30.34 (R-CIS) | .63 |
| Libre | — | 10.7.30.64 – .255 | — | — | — | — |

### 2.3 Tabla de Dispositivos

| Dispositivo | Sistema | Interfaz | IP | Máscara | Gateway | Método | Rol |
|---|---|---|---|---|---|---|---|
| **R-CIS** | Cisco IOS 15.x (IOL) | Et0/0.99 | 10.7.30.2 | /27 | — | Estática | Gateway de gestión |
| **R-CIS** | Cisco IOS 15.x (IOL) | Et0/0.10 | 10.7.30.34 | /27 | — | Estática | Gateway de usuarios y DHCP |
| **SW-CIS** | Cisco IOS 15.x (IOL L2) | Vlan99 | 10.7.30.3 | /27 | 10.7.30.2 | Estática | Switch de acceso |
| **Admin-PC** | Ubuntu | ens3 | 10.7.30.4 | /27 | 10.7.30.2 | Estática | Auditor, servidor syslog |
| **PC-Usuario** | Ubuntu | ens3 | 10.7.30.40 – .62 (rango) | /27 | 10.7.30.34 | **DHCP** | Usuario sin acceso a la gestión |

### 2.4 Tabla de puertos del Switch

| Interfaz | Modo | VLAN | Conectado a |
|---|---|---|---|
| **e0/0** | Trunk (802.1Q) | 10, 99 (nativa 999 tras el hardening) | R-CIS `Et0/0` |
| **e0/1** | Access | 99 | Admin-PC |
| **e0/2** | Access | 10 | PC-Usuario |
| **e0/3, e1/0 – e1/3** | Sin uso | 999 | Sin cable (se apagan con el hardening) |

---

## 3. Recomendaciones CIS aplicadas y por qué

La referencia es el **CIS Cisco IOS 15 Benchmark**. Los controles se organizan en los planos que usa el benchmark. La columna **ID** es la numeración propia del laboratorio (la usa el script); el número de sección exacto depende de la versión del PDF del benchmark que se use.

> Los controles **L-xx** (capa 2) son **complementarios**: refuerzan el switch con prácticas de hardening de Cisco y no se presentan como numerales del benchmark.

### 3.1 Management Plane

| ID | Recomendación | Comando clave | Por qué se aplicó | Equipo |
|---|---|---|---|---|
| M-01 | Habilitar AAA | `aaa new-model`, `aaa authentication login default local` | Es la base de la autenticación y autorización centralizables; sin AAA no hay control de sesiones por método. | R, S |
| M-02 | Usuarios locales con `secret` (sin contraseña en claro) | `username admin-local privilege 15 secret ...` | Un `password` se guarda en claro o con cifrado reversible; `secret` usa hash. | R, S |
| M-03 | `enable secret` robusto, sin `enable password` | `enable algorithm-type scrypt secret ...` | El hash scrypt resiste la fuerza bruta mucho mejor que MD5 (tipo 5) y el tipo 7 es reversible. | R, S |
| M-04 | Cifrar contraseñas en la configuración | `service password-encryption` | Evita que contraseñas residuales se lean a simple vista en `show running-config`. | R, S |
| M-05 | Banners de advertencia | `banner login`, `banner exec` | Deja constancia legal de que el acceso es restringido y monitoreado. | R, S |
| M-06 | SSH versión 2 | `ip ssh version 2` | SSH v1 tiene fallos criptográficos conocidos. | R, S |
| M-07 | Tiempo de espera e intentos de SSH | `ip ssh time-out 60`, `ip ssh authentication-retries 3` | Limita los intentos de adivinar credenciales y las sesiones colgadas. | R, S |
| M-08 | Clave RSA de al menos 2048 bits | `crypto key generate rsa modulus 2048` | Una clave de 1024 bits ya no se considera segura. | R, S |
| M-09 | ACL para restringir quién administra el equipo | `ip access-list standard MGMT-ONLY` | Solo el equipo de gestión puede intentar entrar. | R, S |
| M-10 | Hardening de las líneas VTY | `transport input ssh`, `exec-timeout 5 0`, `access-class MGMT-ONLY in` | Elimina Telnet, cierra sesiones inactivas y aplica la ACL de gestión. | R, S |
| M-11 | Tiempo de inactividad en consola | `exec-timeout 5 0`, `logging synchronous` | Una consola abierta sin límite es una sesión privilegiada olvidada. | R, S |
| M-12 | Puerto auxiliar sin acceso | `no exec` | El auxiliar es una vía de entrada que no se usa. | R, S |
| M-13 | Apagar el servidor HTTP/HTTPS | `no ip http server`, `no ip http secure-server` | Reduce la superficie de ataque; la administración es solo por SSH. | R, S |
| M-14 | Eliminar comunidades SNMP v1/v2c | `no snmp-server community ...` | `public` y `private` son valores conocidos y se transmiten en claro. | R, S |
| M-15 | Registro de eventos con marca de tiempo y syslog | `service timestamps log datetime ...`, `logging buffered`, `logging host` | Sin registros no hay evidencia ni detección; la marca de tiempo permite correlacionar eventos. | R, S |

### 3.2 Control Plane

| ID | Recomendación | Comando clave | Por qué se aplicó | Equipo |
|---|---|---|---|---|
| C-01 | Apagar servicios innecesarios | `no service pad`, `no ip source-route`, `no ip bootp server`, `no ip domain-lookup` | Cada servicio activo es una vía de ataque o de fuga de información sin utilidad en esta red. | R, S |
| C-02 | Apagar CDP | `no cdp run` | CDP anuncia modelo, versión de IOS e IPs a cualquier vecino que escuche. | R, S |

### 3.3 Data Plane

| ID | Recomendación | Comando clave | Por qué se aplicó | Equipo |
|---|---|---|---|---|
| D-01 | Endurecer las interfaces de capa 3 | `no ip redirects`, `no ip unreachables`, `no ip proxy-arp` | Evita fuga de información de topología, redirecciones maliciosas y que el equipo responda ARP por otros. | R, S |
| D-02 | Unicast RPF en la red de usuarios | `ip verify unicast source reachable-via rx` | Descarta paquetes con IP de origen falsificada que entran por la VLAN de usuarios. | R |

### 3.4 Controles complementarios de capa 2 (switch)

| ID | Recomendación | Comando clave | Por qué se aplicó | Equipo |
|---|---|---|---|---|
| L-01 | Trunk seguro | `switchport nonegotiate`, `switchport trunk native vlan 999` | Evita negociación DTP y ataques de VLAN hopping por VLAN nativa. | S |
| L-02 | Puertos sin uso apagados | `shutdown` en los puertos de la VLAN 999 | Un puerto libre y activo es un punto de conexión no autorizado. | S |
| L-03 | Protección de puertos de acceso | `switchport nonegotiate`, `port-security`, `bpduguard` | Limita las MAC por puerto y bloquea switches no autorizados. | S |
| L-04 | DHCP Snooping | `ip dhcp snooping`, `ip dhcp snooping vlan 10`, `ip dhcp snooping trust` | Impide que un DHCP falso en la VLAN de usuarios entregue direcciones o gateway maliciosos. | S |

---

## 4. Procedimiento paso a paso

Los pasos están en el orden en que se ejecutan. Cada uno depende de los anteriores.

> Los nombres de interfaz (`Ethernet0/0`, …) deben ajustarse a los que muestre `show ip interface brief` en la imagen usada en PNETLab. El adaptador de Linux (`ens3`) se consulta con `ip -br link`.

---

### Paso 1. PNETLab y equipo auditor

**1.1 — Red virtual del Admin-PC**

El Admin-PC es una VM de VMware conectada a una red **Host-only** (por ejemplo `VMnet16`), **sin DHCP de VMware**, enlazada a PNETLab con un nodo **Cloud**. Entra al switch por **un solo cable**.

| VM | Sistema | RAM | vCPU | Red virtual |
|---|---|---|---|---|
| Admin-PC | Ubuntu | 2 GB | 2 | VMnet16 (Host-only, sin DHCP) |
| PC-Usuario | Ubuntu | 1 GB | 1 | VMnet17 (Host-only, sin DHCP) |

**1.2 — En PNETLab**

1. Agregar un nodo **Router** (IOL L3) llamado `R-CIS` y un nodo **Switch** (IOL L2) llamado `SW-CIS`.
2. Agregar dos nodos `Network` de tipo `Cloud`: `Nube-Admin` (VMnet16) y `Nube-Usuario` (VMnet17).
3. Conectar `Et0/0` de `R-CIS` a `e0/0` de `SW-CIS`.
4. Conectar `Nube-Admin` a `e0/1` y `Nube-Usuario` a `e0/2` de `SW-CIS`.

> Ver evidencia: [01_topologia_pnet.png](screenshots/01_topologia_pnet.png)

---

### Paso 2. Switch SW-CIS: configuración inicial (insegura)

Esta configuración deja el switch **funcional pero sin hardening**, para que el análisis encuentre incumplimientos (script: [`scripts/sw-cis-base.txt`](scripts/sw-cis-base.txt)).

```bash
enable
configure terminal

hostname SW-CIS
ip domain-name cis.itla.local
spanning-tree mode rapid-pvst

vlan 10
 name USUARIOS
vlan 99
 name GESTION
vlan 999
 name BLACKHOLE
exit

interface Vlan99
 ip address 10.7.30.3 255.255.255.224
 no shutdown
exit
ip default-gateway 10.7.30.2

interface Ethernet0/0
 description Trunk hacia R-CIS
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk allowed vlan 10,99
 no shutdown
exit

interface Ethernet0/1
 description Admin-PC
 switchport mode access
 switchport access vlan 99
 no shutdown
exit

interface Ethernet0/2
 description PC-Usuario
 switchport mode access
 switchport access vlan 10
 no shutdown
exit

interface range Ethernet0/3 , Ethernet1/0 - 3
 description Sin uso
 switchport mode access
 switchport access vlan 999
exit

! --- Acceso inicial inseguro (a propósito) ---
enable password cisco
username admin-local privilege 15 secret Admin-Local#2026
snmp-server community public RO
snmp-server community private RW
ip http server
crypto key generate rsa modulus 1024
line con 0
 exec-timeout 0 0
 login local
exit
line vty 0 4
 login local
 transport input all
exit

end
write memory
```

> Ver evidencia: [02_switch_base.png](screenshots/02_switch_base.png)

---

### Paso 3. Router R-CIS: configuración inicial (insegura)

Script: [`scripts/r-cis-base.txt`](scripts/r-cis-base.txt).

```bash
enable
configure terminal

hostname R-CIS
ip domain-name cis.itla.local

interface Ethernet0/0
 description Trunk hacia SW-CIS
 no ip address
 no shutdown
exit

interface Ethernet0/0.99
 description Gestion
 encapsulation dot1Q 99
 ip address 10.7.30.2 255.255.255.224
exit

interface Ethernet0/0.10
 description Usuarios
 encapsulation dot1Q 10
 ip address 10.7.30.34 255.255.255.224
exit

ip dhcp excluded-address 10.7.30.33 10.7.30.39
ip dhcp pool USUARIOS
 network 10.7.30.32 255.255.255.224
 default-router 10.7.30.34
 dns-server 8.8.8.8
exit

! --- Acceso inicial inseguro (a propósito) ---
enable password cisco
username admin-local privilege 15 secret Admin-Local#2026
snmp-server community public RO
snmp-server community private RW
ip http server
crypto key generate rsa modulus 1024
line con 0
 exec-timeout 0 0
 login local
exit
line vty 0 4
 login local
 transport input all
exit

end
write memory
```

> Ver evidencia: [03_router_base.png](screenshots/03_router_base.png)

---

### Paso 4. Equipo auditor (Admin-PC)

**4.1 — Red** (`/etc/netplan/50-cloud-init.yaml`, ajustar `ens3`):

```yaml
network:
  version: 2
  ethernets:
    ens3:
      mtu: 1460
      addresses: [10.7.30.4/27]
      routes:
        - to: default
          via: 10.7.30.2
```

```bash
sudo netplan apply
```

**4.2 — Dependencias** (instalar **antes** de conectar la VM a PNETLab, con un adaptador NAT temporal, porque el laboratorio no tiene salida a Internet):

```bash
sudo apt update && sudo apt install -y python3-pip python3-venv nmap snmp
python3 -m venv ~/cis && source ~/cis/bin/activate
pip install netmiko
mkdir -p ~/cis-lab/scripts ~/cis-lab/reports ~/cis-lab/running-configs
```

**4.3 — Servidor syslog (UDP 514)**

```bash
sudo sed -i 's/^#module(load="imudp")/module(load="imudp")/; s/^#input(type="imudp" port="514")/input(type="imudp" port="514")/' /etc/rsyslog.conf
sudo systemctl restart rsyslog
ss -lun | grep 514
```

**4.4 — PC-Usuario:** debe recibir IP por DHCP (`10.7.30.40 – .62`) con gateway `10.7.30.34`.

> Ver evidencia: [04_admin_pc_red.png](screenshots/04_admin_pc_red.png)

---

### Paso 5. Verificar la conectividad

```bash
# Admin-PC
ping -c 3 10.7.30.2
ping -c 3 10.7.30.3
ssh admin-local@10.7.30.2      # debe entrar (aún sin hardening)
telnet 10.7.30.2               # debe entrar: línea base insegura
```

Desde el PC-Usuario: `ip addr` y `ping -c 3 10.7.30.34`.

> Ver evidencia: [05_conectividad.png](screenshots/05_conectividad.png)

---

### Paso 6. Análisis CIS inicial con herramienta externa

Se usa **`TODO_HERRAMIENTA`** para analizar la configuración de `R-CIS` y `SW-CIS` contra el CIS Benchmark de Cisco IOS, **antes** de aplicar ningún cambio.

1. Exportar la configuración de cada equipo (`show running-config`) a `running-configs/pre-*.txt`.
2. Cargar el archivo en la herramienta y ejecutar el perfil de análisis CIS de Cisco IOS.
3. Guardar el informe en `reports/herramienta-antes/` y anotar el porcentaje de cumplimiento inicial.

| Equipo | Controles evaluados | Cumplen | No cumplen | % de cumplimiento (antes) |
|---|---|---|---|---|
| R-CIS | `TODO` | `TODO` | `TODO` | `TODO` |
| SW-CIS | `TODO` | `TODO` | `TODO` | `TODO` |

> Ver evidencia: [06_herramienta_antes.png](screenshots/06_herramienta_antes.png)

---

### Paso 7. Script de hardening: informe sin aplicar cambios

El script [`scripts/cis_hardening.py`](scripts/cis_hardening.py) (sección 5) se conecta por SSH a los dos equipos, lee su configuración y evalúa los 21 controles. En este modo **no modifica nada**.

```bash
cd ~/cis-lab && source ~/cis/bin/activate
python3 scripts/cis_hardening.py --audit
```

Pide la contraseña de `admin-local` y genera, en `reports/<fecha-hora>/`:

| Archivo | Contenido |
|---|---|
| `informe-audit.md` | Tabla por equipo con cada control en `PASS` o `FAIL` y el resumen de cumplimiento. |
| `informe-audit.json` | El mismo resultado en formato máquina. |

Comprobar después que el equipo **no cambió**: `show archive config differences` o comparar `show running-config` antes y después.

> Ver evidencia: [07_script_audit.png](screenshots/07_script_audit.png), [08_informe_audit.png](screenshots/08_informe_audit.png)

---

### Paso 8. Script de hardening: aplicar reglas e informe póstumo

> ⚠️ **Antes de aplicar:** mantener una consola de PNETLab abierta en cada equipo. La regla M-10 limita el acceso por SSH al Admin-PC (`10.7.30.4`) y desde esa consola siempre se puede recuperar el acceso.

```bash
python3 scripts/cis_hardening.py --apply
```

El script, por cada equipo:

1. Evalúa los controles (estado **antes**).
2. Guarda una copia de la configuración en `reports/<fecha-hora>/backups/`.
3. Aplica **solo** los comandos de los controles que fallan.
4. Ejecuta `write memory`.
5. Vuelve a evaluar (estado **después**) y escribe `informe-apply.md` y `informe-apply.json`.

Pide también el nuevo `enable secret` (M-03). Los controles sin remediación automática (por ejemplo, crear el usuario local, M-02) quedan como `MANUAL` en el informe.

> Ver evidencia: [09_script_apply.png](screenshots/09_script_apply.png), [10_informe_apply.png](screenshots/10_informe_apply.png)

---

### Paso 9. Análisis CIS final con herramienta externa

Repetir el Paso 6 con las configuraciones ya endurecidas (`running-configs/post-*.txt`) y comparar.

| Equipo | % de cumplimiento (antes) | % de cumplimiento (después) |
|---|---|---|
| R-CIS | `TODO` | `TODO` |
| SW-CIS | `TODO` | `TODO` |

> Ver evidencia: [11_herramienta_despues.png](screenshots/11_herramienta_despues.png)

---

### Paso 10. Pruebas de las recomendaciones aplicadas

**10.1 — Acceso de administración (M-01, M-06, M-09, M-10)**

Desde el **Admin-PC**:

```bash
ssh admin-local@10.7.30.2              # debe entrar y mostrar el banner
ssh admin-local@10.7.30.3              # debe entrar
nc -zv -w 3 10.7.30.2 23               # Telnet: debe fallar
```

Desde el **PC-Usuario** (`10.7.30.40+`):

```bash
ssh admin-local@10.7.30.2              # debe ser rechazado por la ACL MGMT-ONLY
```

En el router: `show ip ssh` debe indicar `SSH Enabled - version 2.0` y `show access-lists MGMT-ONLY` debe mostrar contadores de coincidencias.

> Ver evidencia: [12_ssh_admin_ok.png](screenshots/12_ssh_admin_ok.png), [13_telnet_ssh_usuario_denegado.png](screenshots/13_telnet_ssh_usuario_denegado.png)

**10.2 — Servicios apagados (M-13, M-14, C-01, C-02)**

Desde el Admin-PC:

```bash
nmap -Pn -p 22,23,80,443 10.7.30.2 10.7.30.3     # solo 22 abierto
snmpwalk -v2c -c public 10.7.30.2                # sin respuesta (timeout)
```

En los equipos:

```bash
show cdp                                         # CDP is not enabled
show running-config | include ^no service pad|^no ip source-route|^no ip bootp
```

> Ver evidencia: [14_nmap_despues.png](screenshots/14_nmap_despues.png), [15_snmp_cdp_apagados.png](screenshots/15_snmp_cdp_apagados.png)

**10.3 — Contraseñas, líneas y banners (M-03, M-04, M-05, M-11, M-12)**

```bash
show running-config | include enable|username     # enable secret 9 …, sin "enable password"
show running-config | section line
```

Cerrar la sesión de consola y volver a entrar: se muestra el banner y a los 5 minutos de inactividad la sesión se cierra.

> Ver evidencia: [16_lineas_banner.png](screenshots/16_lineas_banner.png)

**10.4 — Registros (M-15)**

En el router, generar un evento (`configure terminal` → `end`) y un intento SSH fallido desde el Admin-PC. Verificar:

```bash
show logging                                       # R-CIS: eventos con fecha y hora
sudo tail -n 20 /var/log/syslog | grep -E "R-CIS|SW-CIS"   # Admin-PC: llegan por syslog
```

> Ver evidencia: [17_logs_router.png](screenshots/17_logs_router.png), [18_syslog_admin.png](screenshots/18_syslog_admin.png)

**10.5 — Data plane (D-01, D-02)**

```bash
show running-config interface Ethernet0/0.10      # no ip redirects / unreachables / proxy-arp + uRPF
show ip interface Ethernet0/0.10 | include verify|redirects|unreachables|proxy
```

> Ver evidencia: [19_dataplane_router.png](screenshots/19_dataplane_router.png)

**10.6 — Capa 2 (L-01 a L-04)**

```bash
show interfaces trunk                              # native vlan 999
show interfaces status                             # puertos sin uso en "disabled"
show port-security
show ip dhcp snooping
```

Desde el PC-Usuario, renovar la dirección (`sudo dhclient -r && sudo dhclient`): debe seguir recibiendo IP del router (el puerto del trunk es *trusted*).

> Ver evidencia: [20_switch_l2_hardening.png](screenshots/20_switch_l2_hardening.png)

---

### Paso 11. Exportar las configuraciones

```bash
# En cada equipo
terminal length 0
show running-config
```

Copiar la salida a `running-configs/r-cis-running-config.txt` y `running-configs/sw-cis-running-config.txt`. Las configuraciones iniciales (`pre-*`) y los informes de `reports/` también se suben al repositorio.

> Ver evidencia: [21_running_configs.png](screenshots/21_running_configs.png)

---

## 5. El script `cis_hardening.py`

Guardar como `scripts/cis_hardening.py`. Requiere `netmiko`. Los equipos y las IP de gestión están al inicio del archivo.

| Opción | Efecto |
|---|---|
| `--audit` | Solo informe. No envía ningún comando de configuración. |
| `--apply` | Aplica la remediación de los controles que fallan, guarda y genera el informe póstumo. |
| `--user` | Usuario SSH (por defecto `admin-local`). |
| `--devices` | Limita la ejecución a equipos por nombre (por ejemplo `--devices R-CIS`). |

```python
#!/usr/bin/env python3
"""cis_hardening.py - Auditoría y hardening CIS (Cisco IOS) de R-CIS y SW-CIS.

  python3 cis_hardening.py --audit    # solo informe, no cambia nada
  python3 cis_hardening.py --apply    # aplica reglas y genera informe póstumo
"""
import argparse
import getpass
import json
import re
from datetime import datetime
from pathlib import Path

from netmiko import ConnectHandler

DEVICES = [
    {"name": "R-CIS",  "host": "10.7.30.2", "role": "router"},
    {"name": "SW-CIS", "host": "10.7.30.3", "role": "switch"},
]
MGMT_HOST = "10.7.30.4"          # Admin-PC: único origen de administración
SYSLOG = MGMT_HOST
USER_IF = "Ethernet0/0.10"       # subinterfaz de usuarios (uRPF)
DOMAIN = "cis.itla.local"
BANNER = "ACCESO RESTRINGIDO. Solo personal autorizado. Toda actividad es registrada."

_enable_secret = None


def get_enable_secret():
    global _enable_secret
    if _enable_secret is None:
        _enable_secret = getpass.getpass("Nuevo enable secret (se guardará con scrypt): ")
    return _enable_secret


# ---------- utilidades de lectura de la configuración ----------
def has(ctx, pattern):
    return re.search(pattern, ctx["cfg"], re.M) is not None


def blocks(cfg, header):
    """Lista de bloques (líneas hijas) cuyo encabezado coincide con 'header'."""
    out, cur = [], None
    for line in cfg.splitlines():
        if re.match(header, line):
            cur = []
            out.append(cur)
        elif cur is not None and line.startswith(" "):
            cur.append(line.strip())
        else:
            cur = None
    return out


def ifaces(cfg):
    d, name = {}, None
    for line in cfg.splitlines():
        m = re.match(r"^interface (\S+)", line)
        if m:
            name = m.group(1)
            d[name] = []
        elif name and line.startswith(" "):
            d[name].append(line.strip())
        else:
            name = None
    return d


def l3_ifaces(cfg):
    return {n: l for n, l in ifaces(cfg).items()
            if any(re.match(r"ip address \d", x) for x in l) and not n.startswith("Loopback")}


def timeout_ok(lines):
    m = re.search(r"exec-timeout (\d+)(?: (\d+))?", " ".join(lines))
    if not m:
        return False
    total = int(m.group(1)) * 60 + int(m.group(2) or 0)
    return 0 < total <= 300


# ---------- registro de controles ----------
CHECKS = []


def check(cid, title, plane, roles=("router", "switch")):
    def deco(fn):
        CHECKS.append({"id": cid, "title": title, "plane": plane, "roles": roles, "fn": fn})
        return fn
    return deco


# fn(ctx) -> (ok: bool, detalle: str, remediación: list | callable | None)

@check("M-01", "AAA habilitado (aaa new-model + login por defecto)", "Management")
def _(c):
    ok = has(c, r"^aaa new-model") and has(c, r"^aaa authentication login default")
    return ok, "", ["aaa new-model", "aaa authentication login default local",
                    "aaa authorization exec default local"]


@check("M-02", "Usuario local con secret y sin 'password' en claro", "Management")
def _(c):
    ok = has(c, r"^username \S+( privilege \d+)? secret") and \
        not has(c, r"^username \S+( privilege \d+)? password")
    return ok, "", None  # requiere crear la contraseña: manual


@check("M-03", "enable secret tipo 8/9 y sin enable password", "Management")
def _(c):
    ok = has(c, r"^enable secret (8|9) ") and not has(c, r"^enable password")
    return ok, "", lambda: ["no enable password",
                            f"enable algorithm-type scrypt secret {get_enable_secret()}"]


@check("M-04", "service password-encryption", "Management")
def _(c):
    return has(c, r"^service password-encryption"), "", ["service password-encryption"]


@check("M-05", "Banners login y exec", "Management")
def _(c):
    ok = has(c, r"^banner login") and has(c, r"^banner exec")
    return ok, "", [f"banner login #{BANNER}#", f"banner exec #{BANNER}#"]


@check("M-06", "SSH versión 2", "Management")
def _(c):
    return has(c, r"^ip ssh version 2"), "", ["ip ssh version 2"]


@check("M-07", "SSH: time-out <= 60 s y reintentos <= 3", "Management")
def _(c):
    t = re.search(r"^ip ssh time-out (\d+)", c["cfg"], re.M)
    r = re.search(r"^ip ssh authentication-retries (\d+)", c["cfg"], re.M)
    ok = bool(t and r and int(t.group(1)) <= 60 and int(r.group(1)) <= 3)
    return ok, "", ["ip ssh time-out 60", "ip ssh authentication-retries 3"]


@check("M-08", "Clave RSA de al menos 2048 bits", "Management")
def _(c):
    # Heurística: el 'Key Data' de una clave de 2048 bits empieza por 30820122 (4096: 3082022...).
    ok = "30820122" in c["rsa"] or "3082022" in c["rsa"]
    return ok, "", [f"ip domain-name {DOMAIN}", "@genkey"]


@check("M-09", "ACL MGMT-ONLY permite solo al equipo de gestión", "Management")
def _(c):
    acl = blocks(c["cfg"], r"^ip access-list standard MGMT-ONLY")
    ok = bool(acl) and f"permit {MGMT_HOST}" in " ".join(acl[0]).replace("host ", "")
    return ok, "", ["no ip access-list standard MGMT-ONLY", "ip access-list standard MGMT-ONLY",
                    f"permit host {MGMT_HOST}", "deny any log", "exit"]


@check("M-10", "VTY: solo SSH, exec-timeout <= 5 min y access-class", "Management")
def _(c):
    bl = blocks(c["cfg"], r"^line vty")
    ok = bool(bl) and all("transport input ssh" in b and timeout_ok(b)
                          and any(x.startswith("access-class") for x in b) for b in bl)
    ranges = re.findall(r"^line vty (\d+ \d+)", c["cfg"], re.M) or ["0 4"]
    cmds = []
    for r in ranges:
        cmds += [f"line vty {r}", "transport input ssh", "exec-timeout 5 0",
                 "access-class MGMT-ONLY in", "exit"]
    return ok, "", cmds


@check("M-11", "Consola con exec-timeout <= 5 min", "Management")
def _(c):
    bl = blocks(c["cfg"], r"^line con 0")
    ok = bool(bl) and all(timeout_ok(b) for b in bl)
    return ok, "", ["line con 0", "exec-timeout 5 0", "logging synchronous", "exit"]


@check("M-12", "Puerto auxiliar con 'no exec'", "Management")
def _(c):
    bl = blocks(c["cfg"], r"^line aux 0")
    ok = (not bl) or all("no exec" in b for b in bl)
    return ok, "", ["line aux 0", "no exec", "exit"]


@check("M-13", "Servidor HTTP/HTTPS apagado", "Management")
def _(c):
    ok = not has(c, r"^ip http (server|secure-server)")
    return ok, "", ["no ip http server", "no ip http secure-server"]


@check("M-14", "Sin comunidades SNMP v1/v2c", "Management")
def _(c):
    com = re.findall(r"^snmp-server community (\S+)", c["cfg"], re.M)
    return not com, ", ".join(com), [f"no snmp-server community {x}" for x in com]


@check("M-15", "Timestamps, logging buffered y syslog remoto", "Management")
def _(c):
    pats = [r"^service timestamps log datetime", r"^logging buffered",
            rf"^logging host {re.escape(SYSLOG)}"]
    ok = all(has(c, p) for p in pats)
    return ok, "", ["service timestamps log datetime msec localtime show-timezone",
                    "service timestamps debug datetime msec localtime show-timezone",
                    "logging buffered 64000 informational", f"logging host {SYSLOG}",
                    "logging trap informational"]


@check("C-01", "Servicios innecesarios apagados (pad, source-route, bootp, domain-lookup)", "Control")
def _(c):
    pats = [r"^no service pad", r"^no ip source-route", r"^no ip bootp server",
            r"^no ip domain.lookup"]
    ok = all(has(c, p) for p in pats)
    return ok, "", ["no service pad", "no ip source-route", "no ip bootp server",
                    "no ip domain-lookup"]


@check("C-02", "CDP apagado", "Control")
def _(c):
    return has(c, r"^no cdp run"), "", ["no cdp run"]


@check("D-01", "Interfaces L3: sin redirects, unreachables ni proxy-arp", "Data")
def _(c):
    need = ["no ip redirects", "no ip unreachables", "no ip proxy-arp"]
    bad = [n for n, l in l3_ifaces(c["cfg"]).items() if not all(x in l for x in need)]
    cmds = []
    for n in bad:
        cmds += [f"interface {n}"] + need + ["exit"]
    return not bad, ", ".join(bad), cmds


@check("D-02", "uRPF en la subinterfaz de usuarios", "Data", roles=("router",))
def _(c):
    lines = ifaces(c["cfg"]).get(USER_IF)
    ok = lines is not None and any(x.startswith("ip verify unicast source reachable-via rx")
                                   for x in lines)
    return ok, "", [f"interface {USER_IF}", "ip verify unicast source reachable-via rx", "exit"]


@check("L-01", "Trunks: nonegotiate y VLAN nativa distinta de 1", "Capa 2", roles=("switch",))
def _(c):
    bad = [n for n, l in ifaces(c["cfg"]).items() if "switchport mode trunk" in l and not (
        "switchport nonegotiate" in l and any(
            x.startswith("switchport trunk native vlan") and not x.endswith(" 1") for x in l))]
    cmds = []
    for n in bad:
        cmds += [f"interface {n}", "switchport nonegotiate", "switchport trunk native vlan 999", "exit"]
    return not bad, ", ".join(bad), cmds


@check("L-02", "Puertos sin uso (VLAN 999) apagados", "Capa 2", roles=("switch",))
def _(c):
    bad = [n for n, l in ifaces(c["cfg"]).items()
           if "switchport access vlan 999" in l and "shutdown" not in l]
    cmds = []
    for n in bad:
        cmds += [f"interface {n}", "shutdown", "exit"]
    return not bad, ", ".join(bad), cmds


@check("L-03", "Puertos de acceso: nonegotiate, port-security y bpduguard", "Capa 2", roles=("switch",))
def _(c):
    glob = has(c, r"^spanning-tree portfast bpduguard default")
    bad = []
    for n, l in ifaces(c["cfg"]).items():
        if "switchport mode access" in l and "switchport access vlan 999" not in l:
            if not ("switchport nonegotiate" in l and "switchport port-security" in l
                    and (glob or "spanning-tree bpduguard enable" in l)):
                bad.append(n)
    cmds = []
    for n in bad:
        cmds += [f"interface {n}", "switchport nonegotiate", "switchport port-security",
                 "switchport port-security maximum 3", "switchport port-security violation restrict",
                 "switchport port-security mac-address sticky", "spanning-tree portfast",
                 "spanning-tree bpduguard enable", "exit"]
    return not bad, ", ".join(bad), cmds


@check("L-04", "DHCP Snooping en la VLAN 10 con trunk confiable", "Capa 2", roles=("switch",))
def _(c):
    v = re.search(r"^ip dhcp snooping vlan (\S+)", c["cfg"], re.M)
    vlans = v.group(1).split(",") if v else []
    trunks = [n for n, l in ifaces(c["cfg"]).items() if "switchport mode trunk" in l]
    trusted = trunks and all("ip dhcp snooping trust" in ifaces(c["cfg"])[n] for n in trunks)
    ok = has(c, r"^ip dhcp snooping$") and "10" in vlans and bool(trusted)
    cmds = ["ip dhcp snooping", "ip dhcp snooping vlan 10", "no ip dhcp snooping information option"]
    for n in trunks:
        cmds += [f"interface {n}", "ip dhcp snooping trust", "exit"]
    return ok, "", cmds


# ---------- ejecución ----------
def get_ctx(conn):
    return {"cfg": conn.send_command("show running-config"),
            "rsa": conn.send_command("show crypto key mypubkey rsa")}


def evaluate(ctx, role):
    res = []
    for ck in CHECKS:
        if role not in ck["roles"]:
            continue
        ok, detail, fix = ck["fn"](ctx)
        res.append({"id": ck["id"], "title": ck["title"], "plane": ck["plane"],
                    "ok": ok, "detail": detail, "fix": fix})
    return res


def gen_key(conn):
    conn.config_mode()
    out = conn.send_command_timing("crypto key generate rsa modulus 2048", read_timeout=180)
    if "yes/no" in out.lower():
        conn.send_command_timing("yes", read_timeout=180)
    conn.exit_config_mode()


def apply_fix(conn, fix):
    cmds = fix() if callable(fix) else fix
    chunk = []
    for cmd in cmds:
        if cmd == "@genkey":
            if chunk:
                conn.send_config_set(chunk)
                chunk = []
            gen_key(conn)
        else:
            chunk.append(cmd)
    if chunk:
        conn.send_config_set(chunk)


def status(pre, post=None):
    if post is None:
        return "PASS" if pre["ok"] else "FAIL"
    if pre["ok"]:
        return "PASS"
    if post["ok"]:
        return "CORREGIDO"
    return "MANUAL" if pre["fix"] is None else "FALLA"


def write_report(outdir, mode, results):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    md = [f"# Informe CIS ({mode})", f"Generado: {ts}", ""]
    js = {}
    for name, (pre, post) in results.items():
        md += [f"## {name}", ""]
        if post:
            md += ["| ID | Control | Antes | Después |", "|---|---|---|---|"]
            for a, b in zip(pre, post):
                md.append(f"| {a['id']} | {a['title']} | {'PASS' if a['ok'] else 'FAIL'} | {status(a, b)} |")
            pa, pb = sum(r["ok"] for r in pre), sum(r["ok"] for r in post)
            md += ["", f"**Cumplimiento: {pa}/{len(pre)} → {pb}/{len(post)} "
                       f"({100*pb//len(post)}%)**", ""]
        else:
            md += ["| ID | Control | Estado | Detalle |", "|---|---|---|---|"]
            for a in pre:
                md.append(f"| {a['id']} | {a['title']} | {status(a)} | {a['detail']} |")
            pa = sum(r["ok"] for r in pre)
            md += ["", f"**Cumplimiento: {pa}/{len(pre)} ({100*pa//len(pre)}%)**", ""]
        strip = lambda rs: [{k: v for k, v in r.items() if k != "fix"} for r in rs]
        js[name] = {"antes": strip(pre), "despues": strip(post) if post else None}
    (outdir / f"informe-{mode}.md").write_text("\n".join(md), encoding="utf-8")
    (outdir / f"informe-{mode}.json").write_text(json.dumps(js, indent=2, ensure_ascii=False),
                                                 encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description="Auditoría y hardening CIS de Cisco IOS")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--audit", action="store_true", help="solo informe, sin aplicar reglas")
    g.add_argument("--apply", action="store_true", help="aplicar reglas e informe póstumo")
    ap.add_argument("--user", default="admin-local")
    ap.add_argument("--devices", nargs="*", help="nombres de equipos (por defecto, todos)")
    args = ap.parse_args()

    mode = "apply" if args.apply else "audit"
    outdir = Path("reports") / datetime.now().strftime("%Y%m%d-%H%M%S")
    (outdir / "backups").mkdir(parents=True, exist_ok=True)
    pw = getpass.getpass(f"Contraseña de {args.user}: ")

    results = {}
    for dev in DEVICES:
        if args.devices and dev["name"] not in args.devices:
            continue
        print(f"[*] {dev['name']} ({dev['host']}) ...")
        conn = ConnectHandler(device_type="cisco_ios", host=dev["host"],
                              username=args.user, password=pw)
        ctx = get_ctx(conn)
        pre = evaluate(ctx, dev["role"])
        post = None
        if args.apply:
            (outdir / "backups" / f"{dev['name']}-pre.cfg").write_text(ctx["cfg"])
            for r in pre:
                if not r["ok"] and r["fix"]:
                    print(f"    aplicando {r['id']}: {r['title']}")
                    apply_fix(conn, r["fix"])
            conn.save_config()
            ctx2 = get_ctx(conn)
            (outdir / "backups" / f"{dev['name']}-post.cfg").write_text(ctx2["cfg"])
            post = evaluate(ctx2, dev["role"])
        conn.disconnect()
        results[dev["name"]] = (pre, post)

    write_report(outdir, mode, results)
    print(f"[+] Informe en {outdir}/informe-{mode}.md")


if __name__ == "__main__":
    main()
```

> **Notas de uso:**
> * Si el SSH de IOS viejo no negocia con las versiones actuales de OpenSSH/Paramiko, revisar los algoritmos permitidos (en los otros laboratorios se usó `-c aes256-cbc` con el cliente `ssh`).
> * La comprobación M-08 (tamaño de la clave RSA) es una heurística sobre el `Key Data`; se confirma a mano con `show crypto key mypubkey rsa`.
> * La remediación de M-10 y M-09 se ejecuta sobre una sesión ya abierta: el cambio no la cierra, pero las conexiones nuevas desde otro origen sí se rechazan.

---

## 6. Matriz de cumplimiento de requisitos

| Requisito del enunciado | Cómo se cumple | Sección |
|---|---|---|
| **Repositorio de GitHub** | Este repositorio | — |
| Documentación profesional en el repositorio | Este `README.md` y la carpeta `screenshots/` | — |
| Video demostrativo al principio del repositorio | Enlace al inicio de este documento | Inicio |
| Documentación con imágenes | Capturas numeradas en `screenshots/` | 7 |
| Documentación con diagramas | Diagrama de topología y política de gestión | 2.1 |
| Propósito del laboratorio | Sección 1 | 1 |
| Todo script utilizado en el repositorio | Carpeta `scripts/` | 5, 8 |
| Running-configs en el repositorio | Carpeta `running-configs/` | Paso 11 |
| Red con al menos un Router, Switch o Firewall | Router `R-CIS` y Switch `SW-CIS` | 2 |
| Herramienta de análisis basada en CIS Benchmark | `TODO_HERRAMIENTA` y el script `cis_hardening.py` | Pasos 6, 7, 9 |
| Aplicar recomendaciones de hardening | 21 controles (M, C, D y L) | 3, Paso 8 |
| Documentar las recomendaciones y por qué se aplicaron | Tablas 3.1 a 3.4 | 3 |
| Probar las recomendaciones aplicadas | Pruebas 10.1 a 10.6 | Paso 10 |
| Script que escanea los equipos en busca de las recomendaciones | `cis_hardening.py` | 5 |
| Script: crear informe sin aplicar reglas | Modo `--audit` | Paso 7 |
| Script: aplicar reglas y generar informe póstumo | Modo `--apply` | Paso 8 |
| Direccionamiento basado en la matrícula | `10.7.30.0/24` (matrícula 0730) | 2.2 |

---

## 7. Capturas de Pantalla

Numeradas en el orden en que se toman durante el procedimiento.

| # | Archivo | Paso | Descripción |
|---|---|---|---|
| 01 | [`01_topologia_pnet.png`](screenshots/01_topologia_pnet.png) | 1 | Topología en PNETLab: R-CIS, SW-CIS y las nubes. |
| 02 | [`02_switch_base.png`](screenshots/02_switch_base.png) | 2 | Configuración inicial del switch. |
| 03 | [`03_router_base.png`](screenshots/03_router_base.png) | 3 | Configuración inicial del router. |
| 04 | [`04_admin_pc_red.png`](screenshots/04_admin_pc_red.png) | 4 | Admin-PC con `10.7.30.4/27` y syslog escuchando. |
| 05 | [`05_conectividad.png`](screenshots/05_conectividad.png) | 5 | Pings y acceso inicial (aún con Telnet). |
| 06 | [`06_herramienta_antes.png`](screenshots/06_herramienta_antes.png) | 6 | Informe CIS inicial de la herramienta. |
| 07 | [`07_script_audit.png`](screenshots/07_script_audit.png) | 7 | Ejecución de `--audit`. |
| 08 | [`08_informe_audit.png`](screenshots/08_informe_audit.png) | 7 | Informe sin aplicar reglas (FAIL/PASS). |
| 09 | [`09_script_apply.png`](screenshots/09_script_apply.png) | 8 | Ejecución de `--apply`. |
| 10 | [`10_informe_apply.png`](screenshots/10_informe_apply.png) | 8 | Informe póstumo: antes y después. |
| 11 | [`11_herramienta_despues.png`](screenshots/11_herramienta_despues.png) | 9 | Informe CIS final de la herramienta. |
| 12 | [`12_ssh_admin_ok.png`](screenshots/12_ssh_admin_ok.png) | 10.1 | SSH v2 desde el Admin-PC con banner. |
| 13 | [`13_telnet_ssh_usuario_denegado.png`](screenshots/13_telnet_ssh_usuario_denegado.png) | 10.1 | Telnet y SSH desde el PC-Usuario rechazados. |
| 14 | [`14_nmap_despues.png`](screenshots/14_nmap_despues.png) | 10.2 | `nmap` con solo el puerto 22 abierto. |
| 15 | [`15_snmp_cdp_apagados.png`](screenshots/15_snmp_cdp_apagados.png) | 10.2 | SNMP sin respuesta y CDP apagado. |
| 16 | [`16_lineas_banner.png`](screenshots/16_lineas_banner.png) | 10.3 | `enable secret`, líneas y banner. |
| 17 | [`17_logs_router.png`](screenshots/17_logs_router.png) | 10.4 | `show logging` con fecha y hora. |
| 18 | [`18_syslog_admin.png`](screenshots/18_syslog_admin.png) | 10.4 | Eventos recibidos en el servidor syslog. |
| 19 | [`19_dataplane_router.png`](screenshots/19_dataplane_router.png) | 10.5 | Interfaz con redirects, unreachables, proxy-arp y uRPF. |
| 20 | [`20_switch_l2_hardening.png`](screenshots/20_switch_l2_hardening.png) | 10.6 | Trunk, puertos apagados, port-security y DHCP snooping. |
| 21 | [`21_running_configs.png`](screenshots/21_running_configs.png) | 11 | Running-configs finales. |

---

## 8. Estructura del Repositorio

```
/
├── README.md                    ← este documento
├── screenshots/                 ← capturas numeradas de cada configuración
├── scripts/
│   ├── sw-cis-base.txt          ← switch: configuración inicial (insegura)
│   ├── r-cis-base.txt           ← router: configuración inicial (insegura)
│   └── cis_hardening.py         ← auditoría (--audit) y hardening (--apply)
├── reports/
│   ├── herramienta-antes/       ← informe CIS inicial de la herramienta externa
│   ├── herramienta-despues/     ← informe CIS final de la herramienta externa
│   ├── <fecha-hora>/            ← informes del script (audit y apply, md + json)
│   └── <fecha-hora>/backups/    ← configuración de cada equipo antes y después
├── running-configs/
│   ├── pre-r-cis-running-config.txt
│   ├── pre-sw-cis-running-config.txt
│   ├── r-cis-running-config.txt
│   └── sw-cis-running-config.txt
```

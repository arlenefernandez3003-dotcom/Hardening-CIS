# Hardening CIS de Router, Switch y Firewall: Auditoría y Remediación Automatizada

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
   - [Paso 1. PNETLab y máquinas virtuales](#paso-1-pnetlab-y-máquinas-virtuales)
   - [Paso 2. Firewall FW-CIS: configuración inicial (insegura)](#paso-2-firewall-fw-cis-configuración-inicial-insegura)
   - [Paso 3. Router R-CIS: configuración inicial (insegura)](#paso-3-router-r-cis-configuración-inicial-insegura)
   - [Paso 4. Switch SW-CIS: configuración inicial (insegura)](#paso-4-switch-sw-cis-configuración-inicial-insegura)
   - [Paso 5. Equipo auditor (Admin-PC) y PC-Usuario](#paso-5-equipo-auditor-admin-pc-y-pc-usuario)
   - [Paso 6. Verificar la conectividad](#paso-6-verificar-la-conectividad)
   - [Paso 7. Exportar las configuraciones iniciales (línea base)](#paso-7-exportar-las-configuraciones-iniciales-línea-base)
   - [Paso 8. Análisis CIS inicial: informe sin aplicar cambios](#paso-8-análisis-cis-inicial-informe-sin-aplicar-cambios)
   - [Paso 9. Script de hardening: aplicar reglas e informe póstumo](#paso-9-script-de-hardening-aplicar-reglas-e-informe-póstumo)
   - [Paso 10. Exportar configuraciones finales y comparar resultados](#paso-10-exportar-configuraciones-finales-y-comparar-resultados)
   - [Paso 11. Pruebas de las recomendaciones aplicadas](#paso-11-pruebas-de-las-recomendaciones-aplicadas)
   - [Paso 12. Exportar las configuraciones](#paso-12-exportar-las-configuraciones)
5. [El script `cis_hardening.py`](#5-el-script-cis_hardeningpy)
6. [Matriz de cumplimiento de requisitos](#6-matriz-de-cumplimiento-de-requisitos)
7. [Capturas de Pantalla](#7-capturas-de-pantalla)
8. [Estructura del Repositorio](#8-estructura-del-repositorio)

---

## 1. Propósito del Laboratorio

Esta práctica construye una red con **un Router, un Switch y un Firewall**: un router Cisco como borde hacia el ISP, un firewall **FortiGate (FortiOS 7.0.x)** como gateway de las redes internas y un switch Cisco de acceso. La red se deja con una configuración **insegura de fábrica**, se **analiza contra los CIS Benchmarks** de cada equipo y se le aplica **hardening** de forma automatizada.

* Se mide el nivel de cumplimiento **antes** y **después** del hardening con un script propio de auditoría CIS (`cis_hardening.py`), que evalúa los 35 controles elegidos en los tres equipos y genera un informe con el porcentaje de cumplimiento.
* Se aplican recomendaciones del **CIS Cisco IOS Benchmark** al router y al switch (Management Plane, Control Plane y Data Plane, más controles complementarios de capa 2) y del **CIS FortiGate 7.0.x Benchmark** al firewall.
* Un **script en Python** escanea los tres equipos y puede trabajar en dos modos:
  * **`--audit`:** genera un informe **sin aplicar ninguna regla**.
  * **`--apply`:** aplica las reglas que fallan y genera un **informe póstumo** (antes y después).
* Cada recomendación aplicada se **documenta, se justifica y se prueba**.

El objetivo de seguridad es demostrar que la red pasa de una configuración con Telnet, HTTP, SNMP `public`, sesiones sin límite de inactividad y tráfico sin registrar a una con administración solo cifrada y desde el equipo de gestión, servicios innecesarios apagados y eventos centralizados, y que ese cambio es medible y repetible.

---

## 2. Topología y Direccionamiento

> Las redes internas son **privadas** y salen todas de `10.7.30.0/24` (matrícula 0730), repartidas con **VLSM**. No se usa la primera IP utilizable de ninguna red: el gateway usa la **segunda**. La red del ISP es **pública**: `202.50.73.0/24` (NAT de VMware, VMnet8).

### 2.1 Diagrama de Topología

```
              ISP · NAT de VMware (VMnet8)
              202.50.73.0/24 · GW 202.50.73.2
                          │
                  Et0/0: 202.50.73.10
                 ┌────────┴────────┐
                 │      R-CIS      │
                 │  Router (borde) │
                 └────────┬────────┘
                  Et0/1: 10.7.30.66/29
                          │   Tránsito 10.7.30.64/29
                  port1: 10.7.30.67/29
                 ┌────────┴────────┐
                 │     FW-CIS      │
                 │ FortiGate 7.0.x │
                 └────────┬────────┘
                    port2 (trunk 802.1Q)
                    ├ VLAN99  10.7.30.2/27   Gestión
                    └ VLAN10  10.7.30.34/27  Usuarios · DHCP
                          │
                     e0/0 │ trunk · VLAN 10, 99
                 ┌────────┴────────┐
                 │     SW-CIS      │
                 │ Switch · Vlan99 │
                 │  10.7.30.3/27   │
                 └───┬─────────┬───┘
                   e0/1       e0/2
                (VLAN 99)   (VLAN 10)
                     │         │
             ┌───────┴──┐  ┌───┴──────────┐
             │ Admin-PC │  │  PC-Usuario  │
             │10.7.30.4 │  │ DHCP .40-.62 │
             └──────────┘  └──────────────┘

  Flujo del script:
  Admin-PC ──SSH (TCP 22)──► R-CIS / SW-CIS / FW-CIS ──► informe (Markdown + JSON) en reports/
  R-CIS / SW-CIS / FW-CIS ──syslog (UDP 514)──► Admin-PC

  Política de gestión (después del hardening):
  ┌───────────────────────────────────────────────────────────────────┐
  │ Admin-PC (10.7.30.4)  → R-CIS / SW-CIS / FW-CIS : SSH v2, HTTPS   │
  │ PC-Usuario            → equipos de red : SSH/Telnet/HTTP denegados│
  │ Telnet, HTTP y SNMP v1/v2c (public/private) : deshabilitados      │
  └───────────────────────────────────────────────────────────────────┘
```

### 2.2 Redes y VLSM sobre `10.7.30.0/24`

| Bloque | Requisito | Red | VLAN | Hosts utilizables | Gateway | Broadcast |
|---|---|---|---|---|---|---|
| Gestión | `/27` | 10.7.30.0/27 | 99 | .1 – .30 (se usan .2, .3 y .4) | 10.7.30.2 (FW-CIS) | .31 |
| Usuarios | `/27` | 10.7.30.32/27 | 10 | .33 – .62 | 10.7.30.34 (FW-CIS) | .63 |
| Tránsito Router–Firewall | `/29` | 10.7.30.64/29 | — | .65 – .70 (se usan .66 y .67) | 10.7.30.66 (R-CIS) | .71 |
| Libre | — | 10.7.30.72 – .255 | — | — | — | — |

### 2.3 Tabla de Dispositivos

| Dispositivo | Sistema | Interfaz | IP | Máscara | Gateway | Método | Rol |
|---|---|---|---|---|---|---|---|
| **R-CIS** | Cisco IOS 15.x (IOL) | Et0/0 | 202.50.73.10 | /24 | 202.50.73.2 | Estática | WAN y NAT |
| **R-CIS** | Cisco IOS 15.x (IOL) | Et0/1 | 10.7.30.66 | /29 | — | Estática | Tránsito hacia el firewall |
| **FW-CIS** | FortiOS 7.0.x (sin licencia) | port1 | 10.7.30.67 | /29 | 10.7.30.66 | Estática | Tránsito hacia el router |
| **FW-CIS** | FortiOS 7.0.x (sin licencia) | VLAN99 (port2) | 10.7.30.2 | /27 | — | Estática | Gateway de gestión |
| **FW-CIS** | FortiOS 7.0.x (sin licencia) | VLAN10 (port2) | 10.7.30.34 | /27 | — | Estática | Gateway de usuarios y DHCP |
| **SW-CIS** | Cisco IOS 15.x (IOL L2) | Vlan99 | 10.7.30.3 | /27 | 10.7.30.2 | Estática | Switch de acceso |
| **Admin-PC** | Ubuntu Desktop | ens3 | 10.7.30.4 | /27 | 10.7.30.2 | Estática | Auditor, servidor syslog, navegador |
| **PC-Usuario** | Ubuntu | ens3 | 10.7.30.40 – .62 (rango) | /27 | 10.7.30.34 | **DHCP** | Usuario sin acceso a la gestión |

### 2.4 Tabla de puertos del Switch

| Interfaz | Modo | VLAN | Conectado a |
|---|---|---|---|
| **e0/0** | Trunk (802.1Q) | 10, 99 (nativa 999 tras el hardening) | FW-CIS `port2` |
| **e0/1** | Access | 99 | Admin-PC |
| **e0/2** | Access | 10 | PC-Usuario |
| **e0/3, e1/0 – e1/3** | Sin uso | 999 | Sin cable (se apagan con el hardening) |

---

## 3. Recomendaciones CIS aplicadas y por qué

Las referencias son el **CIS Cisco IOS 15 Benchmark** (router y switch) y el **CIS FortiGate 7.0.x Benchmark** (firewall). Los controles se organizan en los planos que usa el benchmark de Cisco. La columna **ID** es la numeración propia del laboratorio (la usa el script); el número de sección exacto depende de la versión del PDF del benchmark que se use.

> Los controles **L-xx** (capa 2) son **complementarios**: refuerzan el switch con prácticas de hardening de Cisco y no se presentan como numerales del benchmark.

En total son **35 controles distintos**: 19 se evalúan en el router, 22 en el switch y 12 en el firewall.

### 3.1 Management Plane (Cisco IOS)

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

### 3.2 Control Plane (Cisco IOS)

| ID | Recomendación | Comando clave | Por qué se aplicó | Equipo |
|---|---|---|---|---|
| C-01 | Apagar servicios innecesarios | `no service pad`, `no ip source-route`, `no ip bootp server`, `no ip domain-lookup` | Cada servicio activo es una vía de ataque o de fuga de información sin utilidad en esta red. | R, S |
| C-02 | Apagar CDP | `no cdp run` | CDP anuncia modelo, versión de IOS e IPs a cualquier vecino que escuche. | R, S |

### 3.3 Data Plane (Cisco IOS)

| ID | Recomendación | Comando clave | Por qué se aplicó | Equipo |
|---|---|---|---|---|
| D-01 | Endurecer las interfaces de capa 3 | `no ip redirects`, `no ip unreachables`, `no ip proxy-arp` | Evita fuga de información de topología, redirecciones maliciosas y que el equipo responda ARP por otros. | R, S |
| D-02 | Unicast RPF en la interfaz hacia el firewall | `ip verify unicast source reachable-via rx` | Descarta paquetes con IP de origen falsificada que llegan desde la red interna. | R |

### 3.4 Controles complementarios de capa 2 (switch)

| ID | Recomendación | Comando clave | Por qué se aplicó | Equipo |
|---|---|---|---|---|
| L-01 | Trunk seguro | `switchport nonegotiate`, `switchport trunk native vlan 999` | Evita negociación DTP y ataques de VLAN hopping por VLAN nativa. | S |
| L-02 | Puertos sin uso apagados | `shutdown` en los puertos de la VLAN 999 | Un puerto libre y activo es un punto de conexión no autorizado. | S |
| L-03 | Protección de puertos de acceso | `switchport nonegotiate`, `port-security`, `bpduguard` | Limita las MAC por puerto y bloquea switches no autorizados. | S |
| L-04 | DHCP Snooping | `ip dhcp snooping`, `ip dhcp snooping vlan 10`, `ip dhcp snooping trust` | Impide que un DHCP falso en la VLAN de usuarios entregue direcciones o gateway maliciosos. | S |

### 3.5 Firewall FortiGate (CIS FortiGate 7.0.x)

| ID | Recomendación | Comando clave | Por qué se aplicó | Equipo |
|---|---|---|---|---|
| F-01 | Banners de inicio de sesión (pre y post login) | `set pre-login-banner enable`, `set post-login-banner enable` | Advierte que el acceso es restringido y monitoreado antes y después de autenticarse. | F |
| F-02 | Strong crypto habilitado | `set strong-crypto enable` | Obliga a usar algoritmos de cifrado robustos en la administración. | F |
| F-03 | GUI solo con TLS 1.2 o superior | `set admin-https-ssl-versions tlsv1-2 tlsv1-3` | TLS 1.0 y 1.1 están obsoletos y tienen debilidades conocidas. | F |
| F-04 | Política de contraseñas de administrador | `config system password-policy` | Una contraseña corta y sin complejidad es fácil de adivinar por fuerza bruta. | F |
| F-05 | Bloqueo de administrador | `set admin-lockout-threshold 3`, `set admin-lockout-duration 900` | Frena los ataques de fuerza bruta contra el inicio de sesión. | F |
| F-06 | Tiempo de inactividad de administrador | `set admintimeout 5` | Cierra sesiones de administración abandonadas. | F |
| F-07 | Solo canales de administración cifrados | `set admin-telnet disable`, `set admin-ssh-v1 disable` | Telnet y SSH v1 envían o protegen mal las credenciales. | F |
| F-08 | Servicios de administración mínimos por interfaz | `set allowaccess ...` | Sin HTTP/Telnet en ninguna interfaz y solo `ping` en la interfaz externa, el firewall no se administra desde fuera. | F |
| F-09 | Sin comunidades SNMP v1/v2c y agente apagado | `config system snmp community`, `sysinfo` | Una comunidad conocida expone información del equipo en claro. | F |
| F-10 | Registro remoto (syslog) | `config log syslogd setting` | Los eventos fuera del equipo no se pierden si este falla o es comprometido. | F |
| F-11 | Las políticas registran todo el tráfico | `set logtraffic all` | Sin registro de sesiones no hay evidencia de qué pasó por el firewall. | F |
| F-12 | Hosts de confianza en las cuentas de administrador | `set trusthost1 10.7.30.4 255.255.255.255` | La cuenta `admin` solo puede iniciar sesión desde el equipo de gestión. | F |

---

## 4. Procedimiento paso a paso

Los pasos están en el orden en que se ejecutan. Cada uno depende de los anteriores.

> Los nombres de interfaz (`Ethernet0/0`, `port1`, …) deben ajustarse a los que muestre `show ip interface brief` (Cisco) o `get system interface physical` (FortiGate) en las imágenes usadas en PNETLab. El adaptador de Linux (`ens3`) se consulta con `ip -br link`.

---

### Paso 1. PNETLab y máquinas virtuales

**1.1 — Red NAT de VMware (ISP)**

**Ruta:** `VMware → Edit → Virtual Network Editor → Change Settings → VMnet8 (NAT)`

| Campo | Valor |
|---|---|
| Subnet IP | `202.50.73.0` |
| Subnet mask | `255.255.255.0` |
| NAT Settings → Gateway IP | `202.50.73.2` |

**1.2 — Redes virtuales de las VMs**

Cada VM se conecta a su propia red **Host-only** (sin DHCP de VMware), enlazada a PNETLab con un nodo **Cloud**. Cada una entra por **un solo cable**.

| VM | Sistema | RAM | vCPU | Red virtual |
|---|---|---|---|---|
| Admin-PC | Ubuntu Desktop | 2 GB | 2 | VMnet16 (Host-only, sin DHCP) |
| PC-Usuario | Ubuntu | 1 GB | 1 | VMnet17 (Host-only, sin DHCP) |

**1.3 — En PNETLab**

1. Agregar un nodo **Router** (IOL L3) llamado `R-CIS`, un nodo **Switch** (IOL L2) llamado `SW-CIS` y un nodo **FortiGate** (FortiOS 7.0.x) llamado `FW-CIS`.
2. Agregar tres nodos `Network` de tipo `Cloud`: `Nube-ISP` (VMnet8), `Nube-Admin` (VMnet16) y `Nube-Usuario` (VMnet17).
3. Conectar `Et0/0` de `R-CIS` a `Nube-ISP`.
4. Conectar `Et0/1` de `R-CIS` a `port1` de `FW-CIS`.
5. Conectar `port2` de `FW-CIS` a `e0/0` de `SW-CIS`.
6. Conectar `Nube-Admin` a `e0/1` y `Nube-Usuario` a `e0/2` de `SW-CIS`.

> Ver evidencia: [01_topologia_pnet.png](screenshots/01_topologia_pnet.png)

---

### Paso 2. Firewall FW-CIS: configuración inicial (insegura)

Esta configuración deja el firewall **funcional pero sin hardening**, para que el análisis encuentre incumplimientos (script: [`scripts/fw-cis-base.conf`](scripts/fw-cis-base.conf)).

**2.1 — Acceso inicial por consola**

Iniciar sesión por la consola de PNETLab con `admin` y contraseña vacía; el FortiGate pide definir una contraseña nueva (`Lab12345!`).

**2.2 — Configuración base (CLI)**

```bash
config system global
    set hostname "FW-CIS"
    set admintimeout 480
    set admin-lockout-threshold 10
    set admin-telnet enable
    set admin-https-ssl-versions tlsv1-1 tlsv1-2 tlsv1-3
end

config system interface
    edit "port1"
        set mode static
        set ip 10.7.30.67 255.255.255.248
        set allowaccess ping https ssh http telnet
        set alias "TRANSITO-R"
        set role wan
        set mtu-override enable
        set mtu 1480
        set tcp-mss 1440
    next
    edit "port2"
        set alias "TRUNK-SW"
        set role undefined
    next
    edit "VLAN99"
        set vdom "root"
        set type vlan
        set interface "port2"
        set vlanid 99
        set mode static
        set ip 10.7.30.2 255.255.255.224
        set allowaccess ping https ssh http telnet
        set alias "GESTION"
        set role lan
        set mtu-override enable
        set mtu 1480
        set tcp-mss 1440
    next
    edit "VLAN10"
        set vdom "root"
        set type vlan
        set interface "port2"
        set vlanid 10
        set mode static
        set ip 10.7.30.34 255.255.255.224
        set allowaccess ping
        set alias "USUARIOS"
        set role lan
        set mtu-override enable
        set mtu 1480
        set tcp-mss 1440
    next
end

config system dhcp server
    edit 1
        set interface "VLAN10"
        set default-gateway 10.7.30.34
        set netmask 255.255.255.224
        set dns-service specify
        set dns-server1 8.8.8.8
        set dns-server2 8.8.4.4
        set lease-time 86400
        config ip-range
            edit 1
                set start-ip 10.7.30.40
                set end-ip 10.7.30.62
            next
        end
    next
end

config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set gateway 10.7.30.66
        set device "port1"
    next
end

config firewall policy
    edit 1
        set name "LAN-to-Transito"
        set srcintf "VLAN10" "VLAN99"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic disable
    next
end

config system snmp sysinfo
    set status enable
end
config system snmp community
    edit 1
        set name "public"
        config hosts
            edit 1
                set ip 0.0.0.0 0.0.0.0
            next
        end
    next
end
```

> Los bloques `config system snmp` de arriba dejan una comunidad `public` a propósito, para que el análisis la detecte.

**2.3 — Verificación**

```bash
get system interface physical
show system interface
show firewall policy
```

> Ver evidencia: [04_firewall_base.png](screenshots/04_firewall_base.png)

---

### Paso 3. Router R-CIS: configuración inicial (insegura)

Script: [`scripts/r-cis-base.txt`](scripts/r-cis-base.txt).

```bash
enable
configure terminal

hostname R-CIS
ip domain-name cis.itla.local

interface Ethernet0/0
 description ISP
 ip address 202.50.73.10 255.255.255.0
 ip nat outside
 no shutdown
exit

interface Ethernet0/1
 description Transito hacia FW-CIS
 ip address 10.7.30.66 255.255.255.248
 ip tcp adjust-mss 1420
 ip nat inside
 no shutdown
exit

ip access-list standard NAT-LAN
 permit 10.7.30.0 0.0.0.127
exit

ip nat inside source list NAT-LAN interface Ethernet0/0 overload
ip route 0.0.0.0 0.0.0.0 202.50.73.2
ip route 10.7.30.0 255.255.255.192 10.7.30.67

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

> Las líneas que empiezan con `!` son comentarios y se pueden pegar sin problema en IOS.

> Ver evidencia: [03_router_base.png](screenshots/03_router_base.png)

---

### Paso 4. Switch SW-CIS: configuración inicial (insegura)

Esta configuración deja el switch **funcional pero sin hardening** (script: [`scripts/sw-cis-base.txt`](scripts/sw-cis-base.txt)).

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
 description Trunk hacia FW-CIS port2
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

### Paso 5. Equipo auditor (Admin-PC) y PC-Usuario

**5.1 — Admin-PC: red** (`/etc/netplan/50-cloud-init.yaml`, ajustar `ens3`):

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
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
```

```bash
sudo netplan apply
```

**5.2 — Admin-PC: dependencias** (la red ya tiene salida a Internet por el NAT del router):

```bash
sudo apt update && sudo apt install -y python3-pip python3-venv nmap snmp netcat-openbsd
python3 -m venv ~/cis && source ~/cis/bin/activate
pip install netmiko
mkdir -p ~/cis-lab/scripts ~/cis-lab/reports ~/cis-lab/running-configs
```

**5.3 — Admin-PC: servidor syslog (UDP 514)**

```bash
sudo sed -i 's/^#module(load="imudp")/module(load="imudp")/; s/^#input(type="imudp" port="514")/input(type="imudp" port="514")/' /etc/rsyslog.conf
sudo systemctl restart rsyslog
ss -lun | grep 514
```

**5.4 — PC-Usuario:** recibe IP por DHCP del FortiGate (`10.7.30.40 – .62`, gateway `10.7.30.34`). Para evitar problemas con paquetes grandes en PNETLab, fijar el MTU en `/etc/netplan/50-cloud-init.yaml`:

```yaml
network:
  version: 2
  ethernets:
    ens3:
      dhcp4: true
      mtu: 1460
```

```bash
sudo netplan apply
ip addr
```

> Ver evidencia: [05_admin_pc_red.png](screenshots/05_admin_pc_red.png)

---

### Paso 6. Verificar la conectividad

Desde el **Admin-PC**:

```bash
ping -c 3 10.7.30.2        # FW-CIS (gateway)
ping -c 3 10.7.30.3        # SW-CIS
ping -c 3 10.7.30.66       # R-CIS
ping -c 3 8.8.8.8          # salida al ISP
ssh admin-local@10.7.30.66 # debe entrar (aún sin hardening)
telnet 10.7.30.66          # debe entrar: línea base insegura
```

Desde el **PC-Usuario**: `ip addr`, `ping -c 3 10.7.30.34` y `ping -c 3 8.8.8.8`.

> Si `ssh` falla con `no matching key exchange method found`, el IOS solo ofrece algoritmos antiguos. Habilitarlos en el cliente, una sola vez:
>
> ```bash
> mkdir -p ~/.ssh && printf 'Host 10.7.30.*\n  KexAlgorithms +diffie-hellman-group14-sha1\n  HostKeyAlgorithms +ssh-rsa\n  Ciphers +aes256-cbc,aes128-cbc\n' >> ~/.ssh/config
> ```

> Ver evidencia: [06_conectividad.png](screenshots/06_conectividad.png)

---

### Paso 7. Exportar las configuraciones iniciales (línea base)

Con la red todavía en la configuración insegura de los Pasos 2 a 4, se guardan las configuraciones de los tres equipos. Estos archivos `pre-*` documentan el estado de partida y quedan en el repositorio. La medición de cumplimiento CIS se hace con el script en el Paso 8.

**7.1 — Router y switch** (desde el Admin-PC, con el entorno virtual activo). Guardar este código en `scripts/exportar_configs.py`:

```python
#!/usr/bin/env python3
"""exportar_configs.py <pre|post>

Guarda el show running-config de R-CIS y SW-CIS en running-configs/.
La configuración de FW-CIS se exporta desde la GUI del FortiGate.
"""
import getpass
import sys
from pathlib import Path

from netmiko import ConnectHandler

DEVICES = {"r-cis": "10.7.30.66", "sw-cis": "10.7.30.3"}

if len(sys.argv) != 2 or sys.argv[1] not in ("pre", "post"):
    sys.exit("Uso: exportar_configs.py <pre|post>")

fase = sys.argv[1]
out = Path("running-configs")
out.mkdir(exist_ok=True)
user = input("Usuario [admin-local]: ") or "admin-local"
password = getpass.getpass("Contraseña: ")

for name, host in DEVICES.items():
    conn = ConnectHandler(device_type="cisco_ios", host=host, username=user, password=password)
    (out / f"{fase}-{name}-running-config.txt").write_text(conn.send_command("show running-config"))
    conn.disconnect()
    print(f"[+] {name} exportado")
```

```bash
cd ~/cis-lab && source ~/cis/bin/activate
python3 scripts/exportar_configs.py pre
ls running-configs/
```

Deben aparecer `pre-r-cis-running-config.txt` y `pre-sw-cis-running-config.txt`.

**7.2 — Firewall** (desde la GUI del FortiGate, en el navegador del Admin-PC): iniciar sesión en `https://10.7.30.2` (aceptar el certificado autofirmado) y, en el menú del usuario `admin` (arriba a la derecha), elegir **Configuration → Backup**, destino **Local PC**, y guardar el archivo como `running-configs/pre-fw-cis-config.conf`.

> Ver evidencia: [07_configs_iniciales.png](screenshots/07_configs_iniciales.png)

---

### Paso 8. Análisis CIS inicial: informe sin aplicar cambios

La herramienta de análisis es el script propio [`scripts/cis_hardening.py`](scripts/cis_hardening.py) (sección 5). Se conecta por SSH a los tres equipos, lee su configuración y evalúa los controles CIS elegidos (19 en el router, 22 en el switch y 12 en el firewall). En el modo `--audit` **no modifica nada**; este informe es la medición **antes** del hardening.

```bash
cd ~/cis-lab && source ~/cis/bin/activate
python3 scripts/cis_hardening.py --audit
```

Pide la contraseña de `admin-local` (router y switch) y la de `admin` (firewall) y genera, en `reports/<fecha-hora>/`:

| Archivo | Contenido |
|---|---|
| `informe-audit.md` | Tabla por equipo con cada control en `PASS` o `FAIL` y el resumen de cumplimiento. |
| `informe-audit.json` | El mismo resultado en formato máquina. |

Para ver los porcentajes de los tres equipos:

```bash
grep -H "Cumplimiento" reports/*/informe-audit.md
```

**Resultado inicial (antes del hardening)**

| Equipo | Controles evaluados | Cumplen | No cumplen | % de cumplimiento (antes) |
|---|---|---|---|---|
| R-CIS | 19 | `TODO` | `TODO` | `TODO` |
| SW-CIS | 22 | `TODO` | `TODO` | `TODO` |
| FW-CIS | 12 | `TODO` | `TODO` | `TODO` |

Comprobar después que los equipos **no cambiaron**: comparar `show running-config` (Cisco) y `show` (FortiGate) antes y después.

> Ver evidencia: [08_script_audit.png](screenshots/08_script_audit.png), [09_informe_audit.png](screenshots/09_informe_audit.png)

---

### Paso 9. Script de hardening: aplicar reglas e informe póstumo

> ⚠️ **Antes de aplicar:** mantener abierta una consola de PNETLab en cada equipo. La regla M-10 limita el SSH de los equipos Cisco al Admin-PC (`10.7.30.4`) y la regla F-12 limita la cuenta `admin` del firewall a ese mismo equipo; desde la consola siempre se puede recuperar el acceso.

```bash
python3 scripts/cis_hardening.py --apply
```

El script, por cada equipo:

1. Evalúa los controles (estado **antes**).
2. Guarda una copia de la configuración en `reports/<fecha-hora>/backups/`.
3. Aplica **solo** los comandos de los controles que fallan.
4. Guarda la configuración (`write memory` en Cisco; el FortiGate la guarda al aplicar cada cambio).
5. Vuelve a evaluar (estado **después**) y escribe `informe-apply.md` y `informe-apply.json`.

Pide también el nuevo `enable secret` (M-03). Los controles sin remediación automática (por ejemplo, crear el usuario local, M-02) quedan como `MANUAL` en el informe. Si algún comando es rechazado por el equipo, el error aparece en la columna **Observación**.

Para ver los porcentajes después del hardening:

```bash
grep -H "Cumplimiento" reports/*/informe-apply.md
```

> Ver evidencia: [10_script_apply.png](screenshots/10_script_apply.png), [11_informe_apply.png](screenshots/11_informe_apply.png)

---

### Paso 10. Exportar configuraciones finales y comparar resultados

**10.1 — Exportar las configuraciones finales**

```bash
cd ~/cis-lab && source ~/cis/bin/activate
python3 scripts/exportar_configs.py post
```

Genera `post-r-cis-running-config.txt` y `post-sw-cis-running-config.txt`. Para el firewall, repetir el respaldo desde la GUI (**Configuration → Backup**) como `running-configs/post-fw-cis-config.conf`.

**10.2 — Comparar antes y después**

Los porcentajes salen del informe póstumo `informe-apply.md` del Paso 9, que muestra el estado de cada control antes y después:

| Equipo | % de cumplimiento (antes) | % de cumplimiento (después) |
|---|---|---|
| R-CIS | `TODO` | `TODO` |
| SW-CIS | `TODO` | `TODO` |
| FW-CIS | `TODO` | `TODO` |

> Es normal que el porcentaje no llegue al 100 %: el laboratorio aplica los controles elegidos (sección 3) y no todo el benchmark. Los controles marcados `MANUAL` requieren una acción del administrador.

Para ver qué cambió realmente en cada equipo:

```bash
diff reports/*/backups/R-CIS-pre.cfg reports/*/backups/R-CIS-post.cfg | head -60
```

> Ver evidencia: [12_configs_finales.png](screenshots/12_configs_finales.png)

---

### Paso 11. Pruebas de las recomendaciones aplicadas

**11.1 — Acceso de administración Cisco (M-01, M-06, M-09, M-10)**

Desde el **Admin-PC**:

```bash
ssh admin-local@10.7.30.66             # R-CIS: debe entrar y mostrar el banner
ssh admin-local@10.7.30.3              # SW-CIS: debe entrar
nc -zv -w 3 10.7.30.66 23              # Telnet: debe fallar
```

Desde el **PC-Usuario** (`10.7.30.40+`):

```bash
ssh admin-local@10.7.30.66             # debe ser rechazado por la ACL MGMT-ONLY
ping -c 3 10.7.30.3                    # el firewall no permite VLAN 10 → VLAN 99: sin respuesta
```

En el router: `show ip ssh` debe indicar `SSH Enabled - version 2.0` y `show access-lists MGMT-ONLY` debe mostrar contadores de coincidencias.

> Ver evidencia: [13_ssh_admin_ok.png](screenshots/13_ssh_admin_ok.png), [14_telnet_ssh_usuario_denegado.png](screenshots/14_telnet_ssh_usuario_denegado.png)

**11.2 — Servicios apagados (M-13, M-14, C-01, C-02)**

Desde el Admin-PC:

```bash
nmap -Pn -p 22,23,80,443 10.7.30.66 10.7.30.3    # solo 22 abierto
snmpwalk -v2c -c public 10.7.30.66               # sin respuesta (timeout)
```

En los equipos Cisco:

```bash
show cdp                                         # CDP is not enabled
show running-config | include ^no service pad|^no ip source-route|^no ip bootp
```

> Ver evidencia: [15_nmap_despues.png](screenshots/15_nmap_despues.png), [16_snmp_cdp_apagados.png](screenshots/16_snmp_cdp_apagados.png)

**11.3 — Contraseñas, líneas y banners (M-03, M-04, M-05, M-11, M-12)**

```bash
show running-config | include enable|username     # enable secret 9 …, sin "enable password"
show running-config | section line
```

Cerrar la sesión de consola y volver a entrar: se muestra el banner y a los 5 minutos de inactividad la sesión se cierra.

> Ver evidencia: [17_lineas_banner.png](screenshots/17_lineas_banner.png)

**11.4 — Registros (M-15)**

En el router, generar un evento (`configure terminal` → `end`) y un intento SSH fallido desde el Admin-PC. Verificar:

```bash
show logging                                                 # R-CIS: eventos con fecha y hora
sudo tail -n 20 /var/log/syslog | grep -E "R-CIS|SW-CIS|FW-CIS"   # Admin-PC: llegan por syslog
```

> Ver evidencia: [18_logs_router.png](screenshots/18_logs_router.png), [19_syslog_admin.png](screenshots/19_syslog_admin.png)

**11.5 — Data plane (D-01, D-02)**

```bash
show running-config interface Ethernet0/1          # no ip redirects / unreachables / proxy-arp + uRPF
show ip interface Ethernet0/1 | include verify|redirects|unreachables|proxy
```

> Ver evidencia: [20_dataplane_router.png](screenshots/20_dataplane_router.png)

**11.6 — Capa 2 (L-01 a L-04)**

```bash
show interfaces trunk                              # native vlan 999
show interfaces status                             # puertos sin uso en "disabled"
show port-security
show ip dhcp snooping
```

Desde el PC-Usuario, renovar la dirección (`sudo dhclient -r && sudo dhclient`): debe seguir recibiendo IP del firewall (el puerto del trunk es *trusted*).

> Ver evidencia: [21_switch_l2_hardening.png](screenshots/21_switch_l2_hardening.png)

**11.7 — Firewall FortiGate (F-01 a F-12)**

Desde el **Admin-PC**:

```bash
ssh admin@10.7.30.2                                    # F-12: entra y muestra el banner (F-01)
nc -zv -w 3 10.7.30.2 23                               # F-07: Telnet, debe fallar
nc -zv -w 3 10.7.30.2 80                               # F-08: HTTP, debe fallar
nmap -Pn --script ssl-enum-ciphers -p 443 10.7.30.2    # F-03: solo TLS 1.2 y 1.3
snmpwalk -v2c -c public 10.7.30.2                      # F-09: sin respuesta (timeout)
```

Desde el **PC-Usuario**:

```bash
ssh admin@10.7.30.34                                   # F-08/F-12: sin respuesta
```

En la consola del FortiGate (por SSH desde el Admin-PC):

```bash
show full-configuration system global | grep -E "admintimeout|lockout|banner|strong-crypto|ssl-versions|telnet"
show full-configuration system password-policy
show full-configuration system interface port1 | grep allowaccess
show full-configuration firewall policy | grep logtraffic
show full-configuration log syslogd setting
```

**Registros de tráfico por CLI (F-10 y F-11)**

Los registros se leen desde la CLI del firewall, sin usar la GUI. Como la VM no tiene disco de logs (`Log hard disk: Not available`), se guardan en memoria. Primero se activa el registro en memoria:

```bash
config log memory setting
    set status enable
end
```

Se genera tráfico desde el **PC-Usuario**:

```bash
ping -c 3 8.8.8.8
```

Luego, en la CLI del FortiGate, se consultan los registros de la política `LAN-to-Transito`:

```bash
execute log filter device memory
execute log filter category 0
execute log filter field policyid 1
execute log display
```

Cada sesión aparece con `policyname="LAN-to-Transito"`, origen `10.7.30.4x`, destino `8.8.8.8` y `action="accept"`, lo que demuestra F-11 (`logtraffic all`). Los mismos eventos llegan al syslog del Admin-PC (F-10):

```bash
sudo tail -n 20 /var/log/syslog | grep FW-CIS
```

> Ver evidencia: [22_fw_acceso_admin.png](screenshots/22_fw_acceso_admin.png), [23_fw_global_hardening.png](screenshots/23_fw_global_hardening.png), [24_fw_logs_politica.png](screenshots/24_fw_logs_politica.png), [25_fw_snmp_tls.png](screenshots/25_fw_snmp_tls.png)

---

### Paso 12. Exportar las configuraciones

Las running-configs ya quedaron guardadas en `running-configs/`: los archivos `pre-*` (Paso 7, configuración insegura) y los `post-*` (Paso 10, configuración endurecida). Verificar que estén los seis archivos:

```bash
ls running-configs/
```

Subir al repositorio `running-configs/`, `reports/` (informes del script y de Nipper Studio) y `scripts/`.

> Ver evidencia: [26_running_configs.png](screenshots/26_running_configs.png)

---

## 5. El script `cis_hardening.py`

Guardar como `scripts/cis_hardening.py`. Requiere `netmiko`. Los equipos y las IP de gestión están al inicio del archivo.

| Opción | Efecto |
|---|---|
| `--audit` | Solo informe. No envía ningún comando de configuración. |
| `--apply` | Aplica la remediación de los controles que fallan, guarda y genera el informe póstumo. |
| `--user` | Usuario SSH de R-CIS y SW-CIS (por defecto `admin-local`). |
| `--fw-user` | Usuario de FW-CIS (por defecto `admin`). |
| `--devices` | Limita la ejecución a equipos por nombre (por ejemplo `--devices FW-CIS`). |

```python
#!/usr/bin/env python3
"""cis_hardening.py - Auditoría y hardening CIS de R-CIS (router), SW-CIS (switch)
y FW-CIS (FortiGate).

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
    {"name": "R-CIS",  "host": "10.7.30.66", "role": "router",   "type": "cisco_ios"},
    {"name": "SW-CIS", "host": "10.7.30.3",  "role": "switch",   "type": "cisco_ios"},
    {"name": "FW-CIS", "host": "10.7.30.2",  "role": "firewall", "type": "fortinet"},
]
MGMT_HOST = "10.7.30.4"            # Admin-PC: único origen de administración y servidor syslog
SYSLOG = MGMT_HOST
ROUTER_LAN_IF = "Ethernet0/1"      # interfaz del router hacia el firewall (uRPF)
FW_WAN_IF = "port1"                # interfaz del firewall hacia el router/ISP
DOMAIN = "cis.itla.local"
BANNER = "ACCESO RESTRINGIDO. Solo personal autorizado. Toda actividad es registrada."

_enable_secret = None


def get_enable_secret():
    global _enable_secret
    if _enable_secret is None:
        _enable_secret = getpass.getpass("Nuevo enable secret (se guardará con scrypt): ")
    return _enable_secret


# ---------- utilidades: Cisco IOS ----------
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


# ---------- utilidades: FortiGate ----------
def fset(text, key):
    """Valor de 'set <key> <valor>' (primera coincidencia) o None."""
    m = re.search(rf"^\s*set {re.escape(key)} (.+)$", text, re.M)
    return m.group(1).strip().strip('"') if m else None


def fnum(text, key):
    v = fset(text, key)
    return int(v) if v and v.isdigit() else 0


def fblocks(text):
    """Bloques 'edit <nombre>' de primer nivel -> {nombre: {clave: valor}}."""
    out, cur = {}, None
    for line in text.splitlines():
        m = re.match(r'^    edit "?([^"\n]+?)"?\s*$', line)
        if m:
            cur = {}
            out[m.group(1)] = cur
        elif re.match(r"^    next", line):
            cur = None
        elif cur is not None:
            s = re.match(r"^        set (\S+) (.+)$", line)
            if s:
                cur[s.group(1)] = s.group(2).strip()
    return out


# ---------- registro de controles ----------
CHECKS = []


def check(cid, title, plane, roles=("router", "switch")):
    def deco(fn):
        CHECKS.append({"id": cid, "title": title, "plane": plane, "roles": roles, "fn": fn})
        return fn
    return deco


# fn(ctx) -> (ok: bool, detalle: str, remediación: list | callable | None)

# ===== Cisco IOS: Management Plane =====
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


# ===== Cisco IOS: Control Plane =====
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


# ===== Cisco IOS: Data Plane =====
@check("D-01", "Interfaces L3: sin redirects, unreachables ni proxy-arp", "Data")
def _(c):
    need = ["no ip redirects", "no ip unreachables", "no ip proxy-arp"]
    bad = [n for n, l in l3_ifaces(c["cfg"]).items() if not all(x in l for x in need)]
    cmds = []
    for n in bad:
        cmds += [f"interface {n}"] + need + ["exit"]
    return not bad, ", ".join(bad), cmds


@check("D-02", "uRPF en la interfaz del router hacia el firewall", "Data", roles=("router",))
def _(c):
    lines = ifaces(c["cfg"]).get(ROUTER_LAN_IF)
    ok = lines is not None and any(x.startswith("ip verify unicast source reachable-via rx")
                                   for x in lines)
    return ok, "", [f"interface {ROUTER_LAN_IF}", "ip verify unicast source reachable-via rx", "exit"]


# ===== Cisco IOS: capa 2 (complementarios, switch) =====
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


# ===== FortiGate (CIS FortiGate 7.0.x) =====
FW = ("firewall",)


@check("F-01", "Banners de inicio de sesión (pre y post login)", "Firewall", roles=FW)
def _(c):
    g = c["fg"]["global"]
    ok = fset(g, "pre-login-banner") == "enable" and fset(g, "post-login-banner") == "enable"
    return ok, "", [
        "config system global", "set pre-login-banner enable", "set post-login-banner enable", "end",
        'config system replacemsg admin "pre_admin-disclaimer-text"', f'set buffer "{BANNER}"', "end",
        'config system replacemsg admin "post_admin-disclaimer-text"', f'set buffer "{BANNER}"', "end"]


@check("F-02", "Strong crypto habilitado", "Firewall", roles=FW)
def _(c):
    ok = fset(c["fg"]["global"], "strong-crypto") == "enable"
    return ok, "", ["config system global", "set strong-crypto enable", "end"]


@check("F-03", "GUI de administración solo con TLS 1.2 o superior", "Firewall", roles=FW)
def _(c):
    v = fset(c["fg"]["global"], "admin-https-ssl-versions") or ""
    ok = bool(v) and "tlsv1-0" not in v and "tlsv1-1" not in v
    return ok, v, ["config system global", "set admin-https-ssl-versions tlsv1-2 tlsv1-3", "end"]


@check("F-04", "Política de contraseñas de administrador", "Firewall", roles=FW)
def _(c):
    p = c["fg"]["pw"]
    keys = ("min-lower-case-letter", "min-upper-case-letter", "min-number", "min-non-alphanumeric")
    ok = (fset(p, "status") == "enable" and fnum(p, "minimum-length") >= 8
          and all(fnum(p, k) >= 1 for k in keys))
    return ok, "", ["config system password-policy", "set status enable",
                    "set apply-to admin-password", "set minimum-length 8",
                    "set min-lower-case-letter 1", "set min-upper-case-letter 1",
                    "set min-number 1", "set min-non-alphanumeric 1", "end"]


@check("F-05", "Bloqueo de administrador: 3 intentos y 900 s", "Firewall", roles=FW)
def _(c):
    g = c["fg"]["global"]
    ok = fnum(g, "admin-lockout-threshold") == 3 and fnum(g, "admin-lockout-duration") >= 900
    return ok, "", ["config system global", "set admin-lockout-threshold 3",
                    "set admin-lockout-duration 900", "end"]


@check("F-06", "Tiempo de inactividad de administrador <= 5 min", "Firewall", roles=FW)
def _(c):
    t = fnum(c["fg"]["global"], "admintimeout")
    return 0 < t <= 5, "", ["config system global", "set admintimeout 5", "end"]


@check("F-07", "Solo canales de administración cifrados (sin Telnet ni SSH v1)", "Firewall", roles=FW)
def _(c):
    g = c["fg"]["global"]
    ok = fset(g, "admin-telnet") in (None, "disable") and fset(g, "admin-ssh-v1") in (None, "disable")
    return ok, "", ["config system global", "set admin-telnet disable",
                    "set admin-ssh-v1 disable", "end"]


def _fw_iface_fixes(c):
    """Interfaces con servicios de administración inseguros -> {nombre: allowaccess nuevo}."""
    bad = {}
    for name, s in fblocks(c["fg"]["iface"]).items():
        acc = s.get("allowaccess", "").split()
        if not acc:
            continue
        if name == FW_WAN_IF:
            new = ["ping"]
        else:
            new = [a for a in acc if a not in ("http", "telnet")] or ["ping"]
        if acc != new:
            bad[name] = new
    return bad


@check("F-08", "Servicios de administración: sin HTTP/Telnet y solo ping en la interfaz externa",
       "Firewall", roles=FW)
def _(c):
    bad = _fw_iface_fixes(c)
    cmds = ["config system interface"]
    for name, new in bad.items():
        cmds += [f'edit "{name}"', f"set allowaccess {' '.join(new)}", "next"]
    cmds.append("end")
    return not bad, ", ".join(bad), cmds


@check("F-09", "Sin comunidades SNMP v1/v2c y agente apagado", "Firewall", roles=FW)
def _(c):
    comm = fblocks(c["fg"]["snmp"])
    ok = not comm and fset(c["fg"]["snmpinfo"], "status") != "enable"
    cmds = ["config system snmp community"] + [f"delete {k}" for k in comm] + ["end",
            "config system snmp sysinfo", "set status disable", "end"]
    return ok, ", ".join(comm.keys()), cmds


@check("F-10", "Registro remoto (syslog) habilitado", "Firewall", roles=FW)
def _(c):
    s = c["fg"]["syslog"]
    ok = fset(s, "status") == "enable" and MGMT_HOST in (fset(s, "server") or "")
    return ok, "", ["config log syslogd setting", "set status enable", f"set server {SYSLOG}",
                    "set port 514", "end"]


@check("F-11", "Las políticas registran todo el tráfico (logtraffic all)", "Firewall", roles=FW)
def _(c):
    bad = [n for n, s in fblocks(c["fg"]["policy"]).items() if s.get("logtraffic", "utm") != "all"]
    cmds = ["config firewall policy"]
    for n in bad:
        cmds += [f"edit {n}", "set logtraffic all", "next"]
    cmds.append("end")
    return not bad, ", ".join(bad), cmds


@check("F-12", "Hosts de confianza en las cuentas de administrador", "Firewall", roles=FW)
def _(c):
    admins = fblocks(c["fg"]["admin"])
    bad = [n for n, s in admins.items() if s.get("trusthost1", "0.0.0.0 0.0.0.0").startswith("0.0.0.0")]
    cmds = ["config system admin"]
    for n in bad:
        cmds += [f'edit "{n}"', f"set trusthost1 {MGMT_HOST} 255.255.255.255", "next"]
    cmds.append("end")
    return not bad, ", ".join(bad), cmds


# ---------- ejecución ----------
FG_SECTIONS = {
    "global": "show full-configuration system global",
    "pw": "show full-configuration system password-policy",
    "iface": "show full-configuration system interface",
    "admin": "show full-configuration system admin",
    "snmp": "show full-configuration system snmp community",
    "snmpinfo": "show full-configuration system snmp sysinfo",
    "syslog": "show full-configuration log syslogd setting",
    "policy": "show full-configuration firewall policy",
}


def get_ctx(conn, role):
    if role == "firewall":
        return {"cfg": conn.send_command("show", read_timeout=120),
                "fg": {k: conn.send_command(cmd, read_timeout=120) for k, cmd in FG_SECTIONS.items()}}
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


def apply_fix(conn, dtype, fix):
    cmds = fix() if callable(fix) else fix
    chunk, out = [], ""
    for cmd in cmds:
        if cmd == "@genkey":
            if chunk:
                out += conn.send_config_set(chunk)
                chunk = []
            gen_key(conn)
        else:
            chunk.append(cmd)
    if chunk:
        if dtype == "fortinet":
            out += conn.send_config_set(chunk, cmd_verify=False)
        else:
            out += conn.send_config_set(chunk)
    return out


def errors_in(output, dtype):
    if dtype == "fortinet":
        keys = ("command fail", "parse error", "unknown action", "node_check_object fail",
                "invalid", "value parse error")
        return [l.strip() for l in output.splitlines() if any(k in l.lower() for k in keys)]
    return [l.strip() for l in output.splitlines() if l.startswith("%")]


def status(pre, post=None):
    if post is None:
        return "PASS" if pre["ok"] else "FAIL"
    if pre["ok"]:
        return "PASS"
    if post["ok"]:
        return "CORREGIDO"
    return "MANUAL" if pre["fix"] is None else "FALLA"


def write_report(outdir, mode, results, notes):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    md = [f"# Informe CIS ({mode})", f"Generado: {ts}", ""]
    js = {}
    for name, (pre, post) in results.items():
        md += [f"## {name}", ""]
        if post:
            md += ["| ID | Control | Antes | Después | Observación |", "|---|---|---|---|---|"]
            for a, b in zip(pre, post):
                obs = notes.get(name, {}).get(a["id"], "")
                md.append(f"| {a['id']} | {a['title']} | {'PASS' if a['ok'] else 'FAIL'} "
                          f"| {status(a, b)} | {obs} |")
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
    ap = argparse.ArgumentParser(description="Auditoría y hardening CIS: router, switch y firewall")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--audit", action="store_true", help="solo informe, sin aplicar reglas")
    g.add_argument("--apply", action="store_true", help="aplicar reglas e informe póstumo")
    ap.add_argument("--user", default="admin-local", help="usuario de R-CIS y SW-CIS")
    ap.add_argument("--fw-user", default="admin", help="usuario de FW-CIS")
    ap.add_argument("--devices", nargs="*", help="nombres de equipos (por defecto, todos)")
    args = ap.parse_args()

    mode = "apply" if args.apply else "audit"
    outdir = Path("reports") / datetime.now().strftime("%Y%m%d-%H%M%S")
    (outdir / "backups").mkdir(parents=True, exist_ok=True)

    selected = [d for d in DEVICES if not args.devices or d["name"] in args.devices]
    creds = {}
    if any(d["type"] == "cisco_ios" for d in selected):
        creds["cisco_ios"] = (args.user, getpass.getpass(f"Contraseña de {args.user} (R-CIS y SW-CIS): "))
    if any(d["type"] == "fortinet" for d in selected):
        creds["fortinet"] = (args.fw_user, getpass.getpass(f"Contraseña de {args.fw_user} (FW-CIS): "))

    results, notes = {}, {}
    for dev in selected:
        print(f"[*] {dev['name']} ({dev['host']}) ...")
        user, pw = creds[dev["type"]]
        conn = ConnectHandler(device_type=dev["type"], host=dev["host"], username=user, password=pw)
        ctx = get_ctx(conn, dev["role"])
        pre = evaluate(ctx, dev["role"])
        post = None
        if args.apply:
            (outdir / "backups" / f"{dev['name']}-pre.cfg").write_text(ctx["cfg"])
            notes[dev["name"]] = {}
            for r in pre:
                if not r["ok"] and r["fix"]:
                    print(f"    aplicando {r['id']}: {r['title']}")
                    errs = errors_in(apply_fix(conn, dev["type"], r["fix"]), dev["type"])
                    if errs:
                        notes[dev["name"]][r["id"]] = "; ".join(errs)
            if dev["type"] == "cisco_ios":
                conn.save_config()
            ctx2 = get_ctx(conn, dev["role"])
            (outdir / "backups" / f"{dev['name']}-post.cfg").write_text(ctx2["cfg"])
            post = evaluate(ctx2, dev["role"])
        conn.disconnect()
        results[dev["name"]] = (pre, post)

    write_report(outdir, mode, results, notes)
    print(f"[+] Informe en {outdir}/informe-{mode}.md")


if __name__ == "__main__":
    main()
```

> **Notas de uso:**
> * Si el SSH de IOS viejo no negocia con las versiones actuales de OpenSSH/Paramiko, revisar los algoritmos permitidos (ver la nota del Paso 6).
> * La comprobación M-08 (tamaño de la clave RSA) es una heurística sobre el `Key Data`; se confirma a mano con `show crypto key mypubkey rsa`.
> * Las remediaciones M-09 y M-10 (Cisco) y F-12 (FortiGate) se ejecutan sobre una sesión ya abierta: el cambio no la cierra, pero las conexiones nuevas desde otro origen sí se rechazan.
> * El FortiGate valida la sintaxis de cada comando según su versión de FortiOS; si alguno es rechazado, el script lo muestra en la columna **Observación** del informe.

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
| Todo script utilizado en el repositorio | Carpeta `scripts/` | 5, Paso 7 |
| Running-configs en el repositorio | Carpeta `running-configs/` | Paso 12 |
| Red con un Router, un Switch y un Firewall | `R-CIS`, `SW-CIS` y `FW-CIS` | 2 |
| Herramienta de análisis basada en CIS Benchmark | Script propio `cis_hardening.py` (35 controles del CIS Cisco IOS y del CIS FortiGate 7.0.x) | 5, Pasos 8 y 9 |
| Todo script utilizado en el repositorio | Carpeta `scripts/` | 5, Paso 7 |
| Aplicar recomendaciones de hardening | 35 controles (M, C, D, L y F) | 3, Paso 9 |
| Documentar las recomendaciones y por qué se aplicaron | Tablas 3.1 a 3.5 | 3 |
| Probar las recomendaciones aplicadas | Pruebas 11.1 a 11.7 | Paso 11 |
| Script que escanea los equipos en busca de las recomendaciones | `cis_hardening.py` (router, switch y firewall) | 5 |
| Script: crear informe sin aplicar reglas | Modo `--audit` | Paso 8 |
| Script: aplicar reglas y generar informe póstumo | Modo `--apply` | Paso 9 |
| Direccionamiento basado en la matrícula | `10.7.30.0/24` (matrícula 0730) | 2.2 |

---

## 7. Capturas de Pantalla

Numeradas en el orden en que se toman durante el procedimiento.

| # | Archivo | Paso | Descripción |
|---|---|---|---|
| 01 | [`01_topologia_pnet.png`](screenshots/01_topologia_pnet.png) | 1 | Topología en PNETLab: R-CIS, FW-CIS, SW-CIS y las nubes del ISP, del Admin-PC y del PC-Usuario. |
| 02 | [`02_switch_base.png`](screenshots/02_switch_base.png) | 4 | `show vlan brief` y `show interfaces trunk` del switch con la configuración inicial. |
| 03 | [`03_router_base.png`](screenshots/03_router_base.png) | 3 | `show ip interface brief` y `show ip route` del router. |
| 04 | [`04_firewall_base.png`](screenshots/04_firewall_base.png) | 2 | Interfaces, política y servidor DHCP del firewall con la configuración inicial. |
| 05 | [`05_admin_pc_red.png`](screenshots/05_admin_pc_red.png) | 5 | Admin-PC con `10.7.30.4/27` y syslog escuchando en el puerto 514. |
| 06 | [`06_conectividad.png`](screenshots/06_conectividad.png) | 6 | Pings entre los equipos, salida al ISP y acceso inicial (aún con Telnet). |
| 07 | [`07_configs_iniciales.png`](screenshots/07_configs_iniciales.png) | 7 | `exportar_configs.py pre` y `ls running-configs/` con los archivos `pre-*`. |
| 08 | [`08_script_audit.png`](screenshots/08_script_audit.png) | 8 | Ejecución del script con `--audit`. |
| 09 | [`09_informe_audit.png`](screenshots/09_informe_audit.png) | 8 | Informe sin aplicar reglas: controles en `PASS` y `FAIL`. |
| 10 | [`10_script_apply.png`](screenshots/10_script_apply.png) | 9 | Ejecución del script con `--apply`. |
| 11 | [`11_informe_apply.png`](screenshots/11_informe_apply.png) | 9 | Informe póstumo: estado antes y después de cada control. |
| 12 | [`12_configs_finales.png`](screenshots/12_configs_finales.png) | 10 | `exportar_configs.py post`, tabla antes/después y `diff` de la configuración. |
| 13 | [`13_ssh_admin_ok.png`](screenshots/13_ssh_admin_ok.png) | 11.1 | SSH v2 desde el Admin-PC con el banner de acceso restringido. |
| 14 | [`14_telnet_ssh_usuario_denegado.png`](screenshots/14_telnet_ssh_usuario_denegado.png) | 11.1 | Telnet fallando y SSH denegado desde el PC-Usuario. |
| 15 | [`15_nmap_despues.png`](screenshots/15_nmap_despues.png) | 11.2 | `nmap` con solo el puerto 22 abierto. |
| 16 | [`16_snmp_cdp_apagados.png`](screenshots/16_snmp_cdp_apagados.png) | 11.2 | SNMP sin respuesta y CDP apagado. |
| 17 | [`17_lineas_banner.png`](screenshots/17_lineas_banner.png) | 11.3 | `enable secret`, líneas `con` y `vty` y banner. |
| 18 | [`18_logs_router.png`](screenshots/18_logs_router.png) | 11.4 | `show logging` del router con fecha y hora. |
| 19 | [`19_syslog_admin.png`](screenshots/19_syslog_admin.png) | 11.4 | Eventos recibidos en el servidor syslog del Admin-PC. |
| 20 | [`20_dataplane_router.png`](screenshots/20_dataplane_router.png) | 11.5 | Interfaz hacia el firewall con `no ip redirects`, `no ip unreachables`, `no ip proxy-arp` y uRPF. |
| 21 | [`21_switch_l2_hardening.png`](screenshots/21_switch_l2_hardening.png) | 11.6 | Trunk, puertos sin uso apagados, port-security y DHCP snooping en el switch. |
| 22 | [`22_fw_acceso_admin.png`](screenshots/22_fw_acceso_admin.png) | 11.7 | SSH al firewall con banner; Telnet y HTTP rechazados. |
| 23 | [`23_fw_global_hardening.png`](screenshots/23_fw_global_hardening.png) | 11.7 | Configuración global endurecida del firewall (timeout, bloqueo, banners, strong crypto, TLS). |
| 24 | [`24_fw_logs_politica.png`](screenshots/24_fw_logs_politica.png) | 11.7 | `execute log display` en la CLI del firewall con las sesiones registradas por la política `LAN-to-Transito`. |
| 25 | [`25_fw_snmp_tls.png`](screenshots/25_fw_snmp_tls.png) | 11.7 | SNMP sin respuesta y `nmap` con solo TLS 1.2 y 1.3 en el firewall. |
| 26 | [`26_running_configs.png`](screenshots/26_running_configs.png) | 12 | Carpeta `running-configs/` con los archivos `pre-*` y `post-*`. |

---

## 8. Estructura del Repositorio

```
/
├── README.md                    ← este documento
├── screenshots/                 ← capturas numeradas de cada configuración
├── scripts/
│   ├── fw-cis-base.conf         ← firewall: configuración inicial (insegura)
│   ├── r-cis-base.txt           ← router: configuración inicial (insegura)
│   ├── sw-cis-base.txt          ← switch: configuración inicial (insegura)
│   ├── exportar_configs.py      ← exporta la running-config de router y switch (pre/post)
│   └── cis_hardening.py         ← auditoría (--audit) y hardening (--apply)
├── reports/
│   ├── <fecha-hora>/            ← informes del script
├── running-configs/
│   ├── pre-r-cis-running-config.txt
│   ├── pre-sw-cis-running-config.txt
│   ├── pre-fw-cis-config.conf
│   ├── post-r-cis-running-config.txt
│   ├── post-sw-cis-running-config.txt
│   └── post-fw-cis-config.conf
```

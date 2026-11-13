# Informe CIS (audit)
Generado: 2026-11-13 12:51:16

## R-CIS

| ID | Control | Estado | Detalle |
|---|---|---|---|
| M-01 | AAA habilitado (aaa new-model + login por defecto) | FAIL |  |
| M-02 | Usuario local con secret y sin 'password' en claro | PASS |  |
| M-03 | enable secret tipo 8/9 y sin enable password | FAIL |  |
| M-04 | service password-encryption | FAIL |  |
| M-05 | Banners login y exec | FAIL |  |
| M-06 | SSH versión 2 | FAIL |  |
| M-07 | SSH: time-out <= 60 s y reintentos <= 3 | FAIL |  |
| M-08 | Clave RSA de al menos 2048 bits | FAIL |  |
| M-09 | ACL MGMT-ONLY permite solo al equipo de gestión | FAIL |  |
| M-10 | VTY: solo SSH, exec-timeout <= 5 min y access-class | FAIL |  |
| M-11 | Consola con exec-timeout <= 5 min | FAIL |  |
| M-12 | Puerto auxiliar con 'no exec' | FAIL |  |
| M-13 | Servidor HTTP/HTTPS apagado | FAIL |  |
| M-14 | Sin comunidades SNMP v1/v2c | FAIL | public, private |
| M-15 | Timestamps, logging buffered y syslog remoto | FAIL |  |
| C-01 | Servicios innecesarios apagados (pad, source-route, bootp, domain-lookup) | FAIL |  |
| C-02 | CDP apagado | FAIL |  |
| D-01 | Interfaces L3: sin redirects, unreachables ni proxy-arp | FAIL | Ethernet0/0, Ethernet0/1 |
| D-02 | uRPF en la interfaz del router hacia el firewall | FAIL |  |

**Cumplimiento: 1/19 (5%)**

## SW-CIS

| ID | Control | Estado | Detalle |
|---|---|---|---|
| M-01 | AAA habilitado (aaa new-model + login por defecto) | FAIL |  |
| M-02 | Usuario local con secret y sin 'password' en claro | PASS |  |
| M-03 | enable secret tipo 8/9 y sin enable password | FAIL |  |
| M-04 | service password-encryption | FAIL |  |
| M-05 | Banners login y exec | FAIL |  |
| M-06 | SSH versión 2 | FAIL |  |
| M-07 | SSH: time-out <= 60 s y reintentos <= 3 | FAIL |  |
| M-08 | Clave RSA de al menos 2048 bits | FAIL |  |
| M-09 | ACL MGMT-ONLY permite solo al equipo de gestión | FAIL |  |
| M-10 | VTY: solo SSH, exec-timeout <= 5 min y access-class | FAIL |  |
| M-11 | Consola con exec-timeout <= 5 min | FAIL |  |
| M-12 | Puerto auxiliar con 'no exec' | FAIL |  |
| M-13 | Servidor HTTP/HTTPS apagado | FAIL |  |
| M-14 | Sin comunidades SNMP v1/v2c | FAIL | public, private |
| M-15 | Timestamps, logging buffered y syslog remoto | FAIL |  |
| C-01 | Servicios innecesarios apagados (pad, source-route, bootp, domain-lookup) | FAIL |  |
| C-02 | CDP apagado | FAIL |  |
| D-01 | Interfaces L3: sin redirects, unreachables ni proxy-arp | FAIL | Vlan99 |
| L-01 | Trunks: nonegotiate y VLAN nativa distinta de 1 | FAIL | Ethernet0/0 |
| L-02 | Puertos sin uso (VLAN 999) apagados | FAIL | Ethernet0/3, Ethernet1/0, Ethernet1/1, Ethernet1/2, Ethernet1/3 |
| L-03 | Puertos de acceso: nonegotiate, port-security y bpduguard | FAIL | Ethernet0/1, Ethernet0/2 |
| L-04 | DHCP Snooping en la VLAN 10 con trunk confiable | FAIL |  |

**Cumplimiento: 1/22 (4%)**

## FW-CIS

| ID | Control | Estado | Detalle |
|---|---|---|---|
| F-01 | Banners de inicio de sesión (pre y post login) | FAIL |  |
| F-02 | Strong crypto habilitado | FAIL |  |
| F-03 | GUI de administración solo con TLS 1.2 o superior | PASS | tlsv1-2 |
| F-04 | Política de contraseñas de administrador | FAIL |  |
| F-05 | Bloqueo de administrador: 3 intentos y 900 s | FAIL |  |
| F-06 | Tiempo de inactividad de administrador <= 5 min | FAIL |  |
| F-07 | Solo canales de administración cifrados (sin Telnet ni SSH v1) | FAIL |  |
| F-08 | Servicios de administración: sin HTTP/Telnet y solo ping en la interfaz externa | FAIL | port1, port3, VLAN99 |
| F-09 | Sin comunidades SNMP v1/v2c y agente apagado | FAIL | 1 |
| F-10 | Registro remoto (syslog) habilitado | FAIL |  |
| F-11 | Las políticas registran todo el tráfico (logtraffic all) | FAIL | 1 |
| F-12 | Hosts de confianza en las cuentas de administrador | FAIL | admin |

**Cumplimiento: 1/12 (8%)**

# Informe CIS (apply)
Generado: 2026-11-13 12:56:54

## R-CIS

| ID | Control | Antes | Después | Observación |
|---|---|---|---|---|
| M-01 | AAA habilitado (aaa new-model + login por defecto) | FAIL | CORREGIDO |  |
| M-02 | Usuario local con secret y sin 'password' en claro | PASS | PASS |  |
| M-03 | enable secret tipo 8/9 y sin enable password | FAIL | CORREGIDO |  |
| M-04 | service password-encryption | FAIL | CORREGIDO |  |
| M-05 | Banners login y exec | FAIL | CORREGIDO |  |
| M-06 | SSH versión 2 | FAIL | CORREGIDO |  |
| M-07 | SSH: time-out <= 60 s y reintentos <= 3 | FAIL | FALLA |  |
| M-08 | Clave RSA de al menos 2048 bits | FAIL | CORREGIDO |  |
| M-09 | ACL MGMT-ONLY permite solo al equipo de gestión | FAIL | CORREGIDO |  |
| M-10 | VTY: solo SSH, exec-timeout <= 5 min y access-class | FAIL | CORREGIDO |  |
| M-11 | Consola con exec-timeout <= 5 min | FAIL | CORREGIDO |  |
| M-12 | Puerto auxiliar con 'no exec' | FAIL | CORREGIDO |  |
| M-13 | Servidor HTTP/HTTPS apagado | FAIL | CORREGIDO |  |
| M-14 | Sin comunidades SNMP v1/v2c | FAIL | CORREGIDO |  |
| M-15 | Timestamps, logging buffered y syslog remoto | FAIL | CORREGIDO |  |
| C-01 | Servicios innecesarios apagados (pad, source-route, bootp, domain-lookup) | FAIL | CORREGIDO |  |
| C-02 | CDP apagado | FAIL | CORREGIDO |  |
| D-01 | Interfaces L3: sin redirects, unreachables ni proxy-arp | FAIL | CORREGIDO |  |
| D-02 | uRPF en la interfaz del router hacia el firewall | FAIL | CORREGIDO |  |

**Cumplimiento: 1/19 → 18/19 (94%)**

## SW-CIS

| ID | Control | Antes | Después | Observación |
|---|---|---|---|---|
| M-01 | AAA habilitado (aaa new-model + login por defecto) | FAIL | CORREGIDO |  |
| M-02 | Usuario local con secret y sin 'password' en claro | PASS | PASS |  |
| M-03 | enable secret tipo 8/9 y sin enable password | FAIL | CORREGIDO |  |
| M-04 | service password-encryption | FAIL | CORREGIDO |  |
| M-05 | Banners login y exec | FAIL | CORREGIDO |  |
| M-06 | SSH versión 2 | FAIL | CORREGIDO |  |
| M-07 | SSH: time-out <= 60 s y reintentos <= 3 | FAIL | FALLA |  |
| M-08 | Clave RSA de al menos 2048 bits | FAIL | CORREGIDO |  |
| M-09 | ACL MGMT-ONLY permite solo al equipo de gestión | FAIL | CORREGIDO |  |
| M-10 | VTY: solo SSH, exec-timeout <= 5 min y access-class | FAIL | CORREGIDO |  |
| M-11 | Consola con exec-timeout <= 5 min | FAIL | CORREGIDO |  |
| M-12 | Puerto auxiliar con 'no exec' | FAIL | CORREGIDO |  |
| M-13 | Servidor HTTP/HTTPS apagado | FAIL | CORREGIDO |  |
| M-14 | Sin comunidades SNMP v1/v2c | FAIL | CORREGIDO |  |
| M-15 | Timestamps, logging buffered y syslog remoto | FAIL | CORREGIDO |  |
| C-01 | Servicios innecesarios apagados (pad, source-route, bootp, domain-lookup) | FAIL | CORREGIDO |  |
| C-02 | CDP apagado | FAIL | CORREGIDO |  |
| D-01 | Interfaces L3: sin redirects, unreachables ni proxy-arp | FAIL | CORREGIDO |  |
| L-01 | Trunks: nonegotiate y VLAN nativa distinta de 1 | FAIL | CORREGIDO |  |
| L-02 | Puertos sin uso (VLAN 999) apagados | FAIL | CORREGIDO |  |
| L-03 | Puertos de acceso: nonegotiate, port-security y bpduguard | FAIL | CORREGIDO | %Warning: portfast should only be enabled on ports connected to a single; %Portfast has been configured on Ethernet0/1 but will only; %Warning: portfast should only be enabled on ports connected to a single; %Portfast has been configured on Ethernet0/2 but will only |
| L-04 | DHCP Snooping en la VLAN 10 con trunk confiable | FAIL | CORREGIDO |  |

**Cumplimiento: 1/22 → 21/22 (95%)**

## FW-CIS

| ID | Control | Antes | Después | Observación |
|---|---|---|---|---|
| F-01 | Banners de inicio de sesión (pre y post login) | FAIL | CORREGIDO |  |
| F-02 | Strong crypto habilitado | FAIL | FALLA | command parse error before 'strong-crypto'; Command fail. Return code -61 |
| F-03 | GUI de administración solo con TLS 1.2 o superior | PASS | PASS |  |
| F-04 | Política de contraseñas de administrador | FAIL | CORREGIDO |  |
| F-05 | Bloqueo de administrador: 3 intentos y 900 s | FAIL | CORREGIDO |  |
| F-06 | Tiempo de inactividad de administrador <= 5 min | FAIL | CORREGIDO |  |
| F-07 | Solo canales de administración cifrados (sin Telnet ni SSH v1) | FAIL | CORREGIDO |  |
| F-08 | Servicios de administración: sin HTTP/Telnet y solo ping en la interfaz externa | FAIL | CORREGIDO |  |
| F-09 | Sin comunidades SNMP v1/v2c y agente apagado | FAIL | CORREGIDO |  |
| F-10 | Registro remoto (syslog) habilitado | FAIL | CORREGIDO |  |
| F-11 | Las políticas registran todo el tráfico (logtraffic all) | FAIL | CORREGIDO |  |
| F-12 | Hosts de confianza en las cuentas de administrador | FAIL | CORREGIDO |  |

**Cumplimiento: 1/12 → 11/12 (91%)**

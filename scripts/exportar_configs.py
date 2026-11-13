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

# Habilita algoritmos SSH antiguos para Cisco IOS 15.x (IOL) en Paramiko moderno
LEGACY_SSH = {
    "disabled_algorithms": {"pubkeys": [], "kex": [], "ciphers": [], "macs": []},
}

if len(sys.argv) != 2 or sys.argv[1] not in ("pre", "post"):
    sys.exit("Uso: exportar_configs.py <pre|post>")

fase = sys.argv[1]
out = Path("running-configs")
out.mkdir(exist_ok=True)
user = input("Usuario [admin-local]: ") or "admin-local"
password = getpass.getpass("Contraseña: ")

for name, host in DEVICES.items():
    conn = ConnectHandler(
        device_type="cisco_ios",
        host=host,
        username=user,
        password=password,
        **LEGACY_SSH,
    )
    (out / f"{fase}-{name}-running-config.txt").write_text(conn.send_command("show running-config"))
    conn.disconnect()
    print(f"[+] {name} exportado")

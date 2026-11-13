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

#!/usr/bin/env python3
"""hubnets — redes y configuración de cada cliente del hub VPN.

Red MANUAL   : definida en MAP="virtual=real ..." del conf. Se crea, borra, desactiva (prefijo "!") y reactiva.
Red DINÁMICA : la anuncia la VPN (rutas por ppp/tun/wg en el namespace). Con AUTO_MAP=1 se mapea sola con la
               convención 10.(200+ID).X.Y. No se borra: se desactiva (va a IGNORE="...") y se reactiva.

  hubnets sync [cliente]                aplica NETMAP, rutas del hub, rutas del túnel y DNS (todos si no se indica)
  hubnets list <cliente> [--json]       redes efectivas
  hubnets add <cliente> <real> [virt]   crea/edita una red manual
  hubnets del <cliente> <real>          borra una red manual
  hubnets off <cliente> <real>          desactiva una red (manual o dinámica)
  hubnets on <cliente> <real>           reactiva una red (manual o dinámica)
  hubnets auto <cliente> on|off         mapeo automático de dinámicas
  hubnets count <cliente>               cantidad de redes activas
"""
import fcntl
import ipaddress as ipa
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

ETC = Path("/etc/vpnhub")
CLIENTES = ETC / "clientes"
SECRETS_DIR = ETC / "secrets"
RUN = Path("/run/vpnhub")
HUB_DNS = Path("/etc/dnsmasq.d/vpnhub.conf")
HUB_HOSTS = ETC / "hosts"
CONFLICTS_FILE = RUN / "conflicts.json"
OVERRIDE_FILE = RUN / "override_routes.json"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,30}$")
FIELDS = ["ID", "TYPE", "SERVER", "PORT", "TRUSTED_CERT", "AUTHGROUP", "MAP", "DIRECT", "CHECK_IP", "HOSTS",
          "DNS_SERVER", "DOMAINS", "OTP_REQUIRED", "AUTO_MAP", "IGNORE", "OWNER", "CREATED_BY", "DESCRIPTION",
          "DISABLED", "DISABLED_BY", "DNS_ALIAS", "IKE_VERSION", "DHGROUP"]
# OWNER vacío = VPN general; OWNER=<usuario> = VPN personal de ese usuario. CREATED_BY = quien la creó.
TRANSIT = ipa.ip_network("100.64.0.0/16")
ROUTE_PROTO = "77"   # marca de las rutas que hubnets agrega dentro del namespace


class HubError(Exception):
    pass


def sh(*args, check=False, timeout=20):
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode:
        raise HubError(f"{' '.join(args)}: {r.stderr.strip()}")
    return r


def net(s):
    try:
        return ipa.ip_network(str(s).strip(), strict=False)
    except ValueError as e:
        raise HubError(f"red inválida: {s}") from e


# ================= configuración =================
def clients():
    return sorted(p.stem for p in CLIENTES.glob("*.conf") if NAME_RE.match(p.stem))


def load(c):
    if not NAME_RE.match(c or "") or not (CLIENTES / f"{c}.conf").exists():
        raise HubError(f"cliente inexistente: {c}")
    script = 'source "$1"; for v in ' + " ".join(FIELDS) + '; do printf "%s\\0" "${!v}"; done'
    r = subprocess.run(["bash", "-c", script, "_", str(CLIENTES / f"{c}.conf")],
                       capture_output=True, text=True, timeout=5)
    vals = r.stdout.split("\0")
    cfg = {k: (vals[i].strip() if i < len(vals) else "") for i, k in enumerate(FIELDS)}
    cfg.update(name=c, id=int(cfg["ID"] or 0), ns=f"vpn-{c}")
    cfg.update(vh=f"vh{cfg['id']}", ns_ip=f"100.64.{cfg['id']}.2", auto=cfg["AUTO_MAP"] != "0")
    return cfg


def pairs(s):
    return [tuple(t.split("=", 1)) for t in s.split() if "=" in t]


def manual_list(cfg):
    """[(virtual, real, activa)] desde MAP; '!' adelante = desactivada."""
    out = []
    for t in cfg["MAP"].split():
        on = not t.startswith("!")
        t = t.lstrip("!")
        if "=" in t:
            v, r = t.split("=", 1)
            out.append((str(net(v)), str(net(r)), on))
    return out


def write_manual(c, items):
    set_var(c, "MAP", "\n     ".join(f"{'' if on else '!'}{v}={r}" for v, r, on in items))


def set_var(c, var, value):
    p = CLIENTES / f"{c}.conf"
    s = p.read_text()
    line = f'{var}="{value}"'
    pat = re.compile(rf'^{var}=(?:"[^"]*"|[^\n]*)', re.M)
    s = pat.sub(lambda m: line, s, count=1) if pat.search(s) else s.rstrip("\n") + "\n" + line + "\n"
    tmp = p.with_suffix(".conf.tmp")
    tmp.write_text(s)
    os.chmod(tmp, 0o644)
    os.replace(tmp, p)


# ================= red =================
def lan():
    dev = json.loads(sh("ip", "-j", "route", "show", "default").stdout or "[{}]")[0].get("dev", "eth0")
    info = json.loads(sh("ip", "-j", "-4", "addr", "show", "dev", dev).stdout or "[]")
    a = info[0]["addr_info"][0] if info and info[0].get("addr_info") else None
    return dev, (ipa.ip_interface(f"{a['local']}/{a['prefixlen']}") if a else None)


def ns_exists(cfg):
    return Path(f"/run/netns/{cfg['ns']}").exists()


def tunnel_iface(cfg):
    if not ns_exists(cfg):
        return None
    for itf in json.loads(sh("ip", "-n", cfg["ns"], "-j", "link").stdout or "[]"):
        if re.match(r"^(ppp|tun|wg|ipsec)", itf.get("ifname", "")) and "UP" in itf.get("flags", []):
            return itf["ifname"]
    return None


def ns_routes(cfg):
    if not ns_exists(cfg):
        return []
    return json.loads(sh("ip", "-n", cfg["ns"], "-j", "-4", "route").stdout or "[]")


def dst_net(r):
    d = r.get("dst", "")
    return net(d if "/" in d else d + "/32")


def dynamic(cfg):
    """Redes que anuncia la VPN (rutas por la interfaz del túnel dentro del namespace)."""
    out = set()
    for rt in ns_routes(cfg):
        if not re.match(r"^(ppp|tun|wg|ipsec)", rt.get("dev", "")) or rt.get("dst") == "default":
            continue
        if str(rt.get("protocol")) == ROUTE_PROTO:     # rutas que puso hubnets para redes manuales
            continue
        try:
            n = dst_net(rt)
        except HubError:
            continue
        if n.prefixlen < 8 or int(n.network_address) == 0:   # 0/1, 128/1 (túnel completo), 0.0.0.0/32
            continue
        out.add(n)
    return sorted(out, key=lambda n: (n.prefixlen, int(n.network_address)))


def convention(cfg, real):
    """IP real -> 10.(200+ID).X.Y conservando 3er y 4to octeto (solo prefijos >= /16)."""
    if real.prefixlen < 16 or 200 + cfg["id"] > 255:
        return None
    o = real.network_address.packed
    return net(f"10.{200 + cfg['id']}.{o[2]}.{o[3]}/{real.prefixlen}")


def other_virtuals(c):
    used = []
    for o in clients():
        if o == c:
            continue
        try:
            ents = json.loads((RUN / f"{o}.map").read_text())
        except (OSError, ValueError):
            try:
                ents = [{"virtual": v, "state": "activa"} for v, _, on in manual_list(load(o)) if on]
            except HubError:
                ents = []
        used += [net(e["virtual"]) for e in ents if e.get("state") == "activa" and e.get("virtual")]
    return used


def reserved():
    _, l = lan()
    return [TRANSIT] + ([l.network] if l else [])


def effective(cfg, others=None):
    others = other_virtuals(cfg["name"]) if others is None else others
    dyn = dynamic(cfg)
    ignore = {str(net(x)) for x in cfg["IGNORE"].split()}
    ents, used = [], list(others)
    full = any(r.get("dst") == "0.0.0.0/1" and re.match(r"^(ppp|tun|wg|ipsec)", r.get("dev", ""))
               for r in ns_routes(cfg))          # túnel completo: la VPN alcanza todo

    for v, r, on in manual_list(cfg):
        vn, rn = net(v), net(r)
        e = {"real": r, "virtual": v, "origin": "manual", "enabled": on,
             "pushed": full or any(rn.subnet_of(d) or d.subnet_of(rn) for d in dyn), "state": "activa"}
        if not on:
            e["state"] = "desactivada"
        elif any(vn.overlaps(u) for u in used):
            e.update(state="conflicto", note="la red virtual se superpone con otra en uso")
        else:
            used.append(vn)
        ents.append(e)
    for d in cfg["DIRECT"].split():
        dn = net(d)
        ents.append({"real": str(dn), "virtual": str(dn), "origin": "manual", "direct": True, "enabled": True,
                     "pushed": any(dn.subnet_of(x) or x.subnet_of(dn) for x in dyn), "state": "activa"})
        used.append(dn)

    for n in dyn:
        if any(n.subnet_of(net(e["real"])) for e in ents if e["state"] == "activa"):
            continue                      # ya cubierta por otra red activa (ej. /32 dentro de un /24)
        if any(net(e["real"]) == n for e in ents):
            continue                      # hay una manual (desactivada) para esa misma red: manda la manual
        e = {"real": str(n), "virtual": None, "origin": "dinamica", "pushed": True, "enabled": str(n) not in ignore}
        if not e["enabled"]:
            e["state"] = "desactivada"
            v = convention(cfg, n)
            e["virtual"] = str(v) if v else None
        elif not cfg["auto"]:
            e["state"] = "sin mapear"
        else:
            v = convention(cfg, n)
            if v is None:
                e.update(state="no mapeable", note=f"/{n.prefixlen} es muy grande: creá una manual con su red virtual")
            elif any(v.overlaps(u) for u in used):
                e.update(state="conflicto", virtual=str(v), note="su red virtual ya está en uso: creá una manual con otra")
            else:
                e.update(state="activa", virtual=str(v))
                used.append(v)
        ents.append(e)

    for x in sorted(ignore - {str(d) for d in dyn}):
        ents.append({"real": x, "virtual": None, "origin": "dinamica", "pushed": False, "enabled": False,
                     "state": "desactivada", "note": "la VPN no la anuncia ahora"})
    return ents


def virt_of(ip, ents):
    a = ipa.ip_address(ip)
    for e in ents:
        if e["state"] != "activa":
            continue
        r, v = net(e["real"]), net(e["virtual"])
        if a in r:
            return str(ipa.ip_address(int(v.network_address) | (int(a) & int(r.hostmask))))
    return None


# ================= aplicar =================
def apply_client(cfg, ents):
    act = [e for e in ents if e["state"] == "activa"]
    ns, vh = cfg["ns"], cfg["vh"]
    if ns_exists(cfg):
        want = [f"-A PREROUTING -d {e['virtual']} -i vn{cfg['id']} -j NETMAP --to {e['real']}"
                for e in act if not e.get("direct")]
        cur = [l for l in sh("ip", "netns", "exec", ns, "iptables", "-t", "nat", "-S", "PREROUTING").stdout.splitlines()
               if l.startswith("-A ")]
        if cur != want:
            sh("ip", "netns", "exec", ns, "iptables", "-t", "nat", "-F", "PREROUTING", check=True)
            for rule in want:
                sh("ip", "netns", "exec", ns, "iptables", "-t", "nat", *rule.split(), check=True)

        # rutas por el túnel para redes manuales que la VPN no anuncia (ej. L2TP)
        tun = tunnel_iface(cfg)
        routes = ns_routes(cfg)
        ours = {str(dst_net(r)) for r in routes if str(r.get("protocol")) == ROUTE_PROTO}
        vpn_nets = [dst_net(r) for r in routes if str(r.get("protocol")) != ROUTE_PROTO
                    and re.match(r"^(ppp|tun|wg|ipsec)", r.get("dev", "")) and r.get("dst") != "default"]
        want_rt = set()
        if tun:
            for e in act:
                rn = net(e["real"])
                if e["origin"] == "manual" and not any(rn.subnet_of(x) for x in vpn_nets):
                    want_rt.add(str(rn))
        for d in ours - want_rt:
            sh("ip", "-n", ns, "route", "del", d, "proto", ROUTE_PROTO)
        for d in want_rt - ours:
            sh("ip", "-n", ns, "route", "replace", d, "dev", tun, "proto", ROUTE_PROTO)

    if Path(f"/sys/class/net/{vh}").exists():
        cur = {r["dst"] for r in json.loads(sh("ip", "-j", "-4", "route", "show", "dev", vh).stdout or "[]")
               if r.get("protocol") != "kernel"}
        want = {e["virtual"] for e in act}
        for d in cur - want:
            sh("ip", "route", "del", d, "dev", vh)
        for d in want - cur:
            sh("ip", "route", "replace", d, "via", cfg["ns_ip"], "dev", vh, check=True)
    RUN.mkdir(mode=0o700, exist_ok=True)
    (RUN / f"{cfg['name']}.map").write_text(json.dumps(ents))
    apply_ns_dns(cfg, act)


def apply_ns_dns(cfg, act):
    """dnsmasq dentro del namespace (vpnhub-dns@): reenvía DOMAINS al DNS del cliente y reescribe IPs."""
    c = cfg["name"]
    unit = f"vpnhub-dns@{c}.service"
    path = RUN / f"{c}.dnsmasq"
    if not (cfg["DNS_SERVER"] and cfg["DOMAINS"] and ns_exists(cfg)):
        if path.exists():
            sh("systemctl", "stop", unit)
            path.unlink(missing_ok=True)
        return
    lines = [f"listen-address={cfg['ns_ip']}", "bind-interfaces", "no-resolv", "no-hosts",
             f"server={cfg['DNS_SERVER']}", "cache-size=500"]
    for e in act:
        if not e.get("direct"):
            r, v = net(e["real"]), net(e["virtual"])
            lines.append(f"alias={r.network_address},{v.network_address},{r.netmask}")
    new = "\n".join(lines) + "\n"
    old = path.read_text() if path.exists() else ""
    if new != old:
        path.write_text(new)
        sh("systemctl", "restart", unit)
    elif sh("systemctl", "is-active", unit).stdout.strip() != "active":
        sh("systemctl", "start", unit)


def apply_hub_dns(all_ents):
    dev, l = lan()
    out = ["# Generado por hubnets — no editar a mano", f"interface={dev}", "bind-dynamic", "no-resolv",
           "domain-needed", "server=1.1.1.1", "server=8.8.8.8", "cache-size=2000", "local=/hub/",
           f"addn-hosts={HUB_HOSTS}"]
    if Path("/sys/class/net/wg0").exists():
        out.append("interface=wg0")
    if l:
        out.append(f"host-record=vpnhub.hub,{l.ip}")
        out.append(f"host-record=vpnhub,{l.ip}")

    hosts_lines = ["# Hosts estaticos y sinteticos de VPN Hub"]
    if l:
        hosts_lines.append(f"{l.ip} vpnhub.hub vpnhub")

    local_domains = set()

    for c, (cfg, ents) in all_ents.items():
        alias = cfg.get("DNS_ALIAS", "").strip() or c
        local_domains.add(f"/{c}/")
        if alias != c:
            local_domains.add(f"/{alias}/")

        out.append(f"# --- {c} (ID {cfg['id']})")
        # HOSTS manuales (ej. router-a.cliente.hub)
        for n, r in pairs(cfg["HOSTS"]):
            v = virt_of(r, ents)
            if v:
                out.append(f"host-record={n}.{c}.hub,{v}")
                h_names = [f"{n}.{c}.hub", f"{n}.{c}"]
                if alias != c:
                    h_names += [f"{n}.{alias}.hub", f"{n}.{alias}"]
                hosts_lines.append(f"{v} {' '.join(h_names)}")
            else:
                out.append(f"# {n}={r}: su red no está mapeada")

        # Resolucion sintetica para cada red activa del cliente (<real_ip>.<alias>)
        for e in ents:
            if e["state"] == "activa" and e.get("virtual") and not e.get("direct"):
                try:
                    rnet = net(e["real"])
                    vnet = net(e["virtual"])
                    if 16 <= rnet.prefixlen <= 32:
                        r_base = int(rnet.network_address)
                        v_base = int(vnet.network_address)
                        alias_names = [alias] if alias == c else [alias, c]
                        for i in range(rnet.num_addresses):
                            r_int = r_base + i
                            v_int = v_base + i
                            rip = f"{(r_int>>24)&255}.{(r_int>>16)&255}.{(r_int>>8)&255}.{r_int&255}"
                            vip = f"{(v_int>>24)&255}.{(v_int>>16)&255}.{(v_int>>8)&255}.{v_int&255}"
                            names = []
                            for a in alias_names:
                                names.append(f"{rip}.{a}")
                                names.append(f"{rip}.{a}.hub")
                            hosts_lines.append(f"{vip} {' '.join(names)}")
                except Exception:
                    pass

        if cfg["DNS_SERVER"] and cfg["DOMAINS"]:
            out += [f"server=/{d}/{cfg['ns_ip']}" for d in cfg["DOMAINS"].split()]

    for ld in sorted(local_domains):
        out.append(f"local={ld}")

    # Guardar /etc/dnsmasq.d/vpnhub-hosts
    RUN.mkdir(mode=0o700, exist_ok=True)
    HUB_HOSTS.parent.mkdir(parents=True, exist_ok=True)
    new_hosts = "\n".join(hosts_lines) + "\n"
    if not HUB_HOSTS.exists() or HUB_HOSTS.read_text() != new_hosts:
        HUB_HOSTS.write_text(new_hosts)
        # SIGHUP recarga addn-hosts sin reiniciar dnsmasq
        sh("systemctl", "kill", "-s", "HUP", "dnsmasq")

    new = "\n".join(out) + "\n"
    if not HUB_DNS.exists() or HUB_DNS.read_text() != new:
        tmp = RUN / "hubdns.test"
        tmp.write_text(new)
        if sh("dnsmasq", "--test", f"--conf-file={tmp}").returncode:
            raise HubError("config DNS del hub inválida:\n" + new)
        tmp.unlink()
        HUB_DNS.write_text(new)
        sh("systemctl", "enable", "-q", "dnsmasq")
        sh("systemctl", "restart", "dnsmasq")


def sync_routing_and_conflicts(all_ents):
    """
    Rutas directas a IP real y detección de colisiones.
    Si una red real activa pertenece a una sola VPN conectada, se enruta directo (proto 77).
    Si colisiona en 2+ VPNs conectadas:
      - Se registra en /run/vpnhub/conflicts.json
      - Si hay un override elegido para esa red, se enruta a ese cliente.
      - Si no hay override, se remueve la ruta directa y se activa la regla REDIRECT en iptables
        para que cualquier acceso web (puerto 80) sea capturado por el Portal de Conflicto.
    """
    overrides = {}
    if OVERRIDE_FILE.exists():
        try:
            overrides = json.loads(OVERRIDE_FILE.read_text())
        except Exception:
            overrides = {}

    active_items = []
    for c, (cfg, ents) in all_ents.items():
        if not tunnel_iface(cfg):
            continue
        alias = cfg.get("DNS_ALIAS", "").strip() or c
        for e in ents:
            if e["state"] == "activa" and e.get("virtual") and not e.get("direct"):
                r_net = net(e["real"])
                v_net = net(e["virtual"])
                base_vip = str(v_net.network_address + 1) if r_net.num_addresses > 2 else str(v_net.network_address)
                active_items.append({
                    "client": c,
                    "alias": alias,
                    "vh": cfg["vh"],
                    "ns_ip": cfg["ns_ip"],
                    "real": str(r_net),
                    "real_net": r_net,
                    "virtual": e["virtual"],
                    "base_virtual_ip": base_vip,
                    "desc": cfg.get("DESCRIPTION", "")
                })

    want_routes = {}
    conflicts_data = {}
    conflicting_nets = set()

    unique_nets = {item["real_net"] for item in active_items}

    for target_net in sorted(unique_nets, key=lambda n: n.prefixlen):
        r_str = str(target_net)
        claimants = []
        seen_clients = set()
        for item in active_items:
            if item["client"] not in seen_clients and target_net.subnet_of(item["real_net"]):
                seen_clients.add(item["client"])
                if target_net == item["real_net"]:
                    virt_sub = item["virtual"]
                    vip_sub = item["base_virtual_ip"]
                else:
                    offset = int(target_net.network_address) - int(item["real_net"].network_address)
                    v_base = int(net(item["virtual"]).network_address) + offset
                    v_sub_net = ipa.ip_network(f"{ipa.ip_address(v_base)}/{target_net.prefixlen}")
                    virt_sub = str(v_sub_net)
                    vip_sub = str(v_sub_net.network_address + 1) if v_sub_net.num_addresses > 2 else str(v_sub_net.network_address)

                claimants.append({
                    "client": item["client"],
                    "alias": item["alias"],
                    "vh": item["vh"],
                    "ns_ip": item["ns_ip"],
                    "real": r_str,
                    "virtual": virt_sub,
                    "base_virtual_ip": vip_sub,
                    "desc": item["desc"]
                })

        if len(claimants) == 1:
            item = claimants[0]
            want_routes[r_str] = (item["ns_ip"], item["vh"])
        else:
            conflicting_nets.add(r_str)
            active_override = overrides.get(r_str)
            matched_override = None
            if active_override:
                for item in claimants:
                    if item["client"] == active_override or item["alias"] == active_override:
                        matched_override = item
                        break

            conflicts_data[r_str] = {
                "real": r_str,
                "clients": [{
                    "client": it["client"],
                    "alias": it["alias"],
                    "virtual": it["virtual"],
                    "base_virtual_ip": it["base_virtual_ip"],
                    "desc": it["desc"]
                } for it in claimants],
                "active_override": matched_override["client"] if matched_override else None
            }

            if matched_override:
                want_routes[r_str] = (matched_override["ns_ip"], matched_override["vh"])

    cur_routes = {}
    try:
        r_out = json.loads(sh("ip", "-j", "-4", "route", "show", "proto", ROUTE_PROTO).stdout or "[]")
        for r in r_out:
            dst = r.get("dst")
            if dst:
                cur_routes[dst if "/" in dst else dst + "/32"] = r
    except Exception:
        pass

    unresolved_conflicts = conflicting_nets - set(want_routes.keys())
    allowed_routes = set(want_routes.keys()) | unresolved_conflicts
    for dst in set(cur_routes.keys()) - allowed_routes:
        sh("ip", "route", "del", dst, "proto", ROUTE_PROTO)

    for dst, (via, dev) in want_routes.items():
        if Path(f"/sys/class/net/{dev}").exists():
            sh("ip", "route", "replace", dst, "via", via, "dev", dev, "proto", ROUTE_PROTO)

    for r_str in unresolved_conflicts:
        sh("ip", "route", "replace", "unreachable", r_str, "proto", ROUTE_PROTO)

    sh("iptables", "-t", "nat", "-N", "VPNHUB_CONFLICTS", check=False)
    c_check = sh("iptables", "-t", "nat", "-C", "PREROUTING", "-j", "VPNHUB_CONFLICTS")
    if c_check.returncode != 0:
        sh("iptables", "-t", "nat", "-A", "PREROUTING", "-j", "VPNHUB_CONFLICTS")

    sh("iptables", "-t", "nat", "-F", "VPNHUB_CONFLICTS")
    for r_str in conflicting_nets:
        c_info = conflicts_data.get(r_str, {})
        if not c_info.get("active_override"):
            sh("iptables", "-t", "nat", "-A", "VPNHUB_CONFLICTS", "-d", r_str,
               "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", "80")

    RUN.mkdir(mode=0o700, exist_ok=True)
    CONFLICTS_FILE.write_text(json.dumps(conflicts_data, indent=2))


def sync(only=None):
    """Recalcula y aplica. El DNS del hub siempre se regenera con todos los clientes."""
    all_ents = {}
    for c in clients():
        try:
            cfg = load(c)
            ents = effective(cfg)
            if only is None or c == only:
                apply_client(cfg, ents)
            all_ents[c] = (cfg, ents)
        except HubError as e:
            print(f"AVISO {c}: {e}", file=sys.stderr)
    apply_hub_dns(all_ents)
    sync_routing_and_conflicts(all_ents)
    return all_ents


class Lock:
    def __enter__(self):
        RUN.mkdir(mode=0o700, exist_ok=True)
        self.f = open(RUN / ".hubnets.lock", "w")
        fcntl.flock(self.f, fcntl.LOCK_EX)
        return self

    def __exit__(self, *a):
        fcntl.flock(self.f, fcntl.LOCK_UN)
        self.f.close()


# ================= edición de redes =================
def add(c, real, virtual=None):
    cfg = load(c)
    r = net(real)
    v = net(virtual) if virtual else convention(cfg, r)
    if v is None:
        raise HubError(f"{r} es más grande que /16: indicá la red virtual")
    if v.prefixlen != r.prefixlen:
        raise HubError(f"la virtual ({v}) debe tener el mismo prefijo que la real (/{r.prefixlen})")
    for x in reserved():
        if v.overlaps(x):
            raise HubError(f"la virtual {v} choca con {x} (LAN del hub o tránsito interno)")
    items = [(vv, rr, on) for vv, rr, on in manual_list(cfg) if net(rr) != r]
    mine = [net(vv) for vv, _, on in items if on]
    mine += [net(e["virtual"]) for e in effective(cfg) if e["state"] == "activa" and e["origin"] == "dinamica"
             and not (net(e["real"]) == r or net(e["real"]).subnet_of(r))]
    for u in mine + other_virtuals(c):
        if v.overlaps(u):
            raise HubError(f"la virtual {v} se superpone con {u}, ya en uso")
    items.append((str(v), str(r), True))
    write_manual(c, items)
    return f"manual {r} -> {v} creada"


def delete(c, real):
    cfg = load(c)
    r = net(real)
    items = manual_list(cfg)
    keep = [x for x in items if net(x[1]) != r]
    if len(keep) != len(items):
        write_manual(c, keep)
        return f"manual {r} borrada"
    if r in [net(d) for d in cfg["DIRECT"].split()]:
        set_var(c, "DIRECT", " ".join(d for d in cfg["DIRECT"].split() if net(d) != r))
        return f"directa {r} borrada"
    raise HubError(f"{r} no es una red manual de {c} (las dinámicas no se borran: se desactivan)")


def set_enabled(c, real, on):
    cfg = load(c)
    r = net(real)
    items = manual_list(cfg)
    if any(net(x[1]) == r for x in items):
        write_manual(c, [(v, rr, on if net(rr) == r else en) for v, rr, en in items])
        return f"manual {r} {'activada' if on else 'desactivada'}"
    ign = cfg["IGNORE"].split()
    if on:
        keep = [x for x in ign if net(x) != r]
        if len(keep) == len(ign):
            raise HubError(f"{r} no está desactivada")
        set_var(c, "IGNORE", " ".join(keep))
    else:
        if r not in dynamic(cfg):
            raise HubError(f"{r} no es una red de {c}")
        if str(r) not in ign:
            set_var(c, "IGNORE", " ".join(ign + [str(r)]))
    return f"dinámica {r} {'activada' if on else 'desactivada'}"


def set_auto(c, on):
    load(c)
    set_var(c, "AUTO_MAP", "1" if on else "0")


# ================= tipos de VPN y configuración desde el panel =================
_HOST = r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?"
_IP = r"(\d{1,3}\.){3}\d{1,3}"
FIELD_SPEC = {
    "SERVER": {"label": "Servidor", "re": rf"^{_HOST}$", "ph": "vpn.cliente.com o IP"},
    "PORT": {"label": "Puerto", "re": r"^\d{1,5}$", "ph": "443"},
    "TRUSTED_CERT": {"label": "Certificado confiable (sha256 / pin)", "re": r"^(pin-sha256:[A-Za-z0-9+/=]{40,50}|[0-9a-fA-F]{64})$",
                     "help": "Huella del certificado del servidor (sha256 o pin-sha256). Usá «Obtener» para leerla."},
    "AUTHGROUP": {"label": "Grupo (authgroup)", "re": r"^[A-Za-z0-9 _.-]{1,64}$", "help": "Opcional"},
    "IKE_VERSION": {"label": "Versión IKE", "re": r"^[12]$", "help": "2 = IKEv2 (strongSwan / EAP), 1 = IKEv1 (vpnc / modo agresivo). Por defecto 2", "ph": "2"},
    "DHGROUP": {"label": "Grupo DH", "re": r"^(dh[0-9]+|[0-9]+)?$", "help": "Grupo Diffie-Hellman IKE (ej. dh14, 14, dh5, dh2). Vacío = dh14 por defecto", "ph": "dh14"},
    "OTP_REQUIRED": {"label": "Pide 2FA (OTP)", "re": r"^[01]$", "kind": "bool"},
    "CHECK_IP": {"label": "IP de chequeo (real)", "re": rf"^{_IP}$", "help": "Equipo del cliente que responde ping"},
    "DNS_SERVER": {"label": "DNS interno del cliente", "re": rf"^{_IP}$"},
    "DOMAINS": {"label": "Dominios internos", "re": rf"^{_HOST}( {_HOST})*$", "help": "Separados por espacio"},
    "HOSTS": {"label": "Nombres fijos", "re": rf"^[a-z0-9-]+={_IP}( [a-z0-9-]+={_IP})*$",
              "help": "nombre=IP_real separados por espacio → nombre.<cliente>.hub", "kind": "textarea"},
    "AUTO_MAP": {"label": "Mapear redes dinámicas automáticamente", "re": r"^[01]$", "kind": "bool"},
    "DESCRIPTION": {"label": "Descripción / Comentario", "re": r"^.{0,255}$", "ph": "ej. Servidores Centrales, Sucursal Norte, etc.",
                    "help": "Opcional. Se muestra debajo del nombre en la tarjeta."},
    "DISABLED": {"label": "Deshabilitada", "re": r"^[01]$", "kind": "bool"},
    "DISABLED_BY": {"label": "Deshabilitada por", "re": r"^[a-z0-9_.-]{0,32}$"},
    "DNS_ALIAS": {"label": "Alias DNS", "re": r"^[a-z0-9][a-z0-9_-]{0,31}$", "ph": "ej. sucursal-norte",
                  "help": "Nombre clave corto para DNS (por defecto es el nombre de la VPN)"},
}
SECRET_SPEC = {
    "VPN_USER": {"label": "Usuario", "kind": "text"},
    "VPN_PASS": {"label": "Contraseña", "kind": "password"},
    "VPN_PSK": {"label": "Clave compartida (PSK)", "kind": "password"},
    "VPN_KEYPASS": {"label": "Contraseña de la clave privada", "kind": "password"},
    "WG_CONF": {"label": "Archivo WireGuard (.conf)", "kind": "file", "ext": ".conf"},
    "OVPN": {"label": "Archivo OpenVPN (.ovpn)", "kind": "file", "ext": ".ovpn"},
}
COMMON = ["DNS_ALIAS", "CHECK_IP", "DNS_SERVER", "DOMAINS", "HOSTS", "AUTO_MAP"]
TYPE_SPEC = {
    "forti": {"label": "FortiGate SSL VPN", "fields": ["SERVER", "PORT", "TRUSTED_CERT", "OTP_REQUIRED"],
              "secrets": ["VPN_USER", "VPN_PASS"], "required": ["SERVER", "VPN_USER", "VPN_PASS"],
              "import": "FortiClient: XML exportado (Backup) o .conf"},
    "forti_ipsec": {"label": "FortiGate IPsec (Dialup)", "fields": ["SERVER", "IKE_VERSION", "AUTHGROUP", "DHGROUP"],
                    "secrets": ["VPN_USER", "VPN_PASS", "VPN_PSK"], "required": ["SERVER", "VPN_PSK", "VPN_USER"],
                    "import": "FortiClient IPsec: XML exportado (Backup) o .conf"},
    "anyconnect": {"label": "Cisco AnyConnect", "fields": ["SERVER", "PORT", "AUTHGROUP", "TRUSTED_CERT", "OTP_REQUIRED"],
                   "secrets": ["VPN_USER", "VPN_PASS"], "required": ["SERVER", "VPN_USER", "VPN_PASS"],
                   "import": "Perfil XML de AnyConnect"},
    "openvpn": {"label": "OpenVPN", "fields": [], "secrets": ["OVPN", "VPN_USER", "VPN_PASS", "VPN_KEYPASS"],
                "required": ["OVPN"], "import": "Archivo .ovpn (con certificados embebidos)"},
    "wireguard": {"label": "WireGuard", "fields": [], "secrets": ["WG_CONF"], "required": ["WG_CONF"],
                  "import": "Archivo .conf de WireGuard / MikroTik Back To Home"},
    "l2tp": {"label": "L2TP/IPsec (PSK)", "fields": ["SERVER"], "secrets": ["VPN_USER", "VPN_PASS", "VPN_PSK"],
             "required": ["SERVER", "VPN_USER", "VPN_PASS", "VPN_PSK"],
             "import": "Agenda de Windows (rasphone.pbk)"},
}
DEFAULT_PORT = {"forti": "443", "anyconnect": "443"}


def meta():
    return {"types": TYPE_SPEC, "fields": FIELD_SPEC, "secrets": SECRET_SPEC, "common": COMMON}


def env_path(c):
    return SECRETS_DIR / f"{c}.env"


def file_path(c, key):
    return SECRETS_DIR / (f"{c}.wg" if key == "WG_CONF" else f"{c}.ovpn")


def read_env(c):
    p = env_path(c)
    if not p.exists():
        return {}
    keys = ["VPN_USER", "VPN_PASS", "VPN_PSK", "VPN_KEYPASS"]
    script = 'source "$1"; ' + "".join(f'printf "%s\\0" "${k}"; ' for k in keys)
    r = subprocess.run(["bash", "-c", script, "_", str(p)], capture_output=True, text=True, timeout=5)
    vals = r.stdout.split("\0") + [""] * len(keys)
    return dict(zip(keys, vals))


def file_summary(key, text):
    if key == "WG_CONF":
        eps = re.findall(r"(?im)^\s*Endpoint\s*=\s*(\S+)", text)
        return "endpoint " + ", ".join(eps) if eps else "sin endpoint"
    rem = re.findall(r"(?im)^\s*remote\s+(\S+)(?:\s+(\d+))?", text)
    auth = bool(re.search(r"(?im)^\s*auth-user-pass", text))
    s = ", ".join(f"{h}:{p or '1194'}" for h, p in rem) or "sin remote"
    return s + (" · pide usuario/contraseña" if auth else "") + (" · clave privada cifrada" if key_encrypted(text) else "")


def endpoint_of(c, cfg=None):
    """Devuelve el servidor o endpoint configurado para la VPN (incluyendo WireGuard y OpenVPN)."""
    if cfg is None:
        try:
            cfg = load(c)
        except Exception:
            return ""
    srv = str(cfg.get("SERVER", "") or "").strip().strip('"\'')
    port = str(cfg.get("PORT", "") or "").strip().strip('"\'')
    if srv:
        return f"{srv}:{port}" if port else srv
    typ = cfg.get("TYPE", "")
    if typ == "wireguard":
        p = file_path(c, "WG_CONF")
        if p.exists():
            try:
                txt = p.read_text(errors="ignore")
                eps = re.findall(r"(?im)^\s*Endpoint\s*=\s*(\S+)", txt)
                real_eps = [e for e in eps if ".sn.mynetname.net" not in e]
                return real_eps[0] if real_eps else (eps[0] if eps else "")
            except Exception:
                pass
    elif typ == "openvpn":
        p = file_path(c, "OVPN")
        if p.exists():
            try:
                txt = p.read_text(errors="ignore")
                rem = re.findall(r"(?im)^\s*remote\s+(\S+)(?:\s+(\d+))?", txt)
                if rem:
                    h, port = rem[0]
                    return f"{h}:{port}" if port else h
            except Exception:
                pass
    return ""


def key_encrypted(text):
    m = re.search(r"<key>(.*?)</key>", text, re.S)
    return bool(m and "ENCRYPTED" in m.group(1))


def get_config(c):
    cfg = load(c)
    typ = cfg["TYPE"]
    spec = TYPE_SPEC.get(typ, {"fields": [], "secrets": []})
    fields = {k: " ".join(cfg.get(k, "").split()) for k in spec["fields"] + COMMON}
    fields["AUTO_MAP"] = "0" if cfg["AUTO_MAP"] == "0" else "1"
    fields["DESCRIPTION"] = cfg.get("DESCRIPTION", "")
    fields["DISABLED"] = "1" if cfg.get("DISABLED") == "1" else "0"
    fields["DISABLED_BY"] = cfg.get("DISABLED_BY", "")
    fields["DNS_ALIAS"] = cfg.get("DNS_ALIAS", "")
    env = read_env(c)
    sec = {}
    for k in spec["secrets"]:
        if k == "VPN_USER":
            sec[k] = {"value": env.get(k, "")}                           # el usuario se muestra
        elif SECRET_SPEC[k]["kind"] == "password":
            sec[k] = {"set": bool(env.get(k))}                           # las claves: solo si están cargadas
        else:
            p = file_path(c, k)
            sec[k] = {"set": p.exists(), "summary": file_summary(k, p.read_text()) if p.exists() else ""}
    return {"name": c, "TYPE": typ, "ID": cfg["ID"], "fields": fields, "secrets": sec,
            "label": TYPE_SPEC.get(typ, {}).get("label", typ),
            "owner": cfg.get("OWNER", ""), "created_by": cfg.get("CREATED_BY", ""),
            "description": cfg.get("DESCRIPTION", ""),
            "disabled": cfg.get("DISABLED", "0") == "1",
            "disabled_by": cfg.get("DISABLED_BY", ""),
            "dns_alias": cfg.get("DNS_ALIAS", "").strip() or c}


def _validate_fields(typ, fields):
    allowed = TYPE_SPEC[typ]["fields"] + COMMON + ["DESCRIPTION", "DISABLED", "DISABLED_BY", "DNS_ALIAS"]
    clean = {}
    for k, v in (fields or {}).items():
        if k not in allowed:
            raise HubError(f"campo no válido para {typ}: {k}")
        v = " ".join(str(v).split())
        if v and not re.match(FIELD_SPEC[k]["re"], v):
            raise HubError(f"{FIELD_SPEC[k]['label']}: valor inválido «{v}»")
        if k == "PORT" and v and not 0 < int(v) < 65536:
            raise HubError("puerto fuera de rango")
        try:
            if k in ("CHECK_IP", "DNS_SERVER") and v:
                ipa.ip_address(v)
            if k == "HOSTS" and v:
                for _, ip in pairs(v):
                    ipa.ip_address(ip)
        except ValueError as e:
            raise HubError(f"{FIELD_SPEC[k]['label']}: IP inválida") from e
        clean[k] = v
    return clean


def _validate_file(key, text):
    text = text.replace("\r\n", "\n").strip() + "\n"
    if len(text) > 200_000:
        raise HubError("archivo demasiado grande")
    if key == "WG_CONF":
        if "[Interface]" not in text or "[Peer]" not in text or not re.search(r"(?im)^\s*PrivateKey\s*=", text):
            raise HubError("el .conf de WireGuard debe tener [Interface] con PrivateKey y al menos un [Peer]")
    else:
        if not re.search(r"(?im)^\s*remote\s+\S+", text):
            raise HubError("el .ovpn no tiene ninguna línea «remote»")
        bad = re.findall(r"(?im)^\s*(up|down|route-up|ipchange|client-connect|tls-verify|learn-address|plugin)\s", text)
        if bad:
            raise HubError(f"el .ovpn usa scripts/plugins no permitidos: {', '.join(sorted(set(bad)))}")
        for ref in re.findall(r"(?im)^\s*(?:ca|cert|key|tls-auth|tls-crypt|pkcs12)\s+(\S+)", text):
            if ref.startswith("[") or ref.lower() == "inline":
                continue
            raise HubError(f"el .ovpn referencia el archivo externo «{ref}»: exportalo con los certificados embebidos")
    return text


def save_config(c, fields=None, secrets=None):
    cfg = load(c)
    typ = cfg["TYPE"]
    if typ not in TYPE_SPEC:
        raise HubError(f"tipo desconocido: {typ}")
    clean = _validate_fields(typ, fields)
    files = {}
    for k in TYPE_SPEC[typ]["secrets"]:
        v = (secrets or {}).get(k)
        if v and SECRET_SPEC[k]["kind"] == "file":
            files[k] = _validate_file(k, v)
    for k, v in clean.items():
        set_var(c, k, v)

    SECRETS_DIR.mkdir(mode=0o700, exist_ok=True)
    for k, text in files.items():
        write_secret(file_path(c, k), text)
    env_keys = [k for k in TYPE_SPEC[typ]["secrets"] if SECRET_SPEC[k]["kind"] in ("text", "password")]
    if env_keys:
        env = read_env(c)
        changed = False
        for k in env_keys:
            v = (secrets or {}).get(k)
            if v is None or v == "":
                continue                                     # vacío = no cambiar
            if any(ch in v for ch in "\n\r\0"):
                raise HubError(f"{SECRET_SPEC[k]['label']} no puede tener saltos de línea")
            env[k], changed = v, True
        if changed or not env_path(c).exists():
            write_secret(env_path(c), "".join(f"{k}={shlex.quote(env.get(k, ''))}\n" for k in env_keys))
    return get_config(c)


def missing(c):
    """Lo que falta cargar para poder conectar."""
    g = get_config(c)
    spec = TYPE_SPEC.get(g["TYPE"], {"required": []})
    out = []
    for k in spec["required"]:
        if k in FIELD_SPEC:
            if not g["fields"].get(k):
                out.append(FIELD_SPEC[k]["label"])
        else:
            s = g["secrets"].get(k, {})
            if not (s.get("value") or s.get("set")):
                out.append(SECRET_SPEC[k]["label"])
    summ = g["secrets"].get("OVPN", {}).get("summary", "") if g["TYPE"] == "openvpn" else ""
    need = (["VPN_USER", "VPN_PASS"] if "pide usuario" in summ else []) + (["VPN_KEYPASS"] if "clave privada cifrada" in summ else [])
    if need:
        for k in need:
            s = g["secrets"].get(k, {})
            if not (s.get("value") or s.get("set")):
                out.append(SECRET_SPEC[k]["label"])
    return out


def write_secret(p, text):
    tmp = p.with_name(p.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(tmp, p)


def create_client(name, typ, fields=None, secrets=None, owner="", created_by=""):
    for who in (owner, created_by):
        if who and not re.match(r"^[a-z0-9][a-z0-9_.-]{0,31}$", who):
            raise HubError("usuario inválido")
    if not NAME_RE.match(name or ""):
        raise HubError("nombre inválido: minúsculas, números, - y _ (máx. 31, sin espacios)")
    if typ not in TYPE_SPEC:
        raise HubError(f"tipo inválido (usar: {', '.join(TYPE_SPEC)})")
    if (CLIENTES / f"{name}.conf").exists():
        raise HubError(f"ya existe una VPN llamada {name}")
    _validate_fields(typ, fields)                       # validar antes de crear nada
    used = {load(c)["id"] for c in clients()}
    nid = next((i for i in range(1, 56) if i not in used), None)
    if nid is None:
        raise HubError("no quedan IDs libres (1-55)")
    p = CLIENTES / f"{name}.conf"
    p.write_text(f"# {name} — creado desde el panel\nID={nid}\nTYPE={typ}\nSERVER=\n"
                 f"PORT={DEFAULT_PORT.get(typ, '')}\nTRUSTED_CERT=\nAUTHGROUP=\nMAP=\"\"\nDIRECT=\"\"\nIGNORE=\"\"\n"
                 "AUTO_MAP=1\nCHECK_IP=\nHOSTS=\"\"\nDNS_SERVER=\nDOMAINS=\"\"\nOTP_REQUIRED=0\nDESCRIPTION=\"\"\n"
                 f"OWNER={owner}\nCREATED_BY={created_by}\nDISABLED=0\nDISABLED_BY=\"\"\nDNS_ALIAS=\"\"\n"
                 "IKE_VERSION=\"2\"\nDHGROUP=\"dh14\"\n")
    os.chmod(p, 0o644)
    try:
        return save_config(name, fields, secrets)
    except HubError:
        p.unlink(missing_ok=True)
        for x in (env_path(name), file_path(name, "WG_CONF"), file_path(name, "OVPN")):
            x.unlink(missing_ok=True)
        raise


def rename_client(old_name, new_name):
    old_name = old_name.strip().lower()
    new_name = new_name.strip().lower()
    if old_name == new_name:
        return old_name
    if not NAME_RE.match(new_name):
        raise HubError("nombre nuevo inválido: minúsculas, números, - y _, hasta 30 caracteres")
    if (CLIENTES / f"{new_name}.conf").exists():
        raise HubError(f"ya existe una VPN llamada '{new_name}'")

    cfg = load(old_name)
    was_active = False
    r_act = sh("systemctl", "is-active", f"vpnhub@{old_name}")
    if r_act.stdout.strip() == "active":
        was_active = True
        sh("systemctl", "stop", f"vpnhub@{old_name}")
    sh("systemctl", "disable", f"vpnhub@{old_name}")

    vh = cfg.get("vh", f"vh{cfg['id']}")
    ns = cfg.get("ns", f"vpn-{old_name}")
    hub_ip = f"100.64.{cfg['id']}.1"
    sh("systemctl", "stop", f"vpnhub-dns@{old_name}")
    sh("iptables", "-t", "nat", "-D", "VPNHUB_POST", "-o", vh, "-j", "SNAT", "--to-source", hub_ip)
    sh("ip", "link", "del", vh)
    sh("ip", "netns", "del", ns)
    shutil.rmtree(f"/etc/netns/{ns}", ignore_errors=True)

    old_conf = CLIENTES / f"{old_name}.conf"
    new_conf = CLIENTES / f"{new_name}.conf"
    content = old_conf.read_text()
    if content.startswith(f"# {old_name}"):
        content = f"# {new_name}" + content[len(f"# {old_name}"):]
    new_conf.write_text(content)
    os.chmod(new_conf, 0o644)
    old_conf.unlink(missing_ok=True)

    for key in ("WG_CONF", "OVPN"):
        f_old = file_path(old_name, key)
        if f_old.exists():
            f_new = file_path(new_name, key)
            f_old.rename(f_new)
    env_old = env_path(old_name)
    if env_old.exists():
        env_new = env_path(new_name)
        env_old.rename(env_new)

    for x in RUN.glob(f"{old_name}.*"):
        x.unlink(missing_ok=True)
    shutil.rmtree(f"/etc/netns/vpn-{old_name}", ignore_errors=True)

    sync()

    if was_active:
        sh("systemctl", "restart", f"vpnhub@{new_name}")

    return new_name


def delete_client(name):
    cfg = load(name)
    sh("systemctl", "stop", f"vpnhub@{name}")
    sh("systemctl", "disable", f"vpnhub@{name}")
    vh = cfg.get("vh", f"vh{cfg['id']}")
    ns = cfg.get("ns", f"vpn-{name}")
    hub_ip = f"100.64.{cfg['id']}.1"
    sh("systemctl", "stop", f"vpnhub-dns@{name}")
    sh("iptables", "-t", "nat", "-D", "VPNHUB_POST", "-o", vh, "-j", "SNAT", "--to-source", hub_ip)
    sh("ip", "link", "del", vh)
    sh("ip", "netns", "del", ns)
    shutil.rmtree(f"/etc/netns/{ns}", ignore_errors=True)
    (CLIENTES / f"{name}.conf").unlink(missing_ok=True)
    for x in (env_path(name), file_path(name, "WG_CONF"), file_path(name, "OVPN")):
        x.unlink(missing_ok=True)
    for x in RUN.glob(f"{name}.*"):
        x.unlink(missing_ok=True)
    shutil.rmtree(f"/etc/netns/vpn-{name}", ignore_errors=True)
    sync()


def fetch_cert(server, port):
    """sha256 del certificado del servidor (TRUSTED_CERT de Forti/AnyConnect)."""
    if not re.match(FIELD_SPEC["SERVER"]["re"], server or "") or not re.match(r"^\d{1,5}$", str(port or "443")):
        raise HubError("servidor o puerto inválido")
    port = str(port or "443")
    r = subprocess.run(["openssl", "s_client", "-connect", f"{server}:{port}", "-servername", server],
                       input="", capture_output=True, timeout=15)
    pem = re.search(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", r.stdout, re.S)
    if not pem:
        raise HubError(f"no pude leer el certificado de {server}:{port}")
    der = subprocess.run(["openssl", "x509", "-outform", "der"], input=pem.group(0), capture_output=True).stdout
    subj = subprocess.run(["openssl", "x509", "-noout", "-subject", "-enddate"], input=pem.group(0),
                          capture_output=True).stdout.decode().strip()
    import hashlib
    return {"sha256": hashlib.sha256(der).hexdigest(), "info": subj}


# ================= CLI =================
def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 1
    cmd, args = argv[0], argv[1:]
    if os.geteuid() != 0:
        raise HubError("ejecutar con sudo")
    with Lock():
        if cmd == "sync":
            sync(args[0] if args else None)
        elif cmd == "count":
            print(sum(1 for e in effective(load(args[0])) if e["state"] == "activa"))
        elif cmd == "list":
            ents = effective(load(args[0]))
            if "--json" in args:
                print(json.dumps(ents, indent=1))
            else:
                for e in ents:
                    tag = "MANUAL  " if e["origin"] == "manual" else "DINÁMICA"
                    print(f"{tag} {e['real']:<18} -> {e['virtual'] or '-':<18} {e['state']}"
                          f"{'' if e['pushed'] else ' (no anunciada)'}{'  ' + e['note'] if e.get('note') else ''}")
        elif cmd == "add":
            print(add(args[0], args[1], args[2] if len(args) > 2 else None)); sync(args[0])
        elif cmd == "del":
            print(delete(args[0], args[1])); sync(args[0])
        elif cmd in ("on", "off"):
            print(set_enabled(args[0], args[1], cmd == "on")); sync(args[0])
        elif cmd == "auto":
            set_auto(args[0], args[1] in ("on", "1", "si", "sí")); sync(args[0])
        else:
            print(__doc__)
            return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except HubError as e:
        sys.exit(f"ERROR: {e}")

#!/usr/bin/env python3
"""Panel web del hub VPN (solo stdlib), con usuarios y permisos.

  vpnhub-panel                       inicia el servidor HTTPS (puerto 8443)
  vpnhub-panel useradd <usuario> [--admin]   crea un usuario (pide la contraseña)
  vpnhub-panel passwd <usuario>      cambia la contraseña de un usuario
  vpnhub-panel users                 lista usuarios

Roles: admin (gestiona usuarios y todas las VPN generales) y usuario.
VPN general (OWNER vacío): la ven los usuarios con acceso ("*" = todas las generales, o una lista).
                           La editan/eliminan el admin y quien la creó.
VPN personal (OWNER=<usuario>): solo la ve y gestiona su dueño. Si se elimina el usuario, se eliminan sus VPN personales.
"""
import base64
import datetime
import fcntl
import getpass
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hubnets as hn  # noqa: E402

ETC = Path("/etc/vpnhub")
RUN = Path("/run/vpnhub")
USERS = ETC / "users.json"
OLD_PASSWD = ETC / "panel.passwd"
CERT, KEY = ETC / "panel.crt", ETC / "panel.key"
HTML = Path(__file__).resolve().with_name("index.html")
LOGIN_HTML = Path(__file__).resolve().with_name("login.html")
FAVICON_SVG = Path(__file__).resolve().with_name("favicon.svg")
FAVICON_PNG = Path(__file__).resolve().with_name("favicon.png")
FAVICON_ICO = Path(__file__).resolve().with_name("favicon.ico")
LOGO_PNG = Path(__file__).resolve().with_name("logo.png")
EMBLEM_PNG = Path(__file__).resolve().with_name("emblem.png")
BANNER_JPG = Path(__file__).resolve().with_name("banner.jpg")
DUO_JSON = ETC / "duo.json"
SESSIONS_FILE = RUN / "sessions.json"
TRUSTED_DEVICES_FILE = ETC / "trusted_devices.json"
LAN_DEVICES_FILE = ETC / "lan_devices.json"
AUDIT_LOG_FILE = Path("/var/log/vpnhub/audit.jsonl")
AUDIT_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
AUDIT_BACKUPS = 5
AUDIT_LOCK = threading.Lock()
INTENTIONAL_DOWN = set()
VPN_PREV_HEALTH = {}
PORT = int(os.environ.get("PANEL_PORT", "8443"))
OTP_RE = re.compile(r"^[0-9A-Za-z]{4,12}$")
USER_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,31}$")
MAX_BODY = 512 * 1024
HUBCTL = "/usr/local/sbin/hubctl"


def run(*args, input=None, timeout=15):
    try:
        r = subprocess.run(args, input=input, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return 124, "timeout"


# ================= usuarios =================
def hash_pw(pw, salt=None, it=200_000):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), it).hex()
    return f"pbkdf2_sha256${it}${salt}${h}"


def verify_pw(stored, pw):
    try:
        _, it, salt, h = stored.split("$")
    except ValueError:
        return False
    return hmac.compare_digest(hash_pw(pw, salt, int(it)).split("$")[3], h)


class UserLock:
    def __enter__(self):
        self.f = open(ETC / ".users.lock", "w")
        fcntl.flock(self.f, fcntl.LOCK_EX)
        return self

    def __exit__(self, *a):
        fcntl.flock(self.f, fcntl.LOCK_UN)
        self.f.close()


def load_users():
    if not USERS.exists() and OLD_PASSWD.exists():          # migración desde la versión de un solo usuario
        u, stored = OLD_PASSWD.read_text().strip().split(":", 1)
        save_users({u: {"hash": stored, "role": "admin", "enabled": True, "access": "*", "created": int(time.time())}})
    try:
        return json.loads(USERS.read_text()).get("users", {})
    except (OSError, ValueError):
        return {}


def save_users(users):
    tmp = USERS.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"users": users}, f, indent=1)
    os.replace(tmp, USERS)


def check_password_policy(pw):
    if len(pw or "") < 8:
        raise hn.HubError("la contraseña debe tener al menos 8 caracteres")


def active_admins(users, exclude=None):
    now = time.time()
    return [n for n, u in users.items()
            if u["role"] == "admin"
            and u.get("enabled", True)
            and not (u.get("expires") and now > u["expires"])
            and n != exclude]


def clean_expires(val):
    if not val:
        return None
    if isinstance(val, (int, float)):
        return int(val) if val > 0 else None
    if isinstance(val, str):
        val = val.strip()
        if not val or val.lower() in ("null", "none"):
            return None
        if val.isdigit():
            return int(val)
        m = re.match(r"^(\d{4})-(\d{2})-(\d{2})$", val)
        if m:
            import datetime
            dt = datetime.datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), 23, 59, 59)
            return int(dt.timestamp())
    raise hn.HubError("fecha de expiración inválida (formato YYYY-MM-DD)")


# ================= 2FA (TOTP y Duo) =================
def generar_secreto_totp(longitud=32):
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return "".join(secrets.choice(chars) for _ in range(longitud))


def calcular_totp(secreto_b32, timestamp=None):
    if timestamp is None:
        timestamp = time.time()
    t = int(timestamp) // 30
    key = base64.b32decode(secreto_b32.upper(), casefold=True)
    msg = struct.pack(">Q", t)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{code % 1000000:06d}"


def verificar_totp(secreto_b32, codigo, ventana=1):
    c = (codigo or "").strip().replace(" ", "")
    if len(c) != 6 or not c.isdigit():
        return False
    paso_base = int(time.time()) // 30
    for drift in range(-ventana, ventana + 1):
        if hmac.compare_digest(calcular_totp(secreto_b32, (paso_base + drift) * 30), c):
            return True
    return False


def generar_uri_totp(secreto_b32, usuario, emisor="Hub VPN"):
    user_quoted = urllib.parse.quote(usuario)
    issuer_quoted = urllib.parse.quote(emisor)
    return (
        f"otpauth://totp/{issuer_quoted}:{user_quoted}"
        f"?secret={secreto_b32}&issuer={issuer_quoted}&algorithm=SHA1&digits=6&period=30"
    )


def generar_qr_base64(uri):
    try:
        import qrcode
        qr = qrcode.QRCode(box_size=5, border=2)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")
    except Exception:
        return ""


def load_duo_config():
    if DUO_JSON.exists():
        try:
            return json.loads(DUO_JSON.read_text())
        except Exception:
            pass
    return {"ikey": "", "skey": "", "host": ""}


def save_duo_config(cfg):
    DUO_JSON.parent.mkdir(parents=True, exist_ok=True)
    tmp = DUO_JSON.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2))
    tmp.chmod(0o600)
    tmp.replace(DUO_JSON)


def get_duo_client():
    cfg = load_duo_config()
    if cfg.get("ikey") and cfg.get("skey") and cfg.get("host"):
        try:
            import duo_client
            return duo_client.Auth(ikey=cfg["ikey"], skey=cfg["skey"], host=cfg["host"])
        except Exception:
            return None
    return None


# ================= sesiones web =================
SESSIONS = {}
TEMP_2FA = {}


def load_sessions():
    global SESSIONS
    if SESSIONS_FILE.exists():
        try:
            SESSIONS = json.loads(SESSIONS_FILE.read_text())
        except Exception:
            SESSIONS = {}


def save_sessions():
    try:
        RUN.mkdir(mode=0o700, exist_ok=True)
        tmp = SESSIONS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(SESSIONS))
        tmp.chmod(0o600)
        tmp.replace(SESSIONS_FILE)
    except Exception:
        pass


def create_session(uname, ip=""):
    load_sessions()
    token = secrets.token_hex(32)
    now = time.time()
    to_del = [k for k, v in SESSIONS.items() if now - v.get("created", 0) > 30 * 86400]
    for k in to_del:
        del SESSIONS[k]
    SESSIONS[token] = {"uname": uname, "created": now, "ip": ip}
    save_sessions()
    return token


def get_session_user(token):
    if not token:
        return None
    load_sessions()
    sess = SESSIONS.get(token)
    if not sess:
        return None
    if time.time() - sess.get("created", 0) > 14 * 86400:
        delete_session(token)
        return None
    uname = sess.get("uname")
    users = load_users()
    u = users.get(uname)
    if not u or not u.get("enabled", True):
        return None
    if u.get("expires") and time.time() > u["expires"]:
        return None
    return uname, u


def delete_session(token):
    load_sessions()
    if token in SESSIONS:
        del SESSIONS[token]
        save_sessions()


# ================= dispositivos de confianza (30 días) =================
TRUSTED_DEVICES = {}
TRUSTED_LOCK = threading.Lock()


def load_trusted_devices():
    global TRUSTED_DEVICES
    with TRUSTED_LOCK:
        if TRUSTED_DEVICES_FILE.exists():
            try:
                TRUSTED_DEVICES = json.loads(TRUSTED_DEVICES_FILE.read_text())
            except Exception:
                TRUSTED_DEVICES = {}


def save_trusted_devices():
    with TRUSTED_LOCK:
        try:
            ETC.mkdir(mode=0o755, exist_ok=True)
            tmp = TRUSTED_DEVICES_FILE.with_suffix(".tmp")
            tmp.write_text(json.dumps(TRUSTED_DEVICES))
            tmp.chmod(0o600)
            tmp.replace(TRUSTED_DEVICES_FILE)
        except Exception:
            pass


def register_trusted_device(uname, ip=""):
    load_trusted_devices()
    now = time.time()
    with TRUSTED_LOCK:
        to_del = [k for k, v in TRUSTED_DEVICES.items() if now - v.get("created", 0) > 30 * 86400]
        for k in to_del:
            del TRUSTED_DEVICES[k]
        token = secrets.token_hex(32)
        TRUSTED_DEVICES[token] = {"uname": uname, "created": now, "ip": ip}
    save_trusted_devices()
    return token


def is_trusted_device(uname, token):
    if not token:
        return False
    load_trusted_devices()
    with TRUSTED_LOCK:
        entry = TRUSTED_DEVICES.get(token)
        if not entry:
            return False
        if time.time() - entry.get("created", 0) > 30 * 86400:
            del TRUSTED_DEVICES[token]
            save_trusted_devices()
            return False
        return entry.get("uname") == uname


def revoke_user_trusted_devices(uname):
    load_trusted_devices()
    with TRUSTED_LOCK:
        to_del = [k for k, v in TRUSTED_DEVICES.items() if v.get("uname") == uname]
        for k in to_del:
            del TRUSTED_DEVICES[k]
    save_trusted_devices()


# ================= auditoría y logs =================
def audit_log(cat, action, msg, user="system", ip="", target="", level="info", detail=None):
    try:
        AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOCK:
            if AUDIT_LOG_FILE.exists() and AUDIT_LOG_FILE.stat().st_size > AUDIT_MAX_BYTES:
                for i in range(AUDIT_BACKUPS - 1, 0, -1):
                    src = AUDIT_LOG_FILE.with_name(f"audit.{i}.jsonl")
                    dst = AUDIT_LOG_FILE.with_name(f"audit.{i+1}.jsonl")
                    if src.exists():
                        os.replace(src, dst)
                os.replace(AUDIT_LOG_FILE, AUDIT_LOG_FILE.with_name("audit.1.jsonl"))

            rec = {
                "ts": round(time.time(), 2),
                "time": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
                "cat": cat,
                "action": action,
                "level": level,
                "user": user or "system",
                "ip": ip or "-",
                "target": target or "-",
                "msg": msg,
                "detail": detail or {}
            }
            with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:
        sys.stderr.write(f"Error escribiendo audit log: {e}\n")


def read_audit_logs(cat="", q="", limit=200):
    if not AUDIT_LOG_FILE.exists():
        return []
    res = []
    q_low = q.strip().lower() if q else None
    try:
        with open(AUDIT_LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except Exception:
                continue
            if cat and item.get("cat") != cat:
                continue
            if q_low:
                haystack = f"{item.get('msg','')} {item.get('user','')} {item.get('ip','')} {item.get('target','')} {item.get('action','')}".lower()
                if q_low not in haystack:
                    continue
            res.append(item)
            if len(res) >= limit:
                break
    except Exception as e:
        sys.stderr.write(f"Error leyendo audit log: {e}\n")
    return res


def get_system_uptime():
    try:
        with open("/proc/uptime", "r") as f:
            secs = float(f.readline().split()[0])
        days = int(secs // 86400)
        hours = int((secs % 86400) // 3600)
        mins = int((secs % 3600) // 60)
        parts = []
        if days: parts.append(f"{days}d")
        if hours: parts.append(f"{hours}h")
        parts.append(f"{mins}m")
        return " ".join(parts) or "< 1m"
    except Exception:
        return "desconocido"


# ================= registro de uso de VPNs =================
USAGE_FILE = ETC / "vpn_usage.json"
USAGE_LOCK = threading.Lock()
VPN_USAGE = {}


def load_vpn_usage():
    global VPN_USAGE
    with USAGE_LOCK:
        if USAGE_FILE.exists():
            try:
                VPN_USAGE = json.loads(USAGE_FILE.read_text())
                if isinstance(VPN_USAGE, dict):
                    return
            except Exception:
                VPN_USAGE = {}
        VPN_USAGE = {}
        # Pre-cargar desde audit.jsonl si existe para no empezar en blanco
        if AUDIT_LOG_FILE.exists():
            try:
                for line in AUDIT_LOG_FILE.read_text().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                        if ev.get("cat") == "vpn" and ev.get("target"):
                            tgt = ev["target"]
                            u = ev.get("user")
                            ts = ev.get("ts", time.time())
                            act = ev.get("action")
                            if tgt not in VPN_USAGE:
                                VPN_USAGE[tgt] = {}
                            if act in ("up", "restart", "otp", "reconnected"):
                                if u and u != "system":
                                    VPN_USAGE[tgt]["connected_by"] = u
                                    VPN_USAGE[tgt]["connected_at"] = ts
                                    VPN_USAGE[tgt]["last_user"] = u
                                    VPN_USAGE[tgt]["last_at"] = ts
                                    VPN_USAGE[tgt]["last_action"] = act
                            elif act == "down":
                                VPN_USAGE[tgt]["connected_by"] = None
                                if u and u != "system":
                                    VPN_USAGE[tgt]["disconnected_by"] = u
                                    VPN_USAGE[tgt]["disconnected_at"] = ts
                                    if not VPN_USAGE[tgt].get("last_user"):
                                        VPN_USAGE[tgt]["last_user"] = u
                                        VPN_USAGE[tgt]["last_at"] = ts
                                VPN_USAGE[tgt]["last_action"] = "down"
                    except Exception:
                        pass
                save_vpn_usage_locked()
            except Exception:
                pass


def save_vpn_usage_locked():
    try:
        USAGE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = USAGE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(VPN_USAGE, indent=2))
        tmp.chmod(0o644)
        tmp.replace(USAGE_FILE)
    except Exception as e:
        sys.stderr.write(f"Error guardando vpn_usage.json: {e}\n")


def record_vpn_action(name, user, action):
    now = time.time()
    with USAGE_LOCK:
        cur = VPN_USAGE.get(name) or {}
        if action in ("up", "restart", "otp"):
            cur["connected_by"] = user
            cur["connected_at"] = now
            cur["last_user"] = user
            cur["last_at"] = now
            cur["last_action"] = action
        elif action == "down":
            cur["connected_by"] = None
            cur["disconnected_by"] = user
            cur["disconnected_at"] = now
            cur["last_action"] = "down"
            if not cur.get("last_user"):
                cur["last_user"] = user
                cur["last_at"] = now
        VPN_USAGE[name] = cur
        save_vpn_usage_locked()


def get_vpn_usage(name):
    with USAGE_LOCK:
        return dict(VPN_USAGE.get(name) or {})


# Cargar estado al importar
load_vpn_usage()


def vpn_monitor_loop():
    time.sleep(5)
    while True:
        try:
            for name in hn.clients():
                try:
                    cfg = hn.load(name)
                    rc_svc, out_svc = run("systemctl", "is-active", f"vpnhub@{name}", timeout=5)
                    svc_ok = (out_svc.strip() == "active")
                    itf = hn.tunnel_iface(cfg) if svc_ok else None
                    has_tun = bool(itf)

                    check_ip = cfg.get("CHECK_IP")
                    chk_ok = None
                    if svc_ok and has_tun and check_ip:
                        rc_p, _ = run("ip", "netns", "exec", cfg["ns"], "ping", "-c", "1", "-W", "2", check_ip, timeout=5)
                        chk_ok = (rc_p == 0)

                    prev = VPN_PREV_HEALTH.get(name)
                    current = (svc_ok, has_tun, chk_ok)
                    VPN_PREV_HEALTH[name] = current

                    if prev is not None:
                        prev_svc, prev_tun, prev_chk = prev
                        if (prev_svc and prev_tun) and not (svc_ok and has_tun):
                            if name not in INTENTIONAL_DOWN:
                                reason = "servicio caído" if not svc_ok else "interfaz de túnel caída"
                                audit_log("vpn", "unexpected_down", f"Desconexión inesperada de '{name}': {reason}",
                                          target=name, level="error")
                        elif (svc_ok and has_tun and prev_chk is True and chk_ok is False):
                            if name not in INTENTIONAL_DOWN:
                                audit_log("vpn", "ping_fail", f"La IP de chequeo de '{name}' ({check_ip}) no responde",
                                          target=name, level="warn")
                        elif not (prev_svc and prev_tun) and (svc_ok and has_tun):
                            audit_log("vpn", "reconnected", f"VPN '{name}' reconectada y operativa",
                                      target=name, level="info")
                            INTENTIONAL_DOWN.discard(name)
                        elif (prev_chk is False and chk_ok is True):
                            audit_log("vpn", "ping_recovered", f"La IP de chequeo de '{name}' ({check_ip}) volvió a responder",
                                      target=name, level="info")
                except Exception:
                    pass
        except Exception as e:
            sys.stderr.write(f"Error en monitor de VPNs: {e}\n")
        time.sleep(15)


# ================= permisos =================
def is_admin_user(uname):
    if not uname:
        return False
    if uname == "admin":
        return True
    u = USERS.get(uname)
    return bool(u and u.get("role") == "admin")


def vpn_meta(name):
    cfg = hn.load(name)
    return {
        "owner": cfg["OWNER"],
        "created_by": cfg["CREATED_BY"],
        "description": cfg.get("DESCRIPTION", ""),
        "disabled": cfg.get("DISABLED", "0") == "1",
        "disabled_by": cfg.get("DISABLED_BY", ""),
    }


def can_see(user, uname, meta):
    if user["role"] == "admin":
        return True
    if meta["owner"]:
        return meta["owner"] == uname
    if meta["created_by"] == uname:
        return True
    acc = user.get("access", "*")
    return acc == "*" or (isinstance(acc, list) and meta.get("name") in acc)


def can_edit(user, uname, meta):
    if user["role"] == "admin":
        return True
    if meta["owner"]:
        return meta["owner"] == uname
    return meta["created_by"] == uname


def visible_clients(user, uname):
    out = []
    for c in hn.clients():
        try:
            m = vpn_meta(c)
        except hn.HubError:
            continue
        m["name"] = c
        if can_see(user, uname, m):
            out.append((c, m))
    return out


def personal_vpns(uname):
    out = []
    for c in hn.clients():
        try:
            if hn.load(c)["OWNER"] == uname:
                out.append(c)
        except hn.HubError:
            pass
    return out


# ================= estado =================
def client_status(name, meta, user, uname):
    try:
        cfg = hn.load(name)
    except hn.HubError as e:
        return {"name": name, "error": str(e)}
    ns = cfg["ns"]
    ents = hn.effective(cfg)
    st = {"name": name, "id": cfg["ID"], "type": cfg["TYPE"],
          "label": hn.TYPE_SPEC.get(cfg["TYPE"], {}).get("label", cfg["TYPE"]),
          "server": hn.endpoint_of(name, cfg),
          "nets": ents, "auto_map": cfg["auto"],
          "scope": "personal" if meta["owner"] else "general", "owner": meta["owner"],
          "created_by": meta["created_by"], "can_edit": can_edit(user, uname, meta),
          "description": cfg.get("DESCRIPTION", ""),
          "dns_alias": cfg.get("DNS_ALIAS", "").strip() or name,
          "hosts": [{"name": f"{n}.{name}.hub", "alias_name": f"{n}.{cfg.get('DNS_ALIAS', '').strip() or name}",
                     "real": r, "virtual": hn.virt_of(r, ents)}
                    for n, r in hn.pairs(cfg["HOSTS"])],
          "otp_required": cfg["OTP_REQUIRED"] == "1",
          "waiting_otp": (RUN / f"{name}.otp-wait").exists()}
    try:
        st["missing"] = hn.missing(name)
    except hn.HubError:
        st["missing"] = []

    _, out = run("systemctl", "show", f"vpnhub@{name}", "-p", "ActiveState", "-p", "UnitFileState",
                 "-p", "ActiveEnterTimestamp", "-p", "NRestarts")
    props = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    st.update(service=props.get("ActiveState", "unknown"), enabled=props.get("UnitFileState") == "enabled",
              since=props.get("ActiveEnterTimestamp", ""), restarts=props.get("NRestarts", "0"))

    st["tunnel_ip"], st["iface"] = None, None
    if hn.ns_exists(cfg):
        _, out = run("ip", "-n", ns, "-4", "-j", "addr")
        try:
            for itf in json.loads(out or "[]"):
                if re.match(r"^(ppp|tun|wg|ipsec)", itf.get("ifname", "")):
                    addrs = itf.get("addr_info", [])
                    st["iface"] = itf["ifname"]
                    st["tunnel_ip"] = addrs[0]["local"] if addrs else None
                    break
        except (ValueError, KeyError):
            pass

    st["handshake_age"] = None
    st["transfer_rx"], st["transfer_tx"] = None, None
    if cfg["TYPE"] == "wireguard" and st["iface"]:
        _, out = run("ip", "netns", "exec", ns, "wg", "show", st["iface"], "latest-handshakes")
        hs = [int(x.split()[1]) for x in out.splitlines() if len(x.split()) == 2 and x.split()[1] != "0"]
        if hs:
            st["handshake_age"] = int(time.time()) - max(hs)

        _, out_t = run("ip", "netns", "exec", ns, "wg", "show", st["iface"], "transfer")
        rx_tot, tx_tot = 0, 0
        has_trans = False
        for line in out_t.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                try:
                    rx_tot += int(parts[1])
                    tx_tot += int(parts[2])
                    has_trans = True
                except ValueError:
                    pass
        if has_trans:
            st["transfer_rx"] = rx_tot
            st["transfer_tx"] = tx_tot
    elif st["iface"] and hn.ns_exists(cfg):
        _, out_s = run("ip", "-n", ns, "-s", "-j", "link", "show", "dev", st["iface"])
        try:
            stats = json.loads(out_s or "[]")
            if stats:
                st64 = stats[0].get("stats64", {})
                st["transfer_rx"] = st64.get("rx", {}).get("bytes")
                st["transfer_tx"] = st64.get("tx", {}).get("bytes")
        except Exception:
            pass

    st["check_ip"], st["check_ok"], st["check_ms"] = cfg["CHECK_IP"], None, None
    if cfg["CHECK_IP"] and st["tunnel_ip"]:
        rc, out = run("ip", "netns", "exec", ns, "ping", "-c1", "-W2", cfg["CHECK_IP"], timeout=5)
        st["check_ok"] = rc == 0
        m = re.search(r"time=([\d.]+)", out)
        st["check_ms"] = float(m.group(1)) if m else None

    disabled = meta.get("disabled", False) or (cfg.get("DISABLED", "0") == "1")
    disabled_by = meta.get("disabled_by", "") or cfg.get("DISABLED_BY", "")
    disabled_by_admin = disabled and is_admin_user(disabled_by)
    is_admin = user.get("role") == "admin"
    if not disabled:
        can_connect = True
    elif disabled_by_admin:
        can_connect = is_admin
    else:
        can_connect = is_admin or (meta.get("owner") == uname) or (meta.get("created_by") == uname)

    usage = get_vpn_usage(name)
    is_active = (st.get("service") == "active")
    connected_by = usage.get("connected_by") if is_active else None
    connected_at = usage.get("connected_at") if is_active else None

    # Fallback si está activa pero no se había registrado connected_by
    if is_active and not connected_by:
        connected_by = usage.get("last_user") or meta.get("created_by") or meta.get("owner") or "admin"
        connected_at = usage.get("last_at")

    last_user = usage.get("last_user")
    last_at = usage.get("last_at")

    st.update(disabled=disabled, disabled_by=disabled_by, disabled_by_admin=disabled_by_admin,
              can_connect=can_connect,
              connected_by=connected_by, connected_at=connected_at,
              last_user=last_user, last_at=last_at)
    return st


# ================= acciones =================
def act_nets(name, body):
    a = body.get("action")
    with hn.Lock():
        if a == "add":
            msg = hn.add(name, body.get("real", ""), body.get("virtual") or None)
        elif a == "del":
            msg = hn.delete(name, body.get("real", ""))
        elif a in ("on", "off"):
            msg = hn.set_enabled(name, body.get("real", ""), a == "on")
        elif a == "auto":
            hn.set_auto(name, bool(body.get("on")))
            msg = "mapeo automático " + ("activado" if body.get("on") else "desactivado")
        else:
            raise hn.HubError("acción inválida")
        hn.sync(name)
    return {"ok": True, "msg": msg}


def restart_if_active(name):
    _, out = run("systemctl", "is-active", f"vpnhub@{name}")
    if out.strip() == "active":
        run("systemctl", "restart", f"vpnhub@{name}", timeout=30)
        return True
    return False


def delete_vpn(name):
    hn.delete_client(name)
    with UserLock():                                   # sacarla de las listas de acceso
        users = load_users()
        for u in users.values():
            if isinstance(u.get("access"), list) and name in u["access"]:
                u["access"].remove(name)
        save_users(users)
    with hn.Lock():
        hn.sync()
    with USAGE_LOCK:
        if name in VPN_USAGE:
            VPN_USAGE.pop(name, None)
            save_vpn_usage_locked()


def users_action(me, body, ip=""):
    a = body.get("action")
    name = (body.get("name") or "").strip().lower()
    with UserLock():
        users = load_users()
        if a == "create":
            if not USER_RE.match(name):
                raise hn.HubError("usuario inválido: minúsculas, números, punto, - y _")
            if name in users:
                raise hn.HubError(f"ya existe el usuario {name}")
            check_password_policy(body.get("password"))
            role = "admin" if body.get("role") == "admin" else "user"
            expires = clean_expires(body.get("expires"))
            metodo_2fa = body.get("metodo_2fa", "ninguno")
            if metodo_2fa not in ("ninguno", "totp", "duo"):
                metodo_2fa = "ninguno"
            doble_factor = metodo_2fa != "ninguno"
            totp_secret = body.get("totp_secret") if metodo_2fa == "totp" else None
            duo_user = (body.get("duo_username") or "").strip() or None
            access_val = clean_access(body.get("access", "*"))
            comment_val = (body.get("comment") or body.get("comentario") or "").strip()
            users[name] = {"hash": hash_pw(body["password"]), "role": role, "enabled": True,
                           "access": access_val, "created": int(time.time()),
                           "expires": expires, "doble_factor": doble_factor, "metodo_2fa": metodo_2fa,
                           "totp_secret": totp_secret, "duo_username": duo_user,
                           "comment": comment_val}
            save_users(users)
            audit_log("user", "create", f"Usuario '{name}' creado (rol: {role}, 2FA: {metodo_2fa})",
                      user=me, ip=ip, target=name,
                      detail={"role": role, "access": access_val, "expires": expires, "metodo_2fa": metodo_2fa, "comment": comment_val})
            return {"ok": True, "msg": f"usuario {name} creado"}
        if name not in users:
            raise hn.HubError("usuario inexistente")
        u = users[name]
        if a == "update":
            if "role" in body:
                role = "admin" if body["role"] == "admin" else "user"
                if role != "admin" and u["role"] == "admin" and not active_admins(users, exclude=name):
                    raise hn.HubError("tiene que quedar al menos un admin habilitado")
                u["role"] = role
            if "access" in body:
                u["access"] = clean_access(body["access"])
            if "expires" in body:
                u["expires"] = clean_expires(body["expires"])
            if "comment" in body or "comentario" in body:
                u["comment"] = (body.get("comment") or body.get("comentario") or "").strip()
            if "metodo_2fa" in body:
                m2fa = body["metodo_2fa"]
                if m2fa not in ("ninguno", "totp", "duo"):
                    m2fa = "ninguno"
                u["metodo_2fa"] = m2fa
                u["doble_factor"] = m2fa != "ninguno"
                if m2fa == "totp":
                    if body.get("totp_secret"):
                        u["totp_secret"] = body["totp_secret"]
                    elif not u.get("totp_secret"):
                        u["totp_secret"] = generar_secreto_totp(32)
                elif m2fa == "duo":
                    if "duo_username" in body:
                        u["duo_username"] = (body.get("duo_username") or "").strip() or None
            if "enabled" in body:
                en = bool(body["enabled"])
                if not en and name == me:
                    raise hn.HubError("no podés deshabilitarte a vos mismo")
                if not en and u["role"] == "admin" and not active_admins(users, exclude=name):
                    raise hn.HubError("tiene que quedar al menos un admin habilitado")
                u["enabled"] = en
                if not en:                             # al deshabilitar: apagar sus VPN personales
                    revoke_user_trusted_devices(name)
                    for c in personal_vpns(name):
                        run(HUBCTL, "down", c, timeout=60)
            if u.get("expires") and time.time() > u["expires"]:
                revoke_user_trusted_devices(name)
                for c in personal_vpns(name):
                    run(HUBCTL, "down", c, timeout=60)
            save_users(users)
            audit_log("user", "update", f"Usuario '{name}' actualizado (rol: {u['role']}, activo: {u['enabled']}, 2FA: {u['metodo_2fa']})",
                      user=me, ip=ip, target=name,
                      detail={"role": u.get("role"), "enabled": u.get("enabled"), "access": u.get("access"), "expires": u.get("expires"), "2fa": u.get("metodo_2fa")})
            return {"ok": True, "msg": f"usuario {name} actualizado"}
        if a == "passwd":
            check_password_policy(body.get("password"))
            u["hash"] = hash_pw(body["password"])
            save_users(users)
            revoke_user_trusted_devices(name)
            audit_log("user", "passwd", f"Contraseña del usuario '{name}' restablecida",
                      user=me, ip=ip, target=name)
            return {"ok": True, "msg": f"contraseña de {name} cambiada"}
        if a == "delete":
            if name == me:
                raise hn.HubError("no podés eliminarte a vos mismo")
            if u["role"] == "admin" and not active_admins(users, exclude=name):
                raise hn.HubError("tiene que quedar al menos un admin habilitado")
            del users[name]
            save_users(users)
            revoke_user_trusted_devices(name)
            audit_log("user", "delete", f"Usuario '{name}' eliminado",
                      user=me, ip=ip, target=name, level="warn")
        else:
            raise hn.HubError("acción inválida")
    # fuera del lock de usuarios: borrar sus VPN personales
    borradas = personal_vpns(name)
    for c in borradas:
        hn.delete_client(c)
    with hn.Lock():
        hn.sync()
    return {"ok": True, "msg": f"usuario {name} eliminado" + (f" junto con {len(borradas)} VPN personales" if borradas else "")}


def clean_access(acc):
    if acc == "*":
        return "*"
    if not isinstance(acc, list):
        raise hn.HubError("acceso inválido")
    generales = {c for c in hn.clients() if not hn.load(c)["OWNER"]}
    return sorted({a for a in acc if a in generales})


def users_list():
    users = load_users()
    out = []
    now = time.time()
    for n, u in sorted(users.items()):
        exp = u.get("expires")
        m2fa = u.get("metodo_2fa", "ninguno")
        df = u.get("doble_factor", m2fa != "ninguno")
        out.append({"name": n, "role": u["role"], "enabled": u.get("enabled", True), "access": u.get("access", "*"),
                    "personal": len(personal_vpns(n)), "created": u.get("created"),
                    "expires": exp, "expired": bool(exp and now > exp),
                    "doble_factor": df, "metodo_2fa": m2fa, "has_totp": bool(u.get("totp_secret")),
                    "duo_username": u.get("duo_username", ""), "comment": u.get("comment", "")})
    generales = [{"name": c, "label": hn.TYPE_SPEC.get(hn.load(c)["TYPE"], {}).get("label", "")}
                 for c in hn.clients() if not hn.load(c)["OWNER"]]
    duo_cfg = load_duo_config()
    duo_configured = bool(duo_cfg.get("ikey") and duo_cfg.get("skey") and duo_cfg.get("host"))
    return {"users": out, "general_vpns": generales, "duo_configured": duo_configured}


# ================= WireGuard Road Warrior Server =================
WG_SERVER_CONF = Path("/etc/wireguard/wg0.conf")
WG_SERVER_KEY = Path("/etc/wireguard/server.key")
WG_SERVER_PUB = Path("/etc/wireguard/server.pub")
RW_PEERS_FILE = ETC / "rw_peers.json"
RW_LOCK = threading.Lock()


def ensure_wg_server():
    """Inicializa la interfaz del servidor WireGuard (wg0) en el host si no existe."""
    try:
        Path("/etc/wireguard").mkdir(mode=0o700, exist_ok=True)
        if not WG_SERVER_KEY.exists():
            rc, priv = run("wg", "genkey")
            if rc != 0:
                print(f"AVISO: no se pudo generar clave privada wg: {priv}", file=sys.stderr)
                return
            WG_SERVER_KEY.write_text(priv.strip() + "\n")
            WG_SERVER_KEY.chmod(0o600)
            rc, pub = run("wg", "pubkey", input=priv.strip())
            if rc == 0:
                WG_SERVER_PUB.write_text(pub.strip() + "\n")

        if not WG_SERVER_PUB.exists() and WG_SERVER_KEY.exists():
            priv = WG_SERVER_KEY.read_text().strip()
            rc, pub = run("wg", "pubkey", input=priv)
            if rc == 0:
                WG_SERVER_PUB.write_text(pub.strip() + "\n")

        if not WG_SERVER_CONF.exists():
            priv = WG_SERVER_KEY.read_text().strip()
            conf = (
                "[Interface]\n"
                "Address = 10.99.0.1/24\n"
                "ListenPort = 51820\n"
                f"PrivateKey = {priv}\n"
                "PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -o eth0 -j MASQUERADE\n"
                "PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; iptables -t nat -D POSTROUTING -s 10.99.0.0/24 -o eth0 -j MASQUERADE\n"
            )
            WG_SERVER_CONF.write_text(conf)
            WG_SERVER_CONF.chmod(0o600)

        # Iniciar y habilitar wg-quick@wg0
        run("systemctl", "enable", "--now", "wg-quick@wg0")
    except Exception as e:
        print(f"AVISO ensure_wg_server: {e}", file=sys.stderr)


def get_or_create_user_wg_conf(uname):
    with RW_LOCK:
        ensure_wg_server()
        peers = {}
        if RW_PEERS_FILE.exists():
            try:
                peers = json.loads(RW_PEERS_FILE.read_text())
            except Exception:
                peers = {}

        server_pub = WG_SERVER_PUB.read_text().strip() if WG_SERVER_PUB.exists() else ""
        dev, l = hn.lan()
        server_endpoint = f"{l.ip if l else '127.0.0.1'}:51820"

        if uname in peers:
            uinfo = peers[uname]
            client_priv = uinfo["private_key"]
            client_ip = uinfo["ip"]
        else:
            rc, client_priv = run("wg", "genkey")
            client_priv = client_priv.strip()
            rc, client_pub = run("wg", "pubkey", input=client_priv.strip())
            client_pub = client_pub.strip()

            used_ips = {p.get("ip") for p in peers.values()}
            next_idx = 2
            while f"10.99.0.{next_idx}" in used_ips and next_idx < 254:
                next_idx += 1
            client_ip = f"10.99.0.{next_idx}"

            peers[uname] = {
                "ip": client_ip,
                "private_key": client_priv,
                "public_key": client_pub,
                "created": int(time.time())
            }
            RW_PEERS_FILE.write_text(json.dumps(peers, indent=2))
            RW_PEERS_FILE.chmod(0o600)

            # Agregar peer a wg0 en vivo
            run("wg", "set", "wg0", "peer", client_pub, "allowed-ips", f"{client_ip}/32")

            # Persistir peer en wg0.conf
            block = f"\n# User {uname}\n[Peer]\nPublicKey = {client_pub}\nAllowedIPs = {client_ip}/32\n"
            with open(WG_SERVER_CONF, "a") as f:
                f.write(block)

        dns_servers = f"{l.ip}, 10.99.0.1" if l else "10.99.0.1"
        return (
            f"[Interface]\n"
            f"# Perfil WireGuard VPN Hub para usuario: {uname}\n"
            f"PrivateKey = {client_priv}\n"
            f"Address = {client_ip}/24\n"
            f"DNS = {dns_servers}\n\n"
            f"[Peer]\n"
            f"PublicKey = {server_pub}\n"
            f"Endpoint = {server_endpoint}\n"
            f"AllowedIPs = 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16\n"
            f"PersistentKeepalive = 25\n"
        )


# ================= Portal de Conflicto y Redirección HTTP (Puerto 80) =================
PORTAL_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Conflicto de Red — VPiNetmap</title>
<style>
:root{--bg:#f8fafc;--card:#ffffff;--subcard:#f8fafc;--line:#e2e8f0;--fg:#0f172a;--muted:#64748b;--accent:#00c0f0;--accent-hover:#0284c7;--accent-light:#f0f9ff;--accent-border:#bae6fd;--warn:#b45309;--warn-bg:#fef3c7;--warn-border:#fde68a;--code-bg:#e0f2fe;--code-fg:#0369a1}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font-family:system-ui,-apple-system,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.wrap{max-width:680px;width:100%;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px;box-shadow:0 10px 25px -5px rgba(0,0,0,0.06),0 8px 10px -6px rgba(0,0,0,0.03)}
.badge{display:inline-flex;align-items:center;gap:6px;background:var(--warn-bg);color:var(--warn);border:1px solid var(--warn-border);padding:4px 10px;border-radius:20px;font-size:12px;font-weight:600;margin-bottom:14px}
h1{font-size:20px;font-weight:700;color:var(--fg);margin-bottom:8px}
p.sub{color:var(--muted);font-size:14px;line-height:1.5;margin-bottom:20px}
p.sub code{color:var(--code-fg);background:var(--code-bg);padding:2px 6px;border-radius:4px;font-weight:600}
.client-list{display:flex;flex-direction:column;gap:12px;margin-bottom:24px}
.card{background:var(--subcard);border:1px solid var(--line);border-radius:10px;padding:16px;display:flex;flex-direction:column;gap:10px}
.card-hdr{display:flex;justify-content:space-between;align-items:baseline}
.card-title{font-size:16px;font-weight:600;color:var(--fg)}
.card-alias{font-size:12px;color:var(--accent);background:var(--accent-light);border:1px solid var(--accent-border);padding:2px 8px;border-radius:6px;font-family:monospace;font-weight:600}
.card-desc{font-size:13px;color:var(--muted);font-style:italic}
.btn-row{display:flex;gap:8px;flex-wrap:wrap;margin-top:4px}
a.btn,button.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:8px 14px;border-radius:7px;font-size:13px;font-weight:500;text-decoration:none;cursor:pointer;transition:all 0.15s;border:none}
a.btn-sec{background:#ffffff;color:#334155;border:1px solid #cbd5e1}
a.btn-sec:hover{background:#f1f5f9;color:#0f172a;border-color:#94a3b8}
button.btn-pri{background:#00c0f0;color:#ffffff;font-weight:600}
button.btn-pri:hover{background:#0284c7}
button.btn-pri:disabled{opacity:0.6;cursor:not-allowed}
.footer{font-size:12px;color:var(--muted);text-align:center;border-top:1px solid var(--line);padding-top:16px}
.footer a{color:#0284c7;text-decoration:none;font-weight:500}
</style>
</head>
<body>
<div class="wrap">
  <div class="badge">⚠️ Conflicto de Red Detectado</div>
  <h1>Dirección IP duplicada en múltiples VPNs</h1>
  <p class="sub">La dirección IP <code>{host}</code> pertenece al segmento <code>{conflicting_net}</code>, el cual está activo simultáneamente en túneles VPN conectados:</p>
  <div class="client-list">
    {cards_html}
  </div>
  <div class="footer">
    VPiNetmap · Gateway Multi-VPN · <a href="/">Ir al Panel de Administración</a>
  </div>
</div>
<script>
async function setOverride(subnet, client, btn) {
  btn.disabled = true;
  const oldText = btn.textContent;
  btn.textContent = "Conmutando...";
  try {
    const res = await fetch("/api/override", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({subnet, client})
    });
    const d = await res.json();
    if (d.ok) {
      setTimeout(() => { location.reload(); }, 600);
    } else {
      alert("Error: " + (d.error || "falló la conmutación"));
      btn.disabled = false;
      btn.textContent = oldText;
    }
  } catch(e) {
    alert("Error de conexión: " + e.message);
    btn.disabled = false;
    btn.textContent = oldText;
  }
}
</script>
</body>
</html>"""


class PortalHandler(BaseHTTPRequestHandler):
    server_version = "vpnhub-conflict-portal"

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        host_hdr = self.headers.get("Host", "").split(":")[0].strip().lower()
        conflicts = {}
        if hn.CONFLICTS_FILE.exists():
            try:
                conflicts = json.loads(hn.CONFLICTS_FILE.read_text())
            except Exception:
                pass

        matched_net, matched_info = None, None
        try:
            h_ip = hn.ipa.ip_address(host_hdr)
            for r_str, cdata in conflicts.items():
                if h_ip in hn.net(r_str):
                    matched_net = r_str
                    matched_info = cdata
                    break
        except Exception:
            pass

        if matched_net and matched_info:
            cards = []
            for cl in matched_info.get("clients", []):
                c_name = cl.get("client", "")
                c_alias = cl.get("alias", c_name)
                c_desc = cl.get("desc", "") or "Sin descripción"
                v_host = cl.get("base_virtual_ip", "")
                try:
                    h_addr = hn.ipa.ip_address(host_hdr)
                    r_base = hn.net(matched_net)
                    v_base = hn.net(cl.get("virtual", ""))
                    offset = int(h_addr) - int(r_base.network_address)
                    v_host = str(hn.ipa.ip_address(int(v_base.network_address) + offset))
                except Exception:
                    pass

                card = f"""
                <div class="card">
                  <div class="card-hdr">
                    <span class="card-title">{c_name}</span>
                    <span class="card-alias">{c_alias}</span>
                  </div>
                  <div class="card-desc">{c_desc}</div>
                  <div class="btn-row">
                    <a class="btn btn-sec" href="http://{host_hdr}.{c_alias}" target="_blank">🌐 Abrir {host_hdr}.{c_alias}</a>
                    <a class="btn btn-sec" href="http://{v_host}" target="_blank">🌐 Abrir {v_host}</a>
                    <button class="btn btn-pri" onclick="setOverride('{matched_net}', '{c_name}', this)">📌 Conmutar IP real a {c_alias}</button>
                  </div>
                </div>"""
                cards.append(card)

            html = (PORTAL_HTML_TEMPLATE.replace("{host}", host_hdr)
                                       .replace("{conflicting_net}", matched_net)
                                       .replace("{cards_html}", "\n".join(cards)))
            body = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # Redirección por defecto a HTTPS del panel
        self.send_response(301)
        redir_host = host_hdr if host_hdr else "127.0.0.1"
        self.send_header("Location", f"https://{redir_host}:8443{self.path}")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        if self.path == "/api/override":
            n = int(self.headers.get("Content-Length", "0") or 0)
            raw = self.rfile.read(n) if n else b"{}"
            try:
                body = json.loads(raw.decode("utf-8"))
            except Exception:
                body = {}
            subnet = (body.get("subnet") or "").strip()
            client = (body.get("client") or "").strip()
            overrides = {}
            if hn.OVERRIDE_FILE.exists():
                try:
                    overrides = json.loads(hn.OVERRIDE_FILE.read_text())
                except Exception:
                    pass
            if client:
                overrides[subnet] = client
            else:
                overrides.pop(subnet, None)
            hn.RUN.mkdir(mode=0o700, exist_ok=True)
            hn.OVERRIDE_FILE.write_text(json.dumps(overrides, indent=2))
            with hn.Lock():
                hn.sync()
            out = json.dumps({"ok": True}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
            return
        self.send_response(404)
        self.end_headers()


def http_portal_loop():
    try:
        srv = ThreadingHTTPServer(("0.0.0.0", 80), PortalHandler)
        print("Portal de conflicto y redireccionador iniciado en puerto 80", flush=True)
        srv.serve_forever()
    except Exception as e:
        sys.stderr.write(f"AVISO: no se pudo iniciar portal en puerto 80: {e}\\n")


# ================= HTTP =================
def ensure_cert():
    if CERT.exists() and KEY.exists():
        return
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
                    "-subj", "/CN=vpnhub.hub", "-addext", "subjectAltName=DNS:vpnhub.hub,DNS:vpnhub",
                    "-keyout", str(KEY), "-out", str(CERT)], check=True, capture_output=True)
    KEY.chmod(0o600)


class Handler(BaseHTTPRequestHandler):
    server_version = "vpnhub-panel"

    @property
    def client_ip(self):
        return self.client_address[0] if self.client_address else "-"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s %s\n" % (self.address_string(), getattr(self, "uname", "-"), fmt % args))

    def send_json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def get_cookie(self, name):
        h = self.headers.get("Cookie", "")
        for part in h.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                if k.strip() == name:
                    return v.strip()
        return None

    def send_file(self, path, content_type="text/html; charset=utf-8"):
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def authed(self):
        token = self.get_cookie("vpnhub_session")
        if token:
            res = get_session_user(token)
            if res:
                self.uname, self.user = res
                return True

        h = self.headers.get("Authorization", "")
        if h.startswith("Basic "):
            try:
                uname, pw = base64.b64decode(h[6:]).decode().split(":", 1)
                uname = uname.strip().lower()
                u = load_users().get(uname)
                if u and u.get("enabled", True) and verify_pw(u["hash"], pw):
                    exp = u.get("expires")
                    if not (exp and time.time() > exp):
                        # Usuarios con 2FA activo deben usar el login web
                        if not u.get("doble_factor") or u.get("metodo_2fa", "ninguno") == "ninguno":
                            self.uname, self.user = uname, u
                            return True
            except (ValueError, UnicodeDecodeError):
                pass
        return False

    def body(self):
        if hasattr(self, "_cached_body"):
            return self._cached_body
        n = int(self.headers.get("Content-Length", "0") or 0)
        if n > MAX_BODY:
            raise hn.HubError("pedido demasiado grande")
        raw = self.rfile.read(n) if n else b"{}"
        try:
            data = json.loads(raw or b"{}")
        except ValueError as e:
            raise hn.HubError("JSON inválido") from e
        if not isinstance(data, dict):
            raise hn.HubError("JSON inválido")
        self._cached_body = data
        return data

    def require_admin(self):
        if self.user["role"] != "admin":
            raise PermissionError("solo el admin")

    def vpn(self, name, edit=False):
        """Devuelve meta de la VPN si el usuario la puede ver (y editar). Si no, 404 (no revela que existe)."""
        if name not in hn.clients():
            raise LookupError
        m = vpn_meta(name)
        m["name"] = name
        if not can_see(self.user, self.uname, m):
            raise LookupError
        if edit and not can_edit(self.user, self.uname, m):
            raise PermissionError("no tenés permiso para modificar esta VPN")
        return m

    def do_GET(self):
        if self.path == "/favicon.ico":
            if FAVICON_ICO.exists():
                return self.send_file(FAVICON_ICO, content_type="image/x-icon")
            if FAVICON_PNG.exists():
                return self.send_file(FAVICON_PNG, content_type="image/png")
            if FAVICON_SVG.exists():
                return self.send_file(FAVICON_SVG, content_type="image/svg+xml")
            self.send_response(404)
            self.end_headers()
            return

        if self.path in ("/favicon.png", "/favicon.svg"):
            if self.path == "/favicon.png" and FAVICON_PNG.exists():
                return self.send_file(FAVICON_PNG, content_type="image/png")
            if FAVICON_SVG.exists():
                return self.send_file(FAVICON_SVG, content_type="image/svg+xml")
            self.send_response(404)
            self.end_headers()
            return

        if self.path == "/emblem.png":
            if EMBLEM_PNG.exists():
                return self.send_file(EMBLEM_PNG, content_type="image/png")
            self.send_response(404)
            self.end_headers()
            return

        if self.path == "/logo.png":
            if LOGO_PNG.exists():
                return self.send_file(LOGO_PNG, content_type="image/png")
            self.send_response(404)
            self.end_headers()
            return

        if self.path == "/banner.jpg":
            if BANNER_JPG.exists():
                return self.send_file(BANNER_JPG, content_type="image/jpeg")
            self.send_response(404)
            self.end_headers()
            return

        if self.path in ("/", "/index.html"):
            if self.authed():
                return self.send_file(HTML)
            return self.send_file(LOGIN_HTML)

        if self.path == "/login":
            if self.authed():
                self.send_response(302)
                self.send_header("Location", "/")
                self.end_headers()
                return
            return self.send_file(LOGIN_HTML)

        if self.path == "/logout":
            token = self.get_cookie("vpnhub_session")
            if token:
                delete_session(token)
            self.send_response(302)
            self.send_header("Set-Cookie", "vpnhub_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0")
            self.send_header("Location", "/")
            self.end_headers()
            return

        if not self.authed():
            return self.send_json(401, {"error": "unauthorized"})

        try:
            if self.path == "/api/meta":
                self.send_json(200, hn.meta())
            elif self.path == "/api/me":
                self.send_json(200, {"name": self.uname, "role": self.user["role"]})
            elif self.path == "/api/status":
                vis = visible_clients(self.user, self.uname)
                with ThreadPoolExecutor(max_workers=8) as ex:
                    data = list(ex.map(lambda x: client_status(x[0], x[1], self.user, self.uname), vis))
                self.send_json(200, {"clients": data, "time": int(time.time()),
                                     "me": {"name": self.uname, "role": self.user["role"]}})
            elif self.path == "/api/users":
                self.require_admin()
                self.send_json(200, users_list())
            elif self.path.startswith("/api/logs"):
                self.require_admin()
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                cat = qs.get("cat", [""])[0]
                q = qs.get("q", [""])[0]
                try:
                    limit = int(qs.get("limit", [200])[0])
                except (ValueError, TypeError):
                    limit = 200
                logs = read_audit_logs(cat=cat, q=q, limit=limit)
                self.send_json(200, {"ok": True, "logs": logs, "count": len(logs)})
            elif self.path.startswith("/api/traffic/summary"):
                self.require_admin()
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                range_arg = qs.get("range", ["today"])[0]
                user_arg = qs.get("user", [""])[0] or None
                vpn_arg = qs.get("vpn", [""])[0] or None
                custom_date = qs.get("date", [""])[0] or None
                import hubtraffic
                res = hubtraffic.query_summary(range_type=range_arg, user=user_arg, vpn=vpn_arg, custom_date=custom_date)
                self.send_json(200, {"ok": True, "summary": res, **res})
            elif self.path.startswith("/api/traffic/sessions"):
                self.require_admin()
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                range_arg = qs.get("range", ["today"])[0]
                user_arg = qs.get("user", [""])[0] or None
                vpn_arg = qs.get("vpn", [""])[0] or None
                custom_date = qs.get("date", [""])[0] or None
                try:
                    limit = int(qs.get("limit", [100])[0])
                except Exception:
                    limit = 100
                try:
                    offset = int(qs.get("offset", [0])[0])
                except Exception:
                    offset = 0
                import hubtraffic
                res = hubtraffic.query_sessions(range_type=range_arg, user=user_arg, vpn=vpn_arg, custom_date=custom_date, limit=limit, offset=offset)
                self.send_json(200, {"ok": True, "sessions": res, "count": len(res)})
            elif self.path.startswith("/api/traffic/live"):
                self.require_admin()
                import hubtraffic
                res = hubtraffic.query_live()
                self.send_json(200, {"ok": True, "live": res, "sessions": res, "active_count": len(res)})
            elif self.path.startswith("/api/traffic/devices"):
                self.require_admin()
                devs = {}
                if LAN_DEVICES_FILE.exists():
                    try:
                        devs = json.loads(LAN_DEVICES_FILE.read_text())
                    except Exception:
                        pass
                self.send_json(200, {"ok": True, "devices": devs})
            elif self.path.startswith("/api/totp/setup"):
                self.require_admin()
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                target = (qs.get("user", [""])[0] or qs.get("name", [""])[0]).strip().lower()
                sec = generar_secreto_totp(32)
                uri = generar_uri_totp(sec, target or "usuario")
                qr = generar_qr_base64(uri)
                self.send_json(200, {"secret": sec, "uri": uri, "qr": qr, "qr_data_uri": qr})
            elif self.path == "/api/duo/config":
                self.require_admin()
                cfg = load_duo_config()
                client = get_duo_client()
                self.send_json(200, {"configured": bool(client), "ikey": cfg.get("ikey", ""),
                                     "host": cfg.get("host", ""), "has_skey": bool(cfg.get("skey"))})
            elif self.path == "/api/conflicts":
                conf = {}
                if hn.CONFLICTS_FILE.exists():
                    try:
                        conf = json.loads(hn.CONFLICTS_FILE.read_text())
                    except Exception:
                        pass
                self.send_json(200, {"ok": True, "conflicts": conf})
            elif self.path == "/api/me/wireguard" or (m_wg := re.match(r"^/api/users/([a-z0-9_.-]+)/wireguard$", self.path)):
                target_user = self.uname if self.path == "/api/me/wireguard" else m_wg.group(1).lower()
                if target_user != self.uname:
                    self.require_admin()
                    users = load_users()
                    if target_user not in users:
                        return self.send_json(404, {"error": "usuario no encontrado"})
                conf_text = get_or_create_user_wg_conf(target_user)
                data = conf_text.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Disposition", f'attachment; filename="vpnhub-{target_user}.conf"')
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
                self.end_headers()
                self.wfile.write(data)
                audit_log("vpn", "wg_download", f"Perfil WireGuard descargado para '{target_user}' por '{self.uname}'",
                          user=self.uname, ip=self.client_ip, target=target_user)
                return
            elif m := re.match(r"^/api/([a-z0-9_-]+)/config$", self.path):
                self.vpn(m.group(1), edit=True)
                cfg = hn.get_config(m.group(1))
                disabled = cfg.get("disabled", False)
                disabled_by = cfg.get("disabled_by", "")
                cfg["disabled_by_admin"] = disabled and is_admin_user(disabled_by)
                self.send_json(200, cfg)
            elif m := re.match(r"^/api/([a-z0-9_-]+)/log$", self.path):
                name = m.group(1)
                self.vpn(name)
                _, out = run("journalctl", "-u", f"vpnhub@{name}", "-n", "150", "-o", "short-iso", "--no-pager")
                lines = [l for l in out.splitlines() if not re.search(r"pass(word)?\s*[=:]|secret", l, re.I)]
                self.send_json(200, {"log": "\n".join(lines)})
            else:
                self.send_json(404, {"error": "no encontrado"})
        except LookupError:
            self.send_json(404, {"error": "no encontrado"})
        except PermissionError as e:
            self.send_json(403, {"error": str(e)})
        except hn.HubError as e:
            self.send_json(400, {"error": str(e)})

    def do_POST(self):
        if self.path == "/api/login":
            body = self.body()
            uname = (body.get("username") or "").strip().lower()
            pw = body.get("password") or ""
            ip = self.client_ip
            users = load_users()
            u = users.get(uname)
            if not u or not u.get("enabled", True) or not verify_pw(u["hash"], pw):
                time.sleep(1)
                reason = "cuenta deshabilitada" if (u and not u.get("enabled", True)) else "credenciales incorrectas"
                audit_log("auth", "login_fail", f"Intento fallido de login para '{uname or '(vacío)'}' ({reason})",
                          user=uname or "-", ip=ip, level="warn")
                return self.send_json(401, {"error": "Usuario o contraseña incorrectos"})
            exp = u.get("expires")
            if exp and time.time() > exp:
                audit_log("auth", "login_fail", f"Intento fallido de login para '{uname}' (cuenta expirada)",
                          user=uname, ip=ip, level="warn")
                return self.send_json(403, {"error": "Tu cuenta ha expirado. Contactá al administrador."})

            if u.get("must_change_password", False):
                temp_tok = secrets.token_hex(24)
                TEMP_2FA[temp_tok] = {"uname": uname, "created": time.time(), "type": "change_pw", "ip": ip}
                audit_log("auth", "must_change_pw", f"Paso obligatorio de cambio de contraseña para '{uname}'", user=uname, ip=ip)
                return self.send_json(200, {"ok": True, "step": "change_password", "temp_token": temp_tok, "username": uname})

            m2fa = u.get("metodo_2fa", "ninguno")
            if u.get("doble_factor", False) and m2fa != "ninguno":
                trust_tok = self.get_cookie("vpnhub_trusted")
                if is_trusted_device(uname, trust_tok):
                    session_id = create_session(uname, ip)
                    audit_log("auth", "login", f"Inicio de sesión exitoso para '{uname}' (2FA omitido: dispositivo de confianza)", user=uname, ip=ip)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Set-Cookie", f"vpnhub_session={session_id}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000")
                    body_out = json.dumps({"ok": True, "redirect": "/"}).encode()
                    self.send_header("Content-Length", str(len(body_out)))
                    self.end_headers()
                    self.wfile.write(body_out)
                    return
                temp_tok = secrets.token_hex(24)
                if m2fa == "totp":
                    TEMP_2FA[temp_tok] = {"uname": uname, "created": time.time(), "type": "totp", "ip": ip}
                    audit_log("auth", "2fa_prompt", f"Paso 1 completado para '{uname}', solicitando TOTP", user=uname, ip=ip)
                    return self.send_json(200, {"ok": True, "step": "totp", "temp_token": temp_tok, "username": uname})
                elif m2fa == "duo":
                    duo_client = get_duo_client()
                    duo_u = u.get("duo_username") or uname
                    txid = None
                    if duo_client:
                        try:
                            res = duo_client.auth(username=duo_u, factor="push", device="auto",
                                                  type="Hub VPN Login", display_username=uname, async_txn=True)
                            txid = res.get("txid")
                        except Exception as e:
                            audit_log("auth", "duo_error", f"Error enviando Duo push: {e}", user=uname, ip=ip, level="warn")
                    TEMP_2FA[temp_tok] = {"uname": uname, "created": time.time(), "type": "duo",
                                          "txid": txid, "duo_user": duo_u, "ip": ip}
                    audit_log("auth", "2fa_prompt", f"Paso 1 completado para '{uname}', solicitando Duo push/passcode", user=uname, ip=ip)
                    return self.send_json(200, {"ok": True, "step": "duo", "temp_token": temp_tok,
                                                "txid": txid, "username": uname})

            session_id = create_session(uname, ip)
            audit_log("auth", "login", f"Inicio de sesión exitoso para '{uname}' (sin 2FA)", user=uname, ip=ip)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", f"vpnhub_session={session_id}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000")
            body_out = json.dumps({"ok": True, "redirect": "/"}).encode()
            self.send_header("Content-Length", str(len(body_out)))
            self.end_headers()
            self.wfile.write(body_out)
            return

        if self.path == "/api/login/2fa":
            body = self.body()
            temp_tok = body.get("temp_token")
            now = time.time()
            entry = TEMP_2FA.get(temp_tok)
            if not entry or now - entry.get("created", 0) > 300:
                if temp_tok in TEMP_2FA:
                    del TEMP_2FA[temp_tok]
                return self.send_json(400, {"error": "Sesión 2FA expirada. Iniciá sesión nuevamente."})

            uname = entry["uname"]
            users = load_users()
            u = users.get(uname)
            if not u:
                return self.send_json(400, {"error": "Usuario inválido"})

            m2fa = entry["type"]
            verified = False
            ip = self.client_ip
            if m2fa == "totp":
                code = (body.get("code") or body.get("codigo") or "").strip()
                sec = u.get("totp_secret")
                if not sec or not verificar_totp(sec, code):
                    audit_log("auth", "2fa_fail", f"Código TOTP incorrecto o expirado para '{uname}'", user=uname, ip=ip, level="warn")
                    return self.send_json(400, {"error": "Código incorrecto o expirado"})
                verified = True
            elif m2fa == "duo":
                act = body.get("action")
                duo_client = get_duo_client()
                if not duo_client:
                    return self.send_json(400, {"error": "Cisco Duo no está configurado en el servidor"})
                if act == "passcode":
                    code = (body.get("code") or "").strip()
                    try:
                        res = duo_client.auth(username=entry.get("duo_user", uname), factor="passcode", passcode=code)
                        if res.get("result") == "allow":
                            verified = True
                        else:
                            audit_log("auth", "2fa_fail", f"Passcode Duo rechazado para '{uname}'", user=uname, ip=ip, level="warn")
                            return self.send_json(400, {"error": res.get("status_msg") or "Código Duo inválido"})
                    except Exception as e:
                        return self.send_json(400, {"error": f"Error Duo: {e}"})
                elif act == "status":
                    txid = body.get("txid") or entry.get("txid")
                    if not txid:
                        return self.send_json(400, {"error": "Transacción no encontrada"})
                    try:
                        res = duo_client.auth_status(txid=txid)
                        res_code = res.get("result")
                        if res_code == "allow":
                            verified = True
                        elif res_code == "deny":
                            audit_log("auth", "2fa_fail", f"Push Duo rechazado para '{uname}'", user=uname, ip=ip, level="warn")
                            return self.send_json(400, {"status": "deny", "error": "Acceso rechazado en Cisco Duo"})
                        else:
                            return self.send_json(200, {"status": "waiting"})
                    except Exception as e:
                        return self.send_json(400, {"error": f"Error Duo: {e}"})

            if verified:
                del TEMP_2FA[temp_tok]
                session_id = create_session(uname, ip)
                audit_log("auth", "login", f"Inicio de sesión exitoso para '{uname}' (2FA: {m2fa.upper()})", user=uname, ip=ip)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"vpnhub_session={session_id}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000")
                if body.get("trust_device"):
                    dev_tok = register_trusted_device(uname, ip)
                    self.send_header("Set-Cookie", f"vpnhub_trusted={dev_tok}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000")
                    audit_log("auth", "trust_device", f"Dispositivo de confianza registrado por 30 días para '{uname}'", user=uname, ip=ip)
                body_out = json.dumps({"ok": True, "redirect": "/"}).encode()
                self.send_header("Content-Length", str(len(body_out)))
                self.end_headers()
                self.wfile.write(body_out)
                return

        if self.path == "/api/login/change-password":
            body = self.body()
            temp_tok = body.get("temp_token")
            new_pw = (body.get("new_password") or "").strip()
            now = time.time()
            entry = TEMP_2FA.get(temp_tok)
            if not entry or now - entry.get("created", 0) > 600 or entry.get("type") != "change_pw":
                if temp_tok in TEMP_2FA:
                    del TEMP_2FA[temp_tok]
                return self.send_json(400, {"error": "Sesión expirada. Iniciá sesión nuevamente."})

            uname = entry["uname"]
            ip = self.client_ip
            if len(new_pw) < 8:
                return self.send_json(400, {"error": "La nueva contraseña debe tener al menos 8 caracteres"})
            if new_pw.lower() == "admin":
                return self.send_json(400, {"error": "Debés elegir una contraseña diferente a 'admin'"})

            with UserLock():
                users = load_users()
                if uname not in users:
                    return self.send_json(400, {"error": "Usuario no encontrado"})
                users[uname]["hash"] = hash_pw(new_pw)
                users[uname]["must_change_password"] = False
                save_users(users)
                if temp_tok in TEMP_2FA:
                    del TEMP_2FA[temp_tok]

            audit_log("auth", "passwd_initial", f"Usuario '{uname}' definió su contraseña inicial obligatoria", user=uname, ip=ip)
            session_id = create_session(uname, ip)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", f"vpnhub_session={session_id}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000")
            body_out = json.dumps({"ok": True, "redirect": "/"}).encode()
            self.send_header("Content-Length", str(len(body_out)))
            self.end_headers()
            self.wfile.write(body_out)
            return

        if self.path == "/api/logout":
            token = self.get_cookie("vpnhub_session")
            u_name = get_session_user(token) if token else ""
            if token:
                delete_session(token)
            if u_name:
                u_str = u_name[0] if isinstance(u_name, tuple) else u_name
                audit_log("auth", "logout", f"Cierre de sesión de '{u_str}'", user=u_str, ip=self.client_ip)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", "vpnhub_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0")
            body_out = json.dumps({"ok": True, "redirect": "/"}).encode()
            self.send_header("Content-Length", str(len(body_out)))
            self.end_headers()
            self.wfile.write(body_out)
            return

        if not self.authed():
            return self.send_json(401, {"error": "unauthorized"})
        # anti-CSRF: un header propio obliga a preflight CORS, que no se permite
        if self.headers.get("X-Requested-With") != "vpnhub":
            return self.send_json(403, {"error": "falta X-Requested-With"})
        try:
            body = self.body()
            if self.path == "/api/override-route":
                subnet = (body.get("subnet") or "").strip()
                client = (body.get("client") or "").strip()
                with hn.Lock():
                    overrides = {}
                    if hn.OVERRIDE_FILE.exists():
                        try:
                            overrides = json.loads(hn.OVERRIDE_FILE.read_text())
                        except Exception:
                            overrides = {}
                    if client:
                        overrides[subnet] = client
                    else:
                        overrides.pop(subnet, None)
                    hn.RUN.mkdir(mode=0o700, exist_ok=True)
                    hn.OVERRIDE_FILE.write_text(json.dumps(overrides, indent=2))
                    hn.sync()
                audit_log("net", "route_override", f"Ruta real {subnet} asignada a '{client or '(ninguno)'}'",
                          user=self.uname, ip=self.client_ip)
                return self.send_json(200, {"ok": True, "subnet": subnet, "client": client})
            if self.path == "/api/traffic/devices":
                self.require_admin()
                ip_arg = (body.get("ip") or "").strip()
                name_arg = (body.get("name") or "").strip()
                if not ip_arg or not name_arg:
                    return self.send_json(400, {"error": "Faltan ip o name"})
                devs = {}
                if LAN_DEVICES_FILE.exists():
                    try:
                        devs = json.loads(LAN_DEVICES_FILE.read_text())
                    except Exception:
                        pass
                devs[ip_arg] = name_arg
                LAN_DEVICES_FILE.write_text(json.dumps(devs, indent=2))
                LAN_DEVICES_FILE.chmod(0o600)
                try:
                    import hubtraffic
                    with hubtraffic.get_db() as conn:
                        conn.execute("INSERT OR REPLACE INTO lan_devices (ip, name, updated_at) VALUES (?, ?, ?)",
                                     (ip_arg, name_arg, int(time.time())))
                        conn.commit()
                except Exception:
                    pass
                audit_log("system", "device_rename", f"Dispositivo LAN '{ip_arg}' nombrado como '{name_arg}'",
                          user=self.uname, ip=self.client_ip)
                return self.send_json(200, {"ok": True, "ip": ip_arg, "name": name_arg})
            if self.path == "/api/duo/config":
                self.require_admin()
                cfg = load_duo_config()
                if "ikey" in body: cfg["ikey"] = body["ikey"].strip()
                if "host" in body: cfg["host"] = body["host"].strip()
                skey_input = (body.get("skey") or "").strip()
                if skey_input and skey_input != "(sin cambios)":
                    cfg["skey"] = skey_input
                save_duo_config(cfg)
                audit_log("system", "duo_config", "Configuración global de Cisco Duo actualizada",
                          user=self.uname, ip=self.client_ip)
                return self.send_json(200, {"ok": True, "msg": "Configuración de Cisco Duo guardada"})
            if self.path == "/api/duo/test":
                self.require_admin()
                cfg = load_duo_config()
                ikey = (body.get("ikey") or cfg.get("ikey", "")).strip()
                skey = (body.get("skey") or "").strip()
                if not skey or skey == "(sin cambios)":
                    skey = cfg.get("skey", "").strip()
                host = (body.get("host") or cfg.get("host", "")).strip()

                if not ikey or not skey or not host:
                    return self.send_json(400, {"ok": False, "error": "Credenciales de Duo incompletas"})

                try:
                    import duo_client
                    client = duo_client.Auth(ikey=ikey, skey=skey, host=host)
                    client.check()
                    audit_log("system", "duo_test", "Prueba de conexión con Cisco Duo exitosa",
                              user=self.uname, ip=self.client_ip, level="info")
                    return self.send_json(200, {"ok": True, "msg": "Conexión y credenciales verificadas con éxito en Cisco Duo"})
                except Exception as e:
                    audit_log("system", "duo_test", f"Error probando conexión con Cisco Duo: {e}",
                              user=self.uname, ip=self.client_ip, level="warn")
                    return self.send_json(400, {"ok": False, "error": f"Fallo al conectar con Duo: {e}"})
            if self.path == "/api/new":
                personal = body.get("scope") == "personal"
                v_name = body.get("name", "").strip()
                v_type = body.get("type", "")
                cfg = hn.create_client(v_name, v_type, body.get("fields") or {},
                                       body.get("secrets") or {}, owner=self.uname if personal else "",
                                       created_by=self.uname)
                with hn.Lock():
                    hn.sync(cfg["name"])
                started = False
                if body.get("connect") and not hn.missing(cfg["name"]):
                    rc, _ = run(HUBCTL, "up", cfg["name"], timeout=30)
                    started = rc == 0
                    if started:
                        INTENTIONAL_DOWN.discard(v_name)
                        record_vpn_action(v_name, self.uname, "up")
                audit_log("vpn", "create", f"VPN '{v_name}' creada (tipo: {v_type}, uso: {'privada' if personal else 'general'})",
                          user=self.uname, ip=self.client_ip, target=v_name)
                return self.send_json(200, {"ok": True, "config": cfg, "started": started,
                                            "missing": hn.missing(cfg["name"])})
            if self.path == "/api/cert":
                return self.send_json(200, hn.fetch_cert(body.get("server", ""), body.get("port", "443")))
            if self.path == "/api/me/password":
                with UserLock():
                    users = load_users()
                    if not verify_pw(users[self.uname]["hash"], body.get("old", "")):
                        audit_log("auth", "passwd_fail", f"Intento fallido de cambiar contraseña para '{self.uname}'",
                                  user=self.uname, ip=self.client_ip, level="warn")
                        raise hn.HubError("la contraseña actual no es correcta")
                    check_password_policy(body.get("new"))
                    users[self.uname]["hash"] = hash_pw(body["new"])
                    save_users(users)
                    revoke_user_trusted_devices(self.uname)
                audit_log("user", "passwd_self", f"Usuario '{self.uname}' cambió su contraseña",
                          user=self.uname, ip=self.client_ip)
                return self.send_json(200, {"ok": True, "msg": "contraseña cambiada"})
            if self.path == "/api/users":
                self.require_admin()
                return self.send_json(200, users_action(self.uname, body, ip=self.client_ip))

            m = re.match(r"^/api/([a-z0-9_-]+)/(up|down|restart|otp|config|nets|delete)$", self.path)
            if not m:
                return self.send_json(404, {"error": "no encontrado"})
            name, action = m.groups()
            self.vpn(name, edit=action in ("config", "nets", "delete"))
            if action in ("up", "restart"):
                curr_cfg = hn.load(name)
                is_disabled = curr_cfg.get("DISABLED", "0") == "1"
                disabled_by = curr_cfg.get("DISABLED_BY", "")
                disabled_by_admin = is_disabled and is_admin_user(disabled_by)
                is_admin = self.user.get("role") == "admin"
                if is_disabled:
                    if disabled_by_admin and not is_admin:
                        raise hn.HubError("Esta VPN fue deshabilitada por un administrador y no puede ser activada por usuarios.")
                    if not is_admin and curr_cfg.get("OWNER") != self.uname and curr_cfg.get("CREATED_BY") != self.uname:
                        raise hn.HubError("La VPN está deshabilitada. Habilitala desde configuración para conectar.")
                    hn.set_var(name, "DISABLED", "0")
                    hn.set_var(name, "DISABLED_BY", "")
                    audit_log("vpn", "enable", f"VPN '{name}' rehabilitada al conectar",
                              user=self.uname, ip=self.client_ip, target=name)

            if action == "up":
                miss = hn.missing(name)
                if miss:
                    raise hn.HubError("falta cargar: " + ", ".join(miss))
                INTENTIONAL_DOWN.discard(name)
                rc, out = run(HUBCTL, "up", name, timeout=30)
                if rc == 0:
                    record_vpn_action(name, self.uname, "up")
                audit_log("vpn", "up", f"Conexión manual de VPN '{name}' ({'OK' if rc==0 else 'Error'})",
                          user=self.uname, ip=self.client_ip, target=name, level="info" if rc==0 else "error")
            elif action == "down":
                INTENTIONAL_DOWN.add(name)
                rc, out = run(HUBCTL, "down", name, timeout=60)
                record_vpn_action(name, self.uname, "down")
                audit_log("vpn", "down", f"Desconexión manual de VPN '{name}'",
                          user=self.uname, ip=self.client_ip, target=name)
            elif action == "restart":
                INTENTIONAL_DOWN.discard(name)
                rc, out = run("systemctl", "restart", f"vpnhub@{name}", timeout=30)
                if rc == 0:
                    record_vpn_action(name, self.uname, "restart")
                audit_log("vpn", "restart", f"Reinicio manual de VPN '{name}' ({'OK' if rc==0 else 'Error'})",
                          user=self.uname, ip=self.client_ip, target=name, level="info" if rc==0 else "error")
            elif action == "otp":
                otp = str(body.get("otp", ""))
                if not OTP_RE.match(otp):
                    raise hn.HubError("código inválido")
                RUN.mkdir(mode=0o700, exist_ok=True)
                fd = os.open(RUN / f"{name}.otp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w") as fh:
                    fh.write(otp)
                rc, out = run("systemctl", "start", f"vpnhub@{name}", timeout=30)
                if rc == 0:
                    record_vpn_action(name, self.uname, "otp")
                audit_log("vpn", "otp", f"Código OTP ingresado para '{name}'",
                          user=self.uname, ip=self.client_ip, target=name)
            elif action == "config":
                with hn.Lock():
                    curr_cfg = hn.load(name)
                    was_disabled = curr_cfg.get("DISABLED", "0") == "1"
                    was_disabled_by = curr_cfg.get("DISABLED_BY", "")
                    was_disabled_by_admin = was_disabled and is_admin_user(was_disabled_by)
                    is_admin = self.user.get("role") == "admin"

                    disable_action_taken = None
                    if "enabled" in body:
                        want_enabled = bool(body["enabled"])
                        if want_enabled:
                            if was_disabled_by_admin and not is_admin:
                                raise hn.HubError("Esta VPN fue deshabilitada por un administrador. Solo un administrador puede reactivarla.")
                            if was_disabled:
                                hn.set_var(name, "DISABLED", "0")
                                hn.set_var(name, "DISABLED_BY", "")
                                disable_action_taken = "enabled"
                        else:
                            if not was_disabled:
                                hn.set_var(name, "DISABLED", "1")
                                hn.set_var(name, "DISABLED_BY", self.uname)
                                disable_action_taken = "disabled"

                    fields = body.get("fields") or {}
                    fields.pop("DISABLED", None)
                    fields.pop("DISABLED_BY", None)

                    new_name = (body.get("new_name") or body.get("name") or name).strip().lower()
                    if new_name and new_name != name:
                        hn.rename_client(name, new_name)
                        with UserLock():
                            users = load_users()
                            changed = False
                            for u in users.values():
                                if isinstance(u.get("access"), list) and name in u["access"]:
                                    u["access"] = [new_name if x == name else x for x in u["access"]]
                                    changed = True
                            if changed:
                                save_users(users)
                        if hn.OVERRIDE_FILE.exists():
                            try:
                                overrides = json.loads(hn.OVERRIDE_FILE.read_text())
                                ov_changed = False
                                for sn, cl in list(overrides.items()):
                                    if cl == name:
                                        overrides[sn] = new_name
                                        ov_changed = True
                                if ov_changed:
                                    hn.OVERRIDE_FILE.write_text(json.dumps(overrides, indent=2))
                            except Exception:
                                pass
                        with USAGE_LOCK:
                            if name in VPN_USAGE:
                                VPN_USAGE[new_name] = VPN_USAGE.pop(name)
                                save_vpn_usage_locked()
                        audit_log("vpn", "rename", f"VPN renombrada de '{name}' a '{new_name}'",
                                  user=self.uname, ip=self.client_ip, target=new_name)
                        name = new_name

                    cfg = hn.save_config(name, fields, body.get("secrets") or {})
                    scope_changed = False
                    if "scope" in body:
                        new_scope = body["scope"]
                        if new_scope == "personal":
                            old_owner = hn.load(name).get("OWNER", "")
                            hn.set_var(name, "OWNER", old_owner or self.uname)
                            scope_changed = True
                        elif new_scope == "general":
                            hn.set_var(name, "OWNER", "")
                            scope_changed = True
                        cfg = hn.get_config(name)
                    hn.sync(name)

                if disable_action_taken == "disabled":
                    INTENTIONAL_DOWN.add(name)
                    run(HUBCTL, "down", name, timeout=60)
                    audit_log("vpn", "disable", f"VPN '{name}' deshabilitada administrativamente por {self.uname}",
                              user=self.uname, ip=self.client_ip, target=name, level="warn")
                elif disable_action_taken == "enabled":
                    audit_log("vpn", "enable", f"VPN '{name}' habilitada nuevamente por {self.uname}",
                              user=self.uname, ip=self.client_ip, target=name)

                restarted = False
                if body.get("reconnect") and (body.get("enabled", True) if "enabled" in body else not was_disabled):
                    restarted = restart_if_active(name)

                audit_log("vpn", "config", f"Configuración de VPN '{name}' actualizada"
                          f"{' (deshabilitada)' if disable_action_taken=='disabled' else ''}"
                          f"{' (habilitada)' if disable_action_taken=='enabled' else ''}"
                          f"{' (uso modificado)' if scope_changed else ''}"
                          f"{' (reconectando)' if restarted else ''}",
                          user=self.uname, ip=self.client_ip, target=name)
                return self.send_json(200, {"ok": True, "name": name, "config": cfg, "restarted": restarted,
                                            "missing": hn.missing(name)})
            elif action == "nets":
                r_nets = act_nets(name, body)
                audit_log("net", "nets_update", f"Redes de '{name}': {r_nets.get('msg', 'actualizadas')}",
                          user=self.uname, ip=self.client_ip, target=name)
                return self.send_json(200, r_nets)
            else:  # delete
                if body.get("confirm") != name:
                    raise hn.HubError("confirmación incorrecta")
                delete_vpn(name)
                audit_log("vpn", "delete", f"VPN '{name}' eliminada",
                          user=self.uname, ip=self.client_ip, target=name, level="warn")
                return self.send_json(200, {"ok": True})
            self.send_json(200 if rc == 0 else 500, {"ok": rc == 0, "error": None if rc == 0 else out[-300:]})
        except LookupError:
            self.send_json(404, {"error": "no encontrado"})
        except PermissionError as e:
            self.send_json(403, {"error": str(e)})
        except hn.HubError as e:
            self.send_json(400, {"error": str(e)})


# ================= CLI =================
def cli(argv):
    cmd = argv[0]
    with UserLock():
        users = load_users()
        if cmd == "init-default-admin":
            if "admin" not in users:
                users["admin"] = {
                    "hash": hash_pw("admin"),
                    "role": "admin",
                    "enabled": True,
                    "access": "*",
                    "must_change_password": True,
                    "created": int(time.time())
                }
                save_users(users)
                print("Usuario inicial 'admin' creado con contraseña 'admin' (cambio obligatorio en primer login).")
            else:
                print("El usuario 'admin' ya existe.")
            return
        if cmd == "users":
            now = time.time()
            for n, u in sorted(users.items()):
                st = "habilitado" if u.get("enabled", True) else "DESHABILITADO"
                exp = u.get("expires")
                if exp:
                    exp_dt = time.strftime('%Y-%m-%d', time.localtime(exp))
                    st += f" (vence {exp_dt}{' - EXPIRADO' if now > exp else ''})"
                if u.get("must_change_password"):
                    st += " [CAMBIO OBLIGATORIO]"
                print(f"{n:<20} {u['role']:<6} {st:<32}  acceso={u.get('access')}")
            return
        name = (argv[1] if len(argv) > 1 and not argv[1].startswith("--") else input("Usuario: ")).strip().lower()
        if not USER_RE.match(name):
            sys.exit("usuario inválido")
        if cmd == "useradd" and name in users:
            sys.exit("ya existe")
        if cmd == "passwd" and name not in users:
            sys.exit("no existe")

        must_change = "--must-change" in argv
        p1 = None
        for i, a in enumerate(argv):
            if a in ("--password", "-p") and i + 1 < len(argv):
                p1 = argv[i + 1]
                break

        if p1 is None:
            if len(argv) > 2 and not argv[2].startswith("--"):
                p1 = argv[2]
            else:
                p1 = getpass.getpass("Contraseña: ")
                if p1 != getpass.getpass("Repetir: ") or (len(p1) < 8 and not must_change):
                    sys.exit("No coinciden o tiene menos de 8 caracteres.")

        if len(p1) < 8 and not must_change:
            sys.exit("La contraseña debe tener al menos 8 caracteres.")

        if cmd == "useradd":
            users[name] = {"hash": hash_pw(p1), "role": "admin" if "--admin" in argv else "user",
                           "enabled": True, "access": "*", "must_change_password": must_change,
                           "created": int(time.time())}
        else:
            users[name]["hash"] = hash_pw(p1)
            if must_change:
                users[name]["must_change_password"] = True
            elif "must_change_password" in users[name]:
                users[name]["must_change_password"] = False
        save_users(users)
    print("Listo.")


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("useradd", "passwd", "users", "init-default-admin"):
        return cli(sys.argv[1:])
    if not load_users():
        with UserLock():
            users = load_users()
            if not users:
                users["admin"] = {
                    "hash": hash_pw("admin"),
                    "role": "admin",
                    "enabled": True,
                    "access": "*",
                    "must_change_password": True,
                    "created": int(time.time())
                }
                save_users(users)
                print("Inicializado automáticamente usuario 'admin' con contraseña temporal 'admin' (cambio obligatorio).")
    ensure_cert()
    ensure_wg_server()
    load_vpn_usage()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(CERT, KEY)
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"Panel en https://0.0.0.0:{PORT}", flush=True)

    # Iniciar monitor de estado de VPNs, portal HTTP y registrar arranque
    threading.Thread(target=vpn_monitor_loop, daemon=True, name="vpn-monitor").start()
    threading.Thread(target=http_portal_loop, daemon=True, name="http-portal").start()
    audit_log("system", "service_start", f"Servicio vpnhub-panel iniciado (uptime del sistema: {get_system_uptime()})")

    srv.serve_forever()


if __name__ == "__main__":
    main()

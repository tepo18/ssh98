#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

# ========================================================
# Ultimate Proxy Engine (Growing Version)
# ========================================================

import os, re, yaml, socket, time, threading, subprocess, json, base64
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque

# ========================================================
# ----------------- PATHS & FILES ------------------------
# ========================================================
BASE_DIR = "/storage/emulated/0/Download/Akbar98"
os.makedirs(BASE_DIR, exist_ok=True)

INPUT_PATH = os.path.join(BASE_DIR, "input.txt")

with open(INPUT_PATH, "w", encoding="utf-8") as f:
    f.write("")

subprocess.call(["nano", INPUT_PATH])

out_folder = input("Enter output folder in Download (default: Proxies): ").strip() or "Proxies"
OUT_DIR = os.path.join("/storage/emulated/0/Download", out_folder)
os.makedirs(OUT_DIR, exist_ok=True)

out_name = input("Enter output filename (without extension, default: final): ").strip() or "final"
OUT_PATH = os.path.join(OUT_DIR, f"{out_name}.yaml")

# ========================================================
# ----------------- USER PING CONFIG ---------------------
# ========================================================
def read_int(prompt, default):
    try:
        v = input(f"{prompt} [{default}]: ").strip()
        return int(v) if v else default
    except:
        return default

def read_float(prompt, default):
    try:
        v = input(f"{prompt} [{default}]: ").strip()
        return float(v) if v else default
    except:
        return default

PING_ATTEMPTS = read_int("Ping attempts", 5)
PING_TIMEOUT = read_float("Ping timeout (sec)", 1.0)
RECHECK_INTERVAL_MIN = read_int("Recheck interval (min, 0=off)", 5)

GREEN_MAX_MS = read_int("GREEN max ms", 100)
YELLOW_MAX_MS = read_int("YELLOW max ms", 300)

RED_MIN_MS = 1
RED_MAX_MS = 300

MAX_WORKERS = 40
FAST_GROUP_LIMIT = 10
STABLE_GROUP_LIMIT = 10


# --------- Utilities ----------
def b64fix(s):
    if not s:
        return ""
    s = str(s).strip().replace("\n", "").replace(" ", "")
    s = s.replace("-", "+").replace("_", "/")
    pad = len(s) % 4
    if pad:
        s += "=" * (4 - pad)
    return s

def is_probably_base64(s):
    if not isinstance(s, str): return False
    s = s.strip()
    if len(s) < 8: return False
    try:
        base64.b64decode(b64fix(s))
        return True
    except Exception:
        return False

def safe_int(v, default=0):
    try:
        return int(v)
    except Exception:
        try:
            return int(float(v))
        except Exception:
            return default

def sanitize(s):
    if not s: return ""
    return re.sub(r"[^A-Za-z0-9_\- .]", "", str(s)).strip()

_used_names = set()
def uniq_name(base):
    base = sanitize(str(base)) or "Proxy"
    name = base
    i = 2
    while name in _used_names:
        name = f"{base} {i}"
        i += 1
    _used_names.add(name)
    return name

def tail(s, n=6):
    if not s: return ""
    s2 = re.sub(r"[-]", "", str(s))
    return s2[-n:] if len(s2) >= n else s2
    
# ========================================================
# ----------------- TCP PING -----------------------------
# ========================================================
def tcp_ping_once(host, port, timeout=PING_TIMEOUT):
    try:
        start = time.monotonic()
        sock = socket.create_connection((host, int(port)), timeout=timeout)
        sock.close()
        return int((time.monotonic() - start) * 1000)
    except:
        return None

def tcp_ping_median(host, port, attempts=PING_ATTEMPTS, timeout=PING_TIMEOUT, gap=0.08):
    vals = []
    for _ in range(max(1, attempts)):
        v = tcp_ping_once(host, port, timeout)
        if v is not None:
            vals.append(v)
        time.sleep(gap)
    if not vals:
        return None
    vals.sort()
    mid = len(vals) // 2
    return vals[mid] if len(vals) % 2 else (vals[mid-1] + vals[mid]) // 2    

# --------- SAFE MODE PING (TCP handshake only) ----------
# SAFE MODE: prefer conservative timeout so "not definitely dead" proxies survive
def tcp_check(host, port, timeout=1.2):
    # resolve host to IP first (avoid long DNS delays)
    if not host: return None
    try:
        # allow numeric IPv6/IPv4 as well
        addrs = socket.getaddrinfo(host, None)
        if not addrs:
            return None
        addr = addrs[0][4][0]
        family = socket.AF_INET6 if ":" in addr else socket.AF_INET
        t0 = time.monotonic()
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((addr, int(port)))
        sock.close()
        return int((time.monotonic() - t0) * 1000)
    except Exception:
        return None

def tcp_ping_median(host, port, attempts=3, timeout=1.2):
    vals = []
    for _ in range(attempts):
        v = tcp_check(host, port, timeout=timeout)
        if v is not None:
            vals.append(v)
        time.sleep(0.03)
    if not vals:
        return None
    vals.sort()
    m = len(vals) // 2
    return vals[m] if len(vals) % 2 == 1 else int((vals[m-1] + vals[m]) / 2)

# small wrapper used by thread pool
def attach_ping(proxy, attempts=3, timeout=1.2):
    try:
        host = proxy.get("server")
        port = proxy.get("port")
        if not host or not port:
            proxy["ping"] = None
            proxy["status"] = "dead"
            return proxy
        ping = tcp_ping_median(host, port, attempts=attempts, timeout=timeout)
        proxy["ping"] = ping
        proxy["status"] = "ok" if ping is not None else "dead"
        return proxy
    except Exception:
        proxy["ping"] = None
        proxy["status"] = "dead"
        return proxy

# --------- JSON fragments extractor (for YAML/JSON bundles) ----------
def extract_json_objects(text):
    objs = []
    stack = []
    start = None
    for i, c in enumerate(text):
        if c == "{":
            if not stack:
                start = i
            stack.append("{")
        elif c == "}":
            if stack:
                stack.pop()
                if not stack and start is not None:
                    objs.append(text[start:i+1])
                    start = None
    return objs

# --------- Validation (keeps only likely-valid proxies) ----------
def validate_proxy(p):
    if not isinstance(p, dict): return False
    if not p.get("type"): return False
    if not p.get("server"): return False
    port = safe_int(p.get("port", 0))
    if not (1 <= port <= 65535): return False
    t = p.get("type").lower()
    if t in ("vless", "vmess") and not p.get("uuid"): return False
    if t == "trojan" and not p.get("password"): return False
    if t == "ss" and (not p.get("cipher") or not p.get("password")): return False
    if t == "ssr" and (not p.get("password")): return False
    # for wireguard allow public/private key presence or at least server
    if t == "wireguard" and not (p.get("public_key") or p.get("private_key") or p.get("server")): return False
    return True
# --------- PARSERS for many link types ----------

# VLESS
def parse_vless(line):
    try:
        parsed = urlparse(line)
        # urlparse breaks vless sometimes; fallback to manual split
        raw = line[8:]
        frag = ""
        if "#" in raw:
            raw, frag = raw.split("#", 1)
            frag = unquote(frag)
        if "?" in raw:
            main, qs = raw.split("?", 1)
        else:
            main, qs = raw, ""
        if "@" not in main:
            return None
        uid, rest = main.split("@", 1)
        hostport = rest
        host, port = hostport.split(":", 1) if ":" in hostport else (hostport, "443")
        q = dict(x.split("=", 1) for x in qs.split("&") if "=" in x) if qs else {}
        net = (q.get("type") or q.get("network") or "tcp").lower()
        sec = (q.get("security") or "").lower()
        name = frag or q.get("remark") or f"vless-{host}-{tail(uid)}"
        p = {
            "name": uniq_name(name),
            "type": "vless",
            "server": host,
            "port": safe_int(port, 443),
            "uuid": uid,
            "encryption": q.get("encryption") or "none",
            "network": net,
            "udp": True
        }
        if sec in ("tls", "reality"):
            p["tls"] = True
            p["servername"] = q.get("sni") or q.get("host") or host
        if net == "ws":
            ws_path = q.get("path") or "/"
            hosth = q.get("host") or q.get("Host") or ""
            p["ws-opts"] = {"path": ws_path}
            if hosth:
                p["ws-opts"]["headers"] = {"Host": hosth}
        if net in ("grpc",):
            svc = q.get("serviceName") or q.get("service") or ""
            if svc:
                p["grpc-opts"] = {"grpc-service-name": svc}
        # reality specific params
        if sec == "reality" or q.get("pbk") or q.get("sid"):
            p["tls"] = True
            p["reality-opts"] = {"public-key": q.get("pbk", ""), "short-id": q.get("sid", ""), "server-name": q.get("sni") or host}
        return p
    except Exception:
        return None

# VMESS
def parse_vmess(line):
    try:
        raw = line[8:].strip()
        # sometimes people put plain json or urlencoded json
        decoded = None
        try:
            decoded = base64.b64decode(b64fix(raw)).decode("utf-8", "ignore")
            js = json.loads(decoded)
        except Exception:
            try:
                js = json.loads(unquote(raw))
            except Exception:
                return None
        host = js.get("add") or js.get("address") or js.get("server")
        port = safe_int(js.get("port") or js.get("ps") or 0)
        uid = js.get("id") or js.get("uuid")
        if not (host and port and uid):
            return None
        net = (js.get("net") or "tcp").lower()
        name = js.get("ps") or f"vmess-{host}-{tail(uid)}"
        p = {
            "name": uniq_name(name),
            "type": "vmess",
            "server": host,
            "port": port,
            "uuid": uid,
            "alterId": safe_int(js.get("aid", js.get("alterId", 0))),
            "cipher": js.get("cipher") or js.get("scy") or "auto",
            "network": net,
            "udp": True
        }
        if js.get("tls") == "tls":
            p["tls"] = True
            p["servername"] = js.get("sni") or js.get("host") or host
        if net == "ws":
            p["ws-opts"] = {"path": js.get("path") or "/", "headers": {"Host": js.get("host") or ""}}
        if net == "grpc":
            svc = js.get("serviceName") or ""
            if svc:
                p["grpc-opts"] = {"grpc-service-name": svc}
        return p
    except Exception:
        return None

# TROJAN
def parse_trojan(line):
    try:
        parsed = urlparse(line)
        pwd = parsed.username or parsed.netloc.split("@")[0] if "@" in parsed.netloc else parsed.username
        host = parsed.hostname or ""
        port = parsed.port or safe_int(parse_qs(parsed.query).get("port", [443])[0], 443)
        frag = parsed.fragment or ""
        if not host:
            return None
        name = frag or f"trojan-{host}"
        p = {"name": uniq_name(name), "type": "trojan", "server": host, "port": port, "password": pwd, "udp": True, "network": "tcp"}
        q = parse_qs(parsed.query)
        if q.get("sni"): p["sni"] = q.get("sni")[0]
        if q.get("type", ["tcp"])[0] == "ws":
            p["network"] = "ws"
            p["ws-opts"] = {"path": q.get("path", ["/"])[0], "headers": {"Host": q.get("host", [""])[0]}}
        return p
    except Exception:
        return None

# SHADOWSOCKS (ss://)
def parse_ss(line):
    try:
        body = line[5:]
        frag = ""
        if "#" in body:
            body, frag = body.split("#", 1)
            frag = unquote(frag)
        # two modes: method:pass@host:port OR base64-encoded userinfo@host:port
        if "@" in body and ":" in body.split("@", 1)[0]:
            creds, hostport = body.split("@", 1)
            # creds might be base64 or plain user:pass
            try:
                decoded = base64.b64decode(b64fix(creds)).decode("utf-8", "ignore")
                if ":" in decoded:
                    method, password = decoded.split(":", 1)
                else:
                    method, password = creds.split(":", 1)
            except Exception:
                try:
                    method, password = creds.split(":", 1)
                except Exception:
                    return None
            host, port = hostport.split(":", 1)
        else:
            # whole thing base64 encoded: base64(method:pwd@host:port)
            try:
                decoded = base64.b64decode(b64fix(body)).decode("utf-8", "ignore")
                pre, addr = decoded.split("@", 1)
                method, password = pre.split(":", 1)
                host, port = addr.split(":", 1)
            except Exception:
                return None
        if not (host and port):
            return None
        name = frag or f"ss-{host}-{port}"
        p = {"name": uniq_name(name), "type": "ss", "server": host, "port": safe_int(port), "cipher": method, "password": password, "udp": True}
        return p
    except Exception:
        return None

# SSR (ssr://)
def parse_ssr(line):
    try:
        raw = line[6:]
        dec = base64.b64decode(b64fix(raw)).decode("utf-8", "ignore")
        parts = dec.split("/?")
        main = parts[0]
        params = parts[1] if len(parts) > 1 else ""
        server, port, proto, method, obfs, pwd_b64 = main.split(":")
        password = base64.b64decode(b64fix(pwd_b64)).decode("utf-8", "ignore")
        q = {}
        if params:
            qs = parse_qs(params)
            for k, v in qs.items():
                try:
                    q[k] = base64.b64decode(b64fix(v[0])).decode("utf-8", "ignore")
                except Exception:
                    q[k] = v[0]
        name = q.get("remarks") or f"ssr-{server}-{port}"
        p = {"name": uniq_name(name), "type": "ssr", "server": server, "port": safe_int(port), "cipher": method, "password": password, "protocol": proto, "obfs": obfs, "obfs-param": q.get("obfsparam", ""), "protocol-param": q.get("protoparam", ""), "udp": True}
        return p
    except Exception:
        return None

# HYSTERIA (hy://)
def parse_hysteria1(line):
    try:
        raw = line[len("hy://"):]
        frag = ""
        if "#" in raw:
            raw, frag = raw.split("#", 1)
            frag = unquote(frag)
        if "?" in raw:
            main, qs = raw.split("?", 1)
        else:
            main, qs = raw, ""
        if "@" not in main:
            return None
        auth, hostport = main.split("@", 1)
        host, port = hostport.split(":", 1)
        q = dict(x.split("=", 1) for x in qs.split("&") if "=" in qs) if qs else {}
        name = frag or f"hysteria-{host}"
        p = {"name": uniq_name(name), "type": "hysteria", "server": host, "port": safe_int(port), "auth": auth, "sni": q.get("sni", host), "alpn": q.get("alpn", "").split(",") if q.get("alpn") else [], "udp": True}
        return p
    except Exception:
        return None

# HYSTERIA2 (hy2:// or hysteria2://)
def parse_hysteria2(line):
    try:
        raw = line
        if line.startswith("hysteria2://"):
            raw = line[len("hysteria2://"):]
        elif line.startswith("hy2://"):
            raw = line[len("hy2://"):]
        frag = ""
        if "#" in raw:
            raw, frag = raw.split("#", 1); frag = unquote(frag)
        if "?" in raw:
            main, qs = raw.split("?", 1)
        else:
            main, qs = raw, ""
        if "@" not in main:
            return None
        auth, hostport = main.split("@", 1)
        host, port = hostport.split(":", 1)
        user = ""
        pwd = ""
        if ":" in auth:
            user, pwd = auth.split(":", 1)
        else:
            pwd = auth
        q = dict(x.split("=", 1) for x in qs.split("&") if "=" in qs) if qs else {}
        name = frag or f"hysteria2-{host}"
        p = {"name": uniq_name(name), "type": "hysteria2", "server": host, "port": safe_int(port), "password": pwd, "sni": q.get("sni", host), "alpn": q.get("alpn", "").split(",") if q.get("alpn") else [], "udp": True}
        return p
    except Exception:
        return None

# TUIC
def parse_tuic(line):
    try:
        raw = line[len("tuic://"):]
        frag = ""
        if "#" in raw:
            raw, frag = raw.split("#", 1); frag = unquote(frag)
        if "?" in raw:
            main, qs = raw.split("?", 1)
        else:
            main, qs = raw, ""
        if "@" not in main:
            return None
        uidpwd, hostport = main.split("@", 1)
        if ":" in uidpwd:
            uuid, pwd = uidpwd.split(":", 1)
        else:
            uuid, pwd = uidpwd, ""
        host, port = hostport.split(":", 1)
        q = dict(x.split("=", 1) for x in qs.split("&") if "=" in qs) if qs else {}
        name = frag or f"tuic-{host}"
        p = {"name": uniq_name(name), "type": "tuic", "server": host, "port": safe_int(port), "uuid": uuid, "password": pwd, "congestion-controller": q.get("congestion", "bbr"), "alpn": q.get("alpn", "").split(",") if q.get("alpn") else ["h3"], "sni": q.get("sni", host), "udp": True}
        if q.get("zerortt"): p["zeroRTT"] = True
        return p
    except Exception:
        return None

# WIREGUARD (wg:// or inline config)
def parse_wireguard(line):
    try:
        if line.startswith("wg://"):
            parsed = urlparse(line)
            pub = parsed.username
            host = parsed.hostname
            port = parsed.port
            q = parse_qs(parsed.query)
            name = parsed.fragment or f"wg-{host}"
            p = {"name": uniq_name(name), "type": "wireguard", "server": host, "port": port or 51820, "public_key": pub or "", "private_key": q.get("privateKey", [""])[0], "address": q.get("address", [""])[0], "mtu": safe_int(q.get("mtu", [1280])[0]), "udp": True}
            if "dns" in q: p["dns"] = q["dns"]
            if "allowedIPs" in q: p["allowed-ips"] = q["allowedIPs"][0].split(",")
            return p
        else:
            # try parsing inline config: look for PublicKey and Endpoint lines
            cfg = line
            pub = re.search(r"PublicKey\s*=\s*([A-Za-z0-9+/=]+)", cfg)
            endpoint = re.search(r"Endpoint\s*=\s*([^:\n\r]+):?(\d+)?", cfg)
            if endpoint:
                host = endpoint.group(1)
                port = safe_int(endpoint.group(2) or 51820)
            else:
                return None
            pubk = pub.group(1) if pub else ""
            name = f"wg-{host}"
            p = {"name": uniq_name(name), "type": "wireguard", "server": host, "port": port, "public_key": pubk, "udp": True}
            return p
    except Exception:
        return None

# H2 (http2)
def parse_h2(line):
    try:
        parsed = urlparse(line)
        host = parsed.hostname
        port = parsed.port or 443
        q = parse_qs(parsed.query)
        name = parsed.fragment or f"h2-{host}"
        p = {"name": uniq_name(name), "type": "h2", "server": host, "port": port, "tls": True, "servername": q.get("sni", [host])[0], "path": q.get("path", ["/"])[0], "host": q.get("host", [host])[0], "alpn": ["h2"], "udp": True}
        return p
    except Exception:
        return None

# QUIC
def parse_quic(line):
    try:
        parsed = urlparse(line)
        host = parsed.hostname
        port = parsed.port or 443
        q = parse_qs(parsed.query)
        name = parsed.fragment or f"quic-{host}"
        p = {"name": uniq_name(name), "type": "quic", "server": host, "port": port, "key": q.get("key", [""])[0], "alpn": q.get("alpn", ["h3"])[0].split(","), "udp": True}
        if q.get("security", [""])[0] == "reality":
            p["reality"] = {"enabled": True, "public-key": q.get("pbk", [""])[0], "short-id": q.get("sid", [""])[0], "server-name": q.get("sni", [host])[0]}
        return p
    except Exception:
        return None

# REALITY (special vless-like)
def parse_reality(line):
    try:
        parsed = urlparse(line)
        uuid = parsed.username
        host = parsed.hostname
        port = parsed.port or 443
        q = parse_qs(parsed.query)
        name = parsed.fragment or f"reality-{host}"
        p = {"name": uniq_name(name), "type": "vless", "server": host, "port": port, "uuid": uuid, "udp": True, "network": "tcp", "tls": True, "reality-opts": {"public-key": q.get("pbk", [""])[0], "short-id": q.get("sid", [""])[0], "server-name": q.get("sni", [host])[0]}}
        return p
    except Exception:
        return None

# GRPC (standalone)
def parse_grpc(line):
    try:
        parsed = urlparse(line)
        host = parsed.hostname
        port = parsed.port or 443
        q = parse_qs(parsed.query)
        name = parsed.fragment or f"grpc-{host}"
        p = {"name": uniq_name(name), "type": "grpc", "server": host, "port": port, "service": q.get("service", [""])[0], "sni": q.get("sni", [host])[0], "udp": True}
        return p
    except Exception:
        return None

# HTTP / SOCKS quick parsers
def parse_http(line):
    try:
        parsed = urlparse(line)
        host = parsed.hostname
        port = parsed.port
        if not (host and port): return None
        user = parsed.username or ""
        pwd = parsed.password or ""
        name = parsed.fragment or f"http-{host}"
        return {"name": uniq_name(name), "type": "http", "server": host, "port": port, "username": user, "password": pwd, "udp": False}
    except Exception:
        return None

def parse_socks(line):
    try:
        parsed = urlparse(line)
        host = parsed.hostname
        port = parsed.port
        if not (host and port): return None
        user = parsed.username or ""
        pwd = parsed.password or ""
        name = parsed.fragment or f"socks-{host}"
        return {"name": uniq_name(name), "type": "socks5", "server": host, "port": port, "username": user, "password": pwd, "udp": True}
    except Exception:
        return None

# --------- Parse JSON node (xray / sing-box style) ----------
def parse_json_node(obj):
    out = []
    try:
        if not isinstance(obj, dict):
            return out
        outbounds = obj.get("outbounds") or obj.get("proxy") or []
        if isinstance(outbounds, dict):
            outbounds = [outbounds]
        for ob in outbounds:
            if not isinstance(ob, dict):
                continue
            proto = (ob.get("protocol") or ob.get("type") or "").lower()
            # handle vless/vmess
            if proto in ("vless", "vmess"):
                settings = ob.get("settings") or {}
                vnext = settings.get("vnext") or settings.get("servers") or []
                v0 = vnext[0] if vnext else {}
                users = v0.get("users") or v0.get("users", []) or [{}]
                user = users[0] if users else {}
                server = v0.get("address") or v0.get("server") or v0.get("host") or ob.get("address") or ""
                port = safe_int(v0.get("port") or settings.get("port") or ob.get("port") or 0)
                uid = user.get("id") or user.get("uuid") or ""
                if not (server and port):
                    continue
                net = (ob.get("streamSettings") or {}).get("network") or (settings.get("network") or "tcp")
                name = ob.get("tag") or f"{proto}-{server}"
                p = {"name": uniq_name(name), "type": proto, "server": server, "port": port, "network": net, "udp": True}
                if proto == "vless":
                    if uid: p["uuid"] = uid
                    p["encryption"] = "none"
                else:
                    if uid: p["uuid"] = uid
                    p["alterId"] = safe_int(user.get("alterId", user.get("aid", 0)))
                    p["cipher"] = user.get("cipher") or user.get("scy") or "auto"
                # stream settings
                stream = ob.get("streamSettings") or {}
                sec = (stream.get("security") or "").lower()
                if sec in ("tls", "reality"):
                    p["tls"] = True
                    p["servername"] = (stream.get("tlsSettings") or {}).get("serverName") or server
                if net == "ws":
                    wsset = stream.get("wsSettings") or {}
                    p["ws-opts"] = {"path": wsset.get("path", "/")}
                    if wsset.get("headers"): p["ws-opts"]["headers"] = wsset.get("headers")
                if net == "grpc":
                    g = stream.get("grpcSettings") or {}
                    svc = g.get("serviceName") or ""
                    if svc: p["grpc-opts"] = {"grpc-service-name": svc}
                out.append(p)
            elif proto == "trojan":
                settings = ob.get("settings") or {}
                servers = settings.get("servers") or []
                s0 = servers[0] if servers else {}
                server = s0.get("address") or s0.get("server") or ob.get("address") or ""
                port = safe_int(s0.get("port") or ob.get("port") or 443)
                pwd = s0.get("password") or s0.get("pass") or ""
                if not (server and port and pwd): continue
                name = ob.get("tag") or f"trojan-{server}"
                p = {"name": uniq_name(name), "type": "trojan", "server": server, "port": port, "password": pwd, "udp": True}
                out.append(p)
            elif proto in ("shadowsocks", "ss"):
                settings = ob.get("settings") or {}
                servers = settings.get("servers") or []
                s0 = servers[0] if servers else {}
                server = s0.get("address") or s0.get("server") or ob.get("address") or ""
                port = safe_int(s0.get("port") or ob.get("port") or 0)
                method = s0.get("method") or s0.get("cipher") or ""
                pwd = s0.get("password") or s0.get("passwd") or ""
                if not (server and port and method and pwd): continue
                name = ob.get("tag") or f"ss-{server}"
                p = {"name": uniq_name(name), "type": "ss", "server": server, "port": port, "cipher": method, "password": pwd, "udp": True}
                out.append(p)
            elif proto == "ssr":
                # simplified handling if present as servers list
                settings = ob.get("settings") or {}
                servers = settings.get("servers") or []
                s0 = servers[0] if servers else {}
                server = s0.get("address") or ""
                port = safe_int(s0.get("port") or 0)
                method = s0.get("method") or ""
                pwd = s0.get("password") or ""
                proto_s = s0.get("protocol") or ""
                obfs = s0.get("obfs") or ""
                if server and port and pwd:
                    name = ob.get("tag") or f"ssr-{server}"
                    p = {"name": uniq_name(name), "type": "ssr", "server": server, "port": port, "cipher": method, "password": pwd, "protocol": proto_s, "obfs": obfs, "udp": True}
                    out.append(p)
            # additional protocols could be added here similarly...
        return out
    except Exception:
        return []

# --------- YAML nodes parser ----------
def parse_yaml_nodes(text):
    out = []
    try:
        docs = list(yaml.safe_load_all(text))
        for doc in docs:
            if not isinstance(doc, dict): continue
            proxies = doc.get("proxies") or doc.get("proxy") or []
            if isinstance(proxies, dict): proxies = [proxies]
            for p in proxies:
                if isinstance(p, dict) and p.get("type") and p.get("server"):
                    # normalize keys
                    out.append(p)
        return out
    except Exception:
        return []

# --------- base64 subscription bundles (one line may be base64 of newline-delimited links)
def parse_base64_bundle(line):
    out = []
    try:
        raw = b64fix(line.strip())
        dec = base64.b64decode(raw).decode("utf-8", "ignore")
        # if it's JSON
        try:
            js = json.loads(dec)
            out += parse_json_node(js)
        except Exception:
            # treat as lines of url links
            for ln in dec.splitlines():
                ln = ln.strip()
                if not ln: continue
                out += parse_line_any(ln)
        return out
    except Exception:
        return []

# helper to parse one single line into proxy(s)
def parse_line_any(line):
    line = line.strip()
    if not line:
        return []
    line_l = line.lower()
    try:
        if line_l.startswith("vless://"):
            p = parse_vless(line)
            return [p] if p else []
        if line_l.startswith("vmess://"):
            p = parse_vmess(line)
            return [p] if p else []
        if line_l.startswith("trojan://"):
            p = parse_trojan(line)
            return [p] if p else []
        if line_l.startswith("ss://"):
            p = parse_ss(line)
            return [p] if p else []
        if line_l.startswith("ssr://"):
            p = parse_ssr(line)
            return [p] if p else []
        if line_l.startswith("hy://") or line_l.startswith("hysteria://"):
            p = parse_hysteria1(line)
            return [p] if p else []
        if line_l.startswith("hy2://") or line_l.startswith("hysteria2://"):
            p = parse_hysteria2(line)
            return [p] if p else []
        if line_l.startswith("tuic://"):
            p = parse_tuic(line)
            return [p] if p else []
        if line_l.startswith("wg://") or ("[Interface]" in line and "[Peer]" in line):
            p = parse_wireguard(line)
            return [p] if p else []
        if line_l.startswith("h2://"):
            p = parse_h2(line)
            return [p] if p else []
        if line_l.startswith("quic://"):
            p = parse_quic(line)
            return [p] if p else []
        if line_l.startswith("reality://"):
            p = parse_reality(line)
            return [p] if p else []
        if line_l.startswith("grpc://"):
            p = parse_grpc(line)
            return [p] if p else []
        if line_l.startswith("http://") or line_l.startswith("https://"):
            # could be a clash raw yaml location or http proxy line
            # try to treat as http proxy url
            p = parse_http(line)
            return [p] if p else []
        if line_l.startswith("socks://") or line_l.startswith("socks5://"):
            p = parse_socks(line)
            return [p] if p else []
        # fallback: check if it's a base64 subscription
        if is_probably_base64(line):
            return parse_base64_bundle(line)
        # fallback: JSON or YAML block
        if line.startswith("{") and line.endswith("}"):
            try:
                js = json.loads(line)
                return parse_json_node(js)
            except Exception:
                return []
        if ":" in line and "\n" in line:
            return parse_yaml_nodes(line)
    except Exception:
        return []
    return []

# --------- MASTER: parse_any (accepts whole input text) ----------
def parse_any(text):
    proxies = []
    if not text or not text.strip():
        return []
    # first try to find JSON fragments inside text
    for frag in extract_json_objects(text):
        try:
            js = json.loads(frag)
            proxies += parse_json_node(js)
        except Exception:
            pass
    # then treat the whole text as potential YAML
    try:
        yaml_nodes = parse_yaml_nodes(text)
        if yaml_nodes:
            proxies += yaml_nodes
    except Exception:
        pass
    # treat as possible base64-only single line
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    for ln in lines:
        # if line looks like a base64 subscription that decodes to many lines, handle it specially
        if is_probably_base64(ln) and not ln.lower().startswith(("vmess://","vless://","ss://","trojan://","ssr://")):
            proxies += parse_base64_bundle(ln)
            continue
        proxies += parse_line_any(ln)
    # final filter: keep only validated format (we will ping later)
    normalized = []
    for p in proxies:
        if not isinstance(p, dict):
            continue
        # normalize port to int
        p["port"] = int(safe_int(p.get("port", 0)))
        # set default name if missing
        if not p.get("name"):
            p["name"] = uniq_name(f"{p.get('type')}-{p.get('server')}-{tail(p.get('port'))}")
        else:
            p["name"] = uniq_name(p["name"])
        # keep it, will be validated/pinged later
        normalized.append(p)
    return normalized

# --------- dedupe and keep only alive proxies ----------
def dedupe_proxies(proxies):
    final = []
    seen = set()
    for p in proxies:
        if not isinstance(p, dict):
            continue
        key = (p.get("type"), p.get("server"), int(safe_int(p.get("port"))), p.get("uuid") or p.get("password") or "")
        if key in seen:
            continue
        seen.add(key)
        final.append(p)
    return final

# --------- Convert to Clash Meta compatible entries (some normalization) ----------
def to_clash_meta_entry(p):
    # user's p is expected validated and alive
    t = p.get("type").lower()
    base = {
        "name": p.get("name"),
        "type": t,
        "server": p.get("server"),
        "port": int(safe_int(p.get("port"))),
    }
    if t in ("vless",):
        base["uuid"] = p.get("uuid")
        base["encryption"] = p.get("encryption", "none")
        if p.get("network"): base["network"] = p.get("network")
        if p.get("tls"): base["tls"] = True
        if p.get("ws-opts"): base["ws-opts"] = p.get("ws-opts")
        if p.get("grpc-opts"): base["grpc-opts"] = p.get("grpc-opts")
        if p.get("reality-opts"): base["reality-opts"] = p.get("reality-opts")
    elif t in ("vmess",):
        base["uuid"] = p.get("uuid")
        base["alterId"] = safe_int(p.get("alterId", p.get("aid", 0)))
        base["cipher"] = p.get("cipher", "auto")
        if p.get("network"): base["network"] = p.get("network")
        if p.get("ws-opts"): base["ws-opts"] = p.get("ws-opts")
        if p.get("grpc-opts"): base["grpc-opts"] = p.get("grpc-opts")
        if p.get("tls"): base["tls"] = True
    elif t in ("trojan",):
        base["password"] = p.get("password")
        if p.get("sni"): base["sni"] = p.get("sni")
        if p.get("ws-opts"): base["ws-opts"] = p.get("ws-opts")
    elif t in ("ss",):
        base["cipher"] = p.get("cipher")
        base["password"] = p.get("password")
    elif t in ("ssr",):
        base["cipher"] = p.get("cipher")
        base["password"] = p.get("password")
        base["protocol"] = p.get("protocol")
        base["obfs"] = p.get("obfs")
    elif t in ("hysteria","hysteria2"):
        if p.get("password"): base["password"] = p.get("password")
        if p.get("auth"): base["password"] = p.get("auth")
        if p.get("alpn"): base["alpn"] = p.get("alpn")
        if p.get("sni"): base["sni"] = p.get("sni")
    elif t in ("tuic",):
        base["uuid"] = p.get("uuid")
        base["password"] = p.get("password")
        base["congestion-controller"] = p.get("congestion-controller")
        if p.get("alpn"): base["alpn"] = p.get("alpn")
    elif t in ("wireguard",):
        if p.get("public_key"): base["public_key"] = p.get("public_key")
        if p.get("private_key"): base["private_key"] = p.get("private_key")
        if p.get("address"): base["address"] = p.get("address")
    # other fields are preserved if present
    for k in ("udp","network","servername","sni","reality-opts"):
        if k in p and k not in base:
            base[k] = p[k]
    return base

# --------- MAIN flow ----------
def process_input_and_write(input_text, out_path=OUT_PATH, safe_mode=True, ping_attempts=3, ping_timeout=1.2):
    print("[*] Parsing input...")
    parsed = parse_any(input_text)
    if not parsed:
        print("[!] No proxies parsed from input.")
        return False
    print(f"[*] Parsed {len(parsed)} raw proxies. Deduplicating...")
    parsed = dedupe_proxies(parsed)
    print(f"[*] {len(parsed)} unique candidates after dedupe. Validating formats...")
    parsed = [p for p in parsed if validate_proxy(p)]
    print(f"[*] {len(parsed)} candidates passed basic validation. Performing SAFE checks (ping)...")
    alive = []
    # ping in parallel with conservative timeouts (safe mode)
    with ThreadPoolExecutor(max_workers=min(40, max(4, len(parsed)))) as ex:
        futures = { ex.submit(attach_ping, p, attempts=ping_attempts, timeout=ping_timeout): p for p in parsed }
        for fut in as_completed(futures):
            try:
                result = fut.result()
                if result and result.get("status") == "ok":
                    alive.append(result)
            except Exception:
                pass
    if not alive:
        print("[!] No alive proxies found after SAFE checks. Exiting without writing file.")
        return False
    print(f"[*] {len(alive)} alive proxies remain. Converting to Clash Meta entries...")
    # convert and prepare final list (keep only validated again)
    final_entries = []
    for p in alive:
        if not validate_proxy(p): continue
        final_entries.append(to_clash_meta_entry(p))
    # final dedupe by key again
    final_entries = dedupe_proxies(final_entries)
    # final sanity: ensure each has name/server/port
    final_entries = [e for e in final_entries if e.get("name") and e.get("server") and 1 <= safe_int(e.get("port")) <= 65535]
    if not final_entries:
        print("[!] After conversion no valid final proxies remain.")
        return False
    # prepare proxy names for groups
    proxy_names = [p["name"] for p in final_entries]
# ========================================================
# ----------------- LOAD INPUT ---------------------------
# ========================================================
try:
    with open(INPUT_PATH, "r", encoding="utf-8") as f:
        content = f.read()
except:
    content = ""

proxies = []
for ln in content.splitlines():
    ln = ln.strip()
    if ln:
        proxies.extend(parse_line_any(ln))

# ========================================================
# ----------------- DEDUPE -------------------------------
# ========================================================
seen = set()
unique = []
for p in proxies:
    key = (p.get("type"), p.get("server"), p.get("port"))
    if key not in seen:
        seen.add(key)
        unique.append(p)
proxies = unique

# ========================================================
# ----------------- INITIAL PING -------------------------
# ========================================================
final_proxies = []
with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(proxies))) as ex:
    futs = {ex.submit(tcp_ping_median, p["server"], p["port"]): p for p in proxies}
    for fut in as_completed(futs):
        p = futs[fut]
        ping = fut.result()
        p["ping"] = ping
        if ping and RED_MIN_MS <= ping <= RED_MAX_MS:
            p["status"] = "ok"
            final_proxies.append(p)

# ========================================================
# ----------------- SORT & CATEGORIZE --------------------
# ========================================================
good_sorted = sorted(final_proxies, key=lambda x: x["ping"])

fast_sorted = [p for p in good_sorted if p["ping"] <= GREEN_MAX_MS][:FAST_GROUP_LIMIT]
stable_sorted = [p for p in good_sorted if GREEN_MAX_MS < p["ping"] <= YELLOW_MAX_MS][:STABLE_GROUP_LIMIT]

kept = fast_sorted + stable_sorted

fast_names = [p["name"] for p in fast_sorted]
stable_names = [p["name"] for p in stable_sorted]
all_names_output = [p["name"] for p in kept]

# ========================================================
# ----------------- BUILD CONFIG -------------------------
# ========================================================

PING_RANGES = {
    "green": (1, 800),
    "yellow": (801, 5000),
    "red": (5001, 99999),
}

GROUP_SETTINGS = {
    "Auto":     {"min_proxies": 8,  "ping_color": "green"},
    "Stable":   {"min_proxies": 9, "ping_color": "green"},
    "Fallback": {"min_proxies": 5, "ping_color": "green"},
}

def get_group_proxies(group_name):
    settings = GROUP_SETTINGS.get(group_name, {})
    min_proxies = settings.get("min_proxies", 5)
    ping_color = settings.get("ping_color", "green")
    ping_min, ping_max = PING_RANGES.get(ping_color, (1, 99999))

    candidates = [p for p in good_sorted if p.get("status")=="ok" and ping_min <= p.get("ping",0) <= ping_max]
    candidates.sort(key=lambda x: x.get("ping", 99999))

    if len(candidates) < min_proxies:
        backup = [p for p in good_sorted if p.get("status")=="ok"]
        backup.sort(key=lambda x: x.get("ping", 99999))
        for p in backup:
            if p not in candidates:
                candidates.append(p)
            if len(candidates) >= min_proxies:
                break

    return candidates[:min_proxies] if candidates else []

proxy_names = [p["name"] for p in kept]

config = {
    "proxies": final_proxies,
    "proxy-groups": [
    
        {"name": "Select", "type": "select", "proxies":["Auto", "Stable", "Fallback", "DIRECT"] + proxy_names},
        
        {"name": "Auto", "type": "url-test", "url":"https://www.gstatic.com/generate_204", "interval": GROUP_SETTINGS["Auto"]["interval"] if "interval" in GROUP_SETTINGS["Auto"] else 300, "tolerance": GROUP_SETTINGS["Auto"].get("tolerance",3), "proxies":[p["name"] for p in get_group_proxies("Auto")]},
        
        {"name": "Stable", "type": "fallback", "url":"https://www.gstatic.com/generate_204", "interval": GROUP_SETTINGS["Stable"].get("interval",300), "proxies":[p["name"] for p in get_group_proxies("Stable")]},
        
        {"name": "Fallback", "type": "fallback", "url":"https://www.gstatic.com/generate_204", "interval": GROUP_SETTINGS["Fallback"].get("interval",300), "timeout": GROUP_SETTINGS["Fallback"].get("timeout",5), "tolerance": GROUP_SETTINGS["Fallback"].get("tolerance",3), "proxies":[p["name"] for p in get_group_proxies("Fallback")]}
        
    ],
    "rules": ["MATCH,Select"]
}

with open(OUT_PATH, "w", encoding="utf-8") as f:
    yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False)

# ----------------- SMART SWITCH -----------------
MIN_PROXIES = min(50, len(good_sorted))
stable_proxies = good_sorted[:MIN_PROXIES]

ping_history = {p["name"]: deque(maxlen=50) for p in stable_proxies}
stability_score = {p["name"]: 0 for p in stable_proxies}

DEFAULT_PING = 1800
ACTIVE_AVG_THRESHOLD = 800
SLEEP_SLOW = 9
SLEEP_FAST = 2
PING_TIMEOUT = 1

def classify_good_proxies():
    green, yellow = [], []
    for p in good_sorted:
        ping = p.get("ping")
        if ping is None or ping < 1 or ping > PING_TIMEOUT_MAX:
            continue
        if PING_GREEN_MIN <= ping <= PING_GREEN_MAX:
            green.append(p)
        elif PING_YELLOW_MIN <= ping <= PING_YELLOW_MAX:
            yellow.append(p)
    green.sort(key=lambda x: x["ping"])
    yellow.sort(key=lambda x: x["ping"])
    return green, yellow

def update_groups_with_ping():
    for group in config["proxy-groups"]:
        name = group["name"]
        if name in GROUP_SETTINGS:
            group["proxies"] = [p["name"] for p in get_group_proxies(name)]

def smart_auto_switch_advanced():
    if not stable_proxies:
        return
    active = stable_proxies[0]

    while True:
        best = active
        for p in stable_proxies:
            ping = tcp_ping_median(p["server"], p["port"], timeout=PING_TIMEOUT)
            if ping is None or ping < 1 or ping > PING_TIMEOUT_MAX:
                stability_score[p["name"]] = 0
                continue
            ping_history[p["name"]].append(ping)
            stability_score[p["name"]] += 1
            avg_ping = sum(ping_history[p["name"]]) / len(ping_history[p["name"]])
            best_avg = sum(ping_history[best["name"]]) / len(ping_history[best["name"]]) if ping_history[best["name"]] else DEFAULT_PING
            if avg_ping < best_avg:
                best = p

        if best["name"] != active["name"]:
            active = best
            print(f"[⚡] Switched → {active['name']} ({avg_ping:.0f}ms)")

        update_groups_with_ping()

        for group in config["proxy-groups"]:
            if group["name"] == "Fallback":
                if active["name"] in group["proxies"]:
                    group["proxies"].remove(active["name"])
                group["proxies"].insert(0, active["name"])
                break

        with open(OUT_PATH, "w", encoding="utf-8") as f:
            yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False)

        active_avg = sum(ping_history[active["name"]]) / len(ping_history[active["name"]]) if ping_history[active["name"]] else DEFAULT_PING
        time.sleep(SLEEP_SLOW if active_avg < ACTIVE_AVG_THRESHOLD else SLEEP_FAST)

threading.Thread(
    target=smart_auto_switch_advanced,
    daemon=True
).start()
#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-




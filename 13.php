#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os, re, json, socket, time, subprocess, base64, yaml
from urllib.parse import unquote, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque
import threading

# ======================================
# PATHS
# ======================================
BASE_DIR = "/storage/emulated/0/Download/Akbar98"
os.makedirs(BASE_DIR, exist_ok=True)
INPUT_PATH = os.path.join(BASE_DIR, "input.txt")

with open(INPUT_PATH, "w", encoding="utf-8") as f:
    f.write("")
subprocess.call(["nano", INPUT_PATH])

out_folder = input("Enter output folder name in Download: ").strip()
if not out_folder:
    print("Folder name required."); exit(1)
OUT_DIR = os.path.join("/storage/emulated/0/Download", out_folder)
os.makedirs(OUT_DIR, exist_ok=True)

out_name = input("Enter output file name (without extension): ").strip()
if not out_name:
    print("File name required."); exit(1)
OUT_PATH = os.path.join(OUT_DIR, f"{out_name}.yaml")

# ======================================
# HELPERS
# ======================================
def b64fix(s):
    if not s: return ""
    s = s.strip().replace(" ", "").replace("\n", "")
    s = s.replace("-", "+").replace("_", "/")
    return s + "=" * (-len(s) % 4)

def safe_int(x, d=0):
    try: return int(x)
    except: return d

def uniq_name(x):
    base = re.sub(r"[^A-Za-z0-9_\- .\u0600-\u06FF]", "", x or "")
    if not base: base = "Proxy"
    i = 1; name = base
    while name in uniq_name.used:
        i += 1; name = f"{base}-{i}"
    uniq_name.used.add(name)
    return name
uniq_name.used = set()

def extract_parts(raw):
    frag = ""
    if "#" in raw:
        raw, frag = raw.split("#", 1)
        frag = unquote(frag)

    if "?" in raw:
        main, qs = raw.split("?", 1)
        q = {k: v[0] if isinstance(v, list) else v for k, v in parse_qs(qs).items()}
    else:
        main, q = raw, {}

    return main, q, frag

def detect(line):
    l = line.lower()
    if l.startswith("vless://"): return "vless"
    if l.startswith("vmess://"): return "vmess"
    if l.startswith("trojan://"): return "trojan"
    if l.startswith("ss://"): return "ss"
    if l.startswith("hysteria2://"): return "hysteria2"
    return None

# ======================================
# PING
# ======================================
# ---------------- TCP ping ----------------
def tcp_ping_once(host, port, timeout=0.3):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start = time.time()
        sock.connect((host, port))
        sock.close()
        return int((time.time() - start) * 1000)
    except:
        return None

def tcp_ping_median(host, port, attempts=3):
    pings = []
    for _ in range(attempts):
        p = tcp_ping_once(host, port)
        if p is not None: pings.append(p)
    if pings:
        pings.sort()
        mid = len(pings) // 2
        return pings[mid] if len(pings) % 2 else (pings[mid-1]+pings[mid])//2
    return None

def tcp_ping_ms(host, port, timeout=2.0):
    try:
        start = time.monotonic()
        sock = socket.create_connection((host, int(port)), timeout=timeout)
        sock.close()
        return int((time.monotonic() - start) * 1000)
    except Exception:
        return None

def attach_ping(proxy):
    proxy['ping'] = tcp_ping_median(proxy['server'], proxy['port'])
    proxy['status'] = "ok" if proxy['ping'] is not None else "fail"
    return proxy

# ======================================
# PARSERS
# ======================================
def parse_vless(line):
    try:
        raw = line[8:]
        main, q, frag = extract_parts(raw)
        if "@" not in main: return None
        uid, hostport = main.split("@", 1)
        if ":" not in hostport: return None
        host, port = hostport.split(":", 1)

        p = {
            "type": "vless",
            "name": uniq_name(frag or f"VLESS-{host}"),
            "server": host,
            "port": safe_int(port),
            "uuid": uid,
            "udp": True,
            "network": q.get("type", "tcp"),
            "flow": q.get("flow", "")
        }

        sec = q.get("security", "")
        if sec == "tls":
            p["tls"] = True
            p["sni"] = q.get("sni", host)
        if sec == "reality":
            p["tls"] = True
            p["reality"] = True
            p["pbk"] = q.get("pbk", "")
            p["sid"] = q.get("sid", "")
            p["sni"] = q.get("sni", host)

        if p["network"] == "ws":
            p["ws-opts"] = {"path": q.get("path", "/"), "headers": {"Host": q.get("host", host)}}
        if p["network"] == "grpc":
            p["grpc-opts"] = {"grpc-service-name": q.get("serviceName", "")}

        return p
    except:
        return None

def parse_vmess(line):
    try:
        raw = line[8:]
        try: js = json.loads(base64.b64decode(b64fix(raw)).decode())
        except: js = json.loads(unquote(raw))

        host = js.get("add")
        port = js.get("port")
        uuid = js.get("id")
        p = {
            "type": "vmess",
            "name": uniq_name(js.get("ps") or f"VMESS-{host}"),
            "server": host,
            "port": safe_int(port),
            "uuid": uuid,
            "alterId": safe_int(js.get("aid", 0)),
            "cipher": js.get("scy", "auto"),
            "udp": True,
            "network": js.get("net", "tcp")
        }
        if p["network"] == "ws":
            p["ws-opts"] = {"path": js.get("path", "/"), "headers": {"Host": js.get("host", host)}}
        if js.get("tls") == "tls":
            p["tls"] = True
            p["sni"] = js.get("sni", host)
        return p
    except:
        return None

def parse_trojan(line):
    try:
        raw = line[9:]
        main, q, frag = extract_parts(raw)
        pwd, hostport = main.split("@", 1)
        host, port = hostport.split(":", 1)
        p = {"type": "trojan","name": uniq_name(frag or f"TROJAN-{host}"),"server": host,"port": safe_int(port),"password": pwd,"udp": True,"tls": True,"sni": q.get("sni", host)}
        return p
    except:
        return None

def parse_ss(line):
    try:
        raw = line[5:]
        frag = ""
        if "#" in raw: raw, frag = raw.split("#", 1); frag = unquote(frag)
        if "@" not in raw:
            dec = base64.b64decode(b64fix(raw)).decode()
            creds, addr = dec.split("@", 1)
            method, pwd = creds.split(":", 1)
            host, port = addr.split(":", 1)
        else:
            creds, addr = raw.split("@", 1)
            try: dec = base64.b64decode(b64fix(creds)).decode(); method, pwd = dec.split(":", 1)
            except: method, pwd = creds.split(":", 1)
            host, port = addr.split(":", 1)
        return {"type": "ss","name": uniq_name(frag or f"SS-{host}"),"server": host,"port": safe_int(port),"cipher": method,"password": pwd,"udp": True}
    except:
        return None

def parse_hysteria2(line):
    try:
        raw = line[len("hysteria2://"):]
        main, q, frag = extract_parts(raw)
        host, port = main.split(":")
        return {"type": "hysteria2","name": uniq_name(frag or f"HYSTERIA2-{host}"),"server": host,"port": safe_int(port),"auth": q.get("auth", ""),"obfs": q.get("obfs", ""),"obfs-password": q.get("obfs-password", ""),"sni": q.get("sni", host),"udp": True}
    except:
        return None

def parse_link(line):
    proto = detect(line)
    if proto == "vless": return parse_vless(line)
    if proto == "vmess": return parse_vmess(line)
    if proto == "trojan": return parse_trojan(line)
    if proto == "ss": return parse_ss(line)
    if proto == "hysteria2": return parse_hysteria2(line)
    try: return json.loads(line)
    except: return None

def valid(p):
    if not p or not p.get("server") or not p.get("port"): return False
    t = p["type"]
    if t in ("vless", "vmess") and not p.get("uuid"): return False
    if t == "trojan" and not p.get("password"): return False
    if t == "ss" and (not p.get("cipher") or not p.get("password")): return False
    return True

# ======================================
# INPUT
# ======================================
with open(INPUT_PATH, "r", encoding="utf-8") as f:
    lines = [x.strip() for x in f if x.strip()]

parsed = [p for l in lines if valid((p:=parse_link(l)))]

if not parsed:
    print("[ERROR] No valid proxies!"); exit(1)

print("[INFO] Valid proxies:", len(parsed))
proxies = parsed

# ----------------- Attach ping -----------------
results = []
if proxies:
    max_workers = min(40, len(proxies))
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(attach_ping, p): idx for idx,p in enumerate(proxies)}
        for fut in as_completed(futs):
            try: results.append(fut.result())
            except: pass

name_map = {p["name"]: p for p in results} if results else {p["name"]: p for p in proxies}
final_proxies = [name_map.get(p["name"], p) for p in proxies]

good = [p for p in final_proxies if p.get("status")=="ok"]
good_sorted = sorted(good, key=lambda x: x.get("ping", 99999))
proxy_names = [p["name"] for p in final_proxies]

# ----------------- نام گروه‌ها و تنظیمات پیشرفته -----------------


Select  = "🟢SELECT🟢"
Auto     = "🔴AUTO🔴"
Stable  = "🥌STABLE🥌"
Fallback = "🔵FALLBACK🔵"


# رنج ping برای رنگ‌ها (ms)
PING_RANGES = {
    "green": (1, 800),       # سبز سریع
    "yellow": (801, 2500),   # زرد متوسط
    "red": (5000, 99999),    # تایم‌اوت یا خیلی کند
}

# تنظیمات دلخواه گروه‌ها
GROUP_SETTINGS = {
    Auto:      {"min_proxies": 30, "ping_color": "green", "interval": 10000, "tolerance": 1000, "timeout": 100},
    Stable:    {"min_proxies": 20, "ping_color": "green", "interval": 1000, "tolerance": 2000, "timeout": 10000},
    Fallback:  {"min_proxies": 19, "ping_color": "yellow", "interval": 100, "tolerance": 3000, "timeout": 1000},
}


# ----------------- تابع انتخاب پروکسی‌های گروه -----------------
def get_group_proxies(group_name):
    settings = GROUP_SETTINGS.get(group_name, {})
    min_proxies = settings.get("min_proxies", 25)
    ping_color = settings.get("ping_color", "green")
    ping_min, ping_max = PING_RANGES.get(ping_color, (1, 99999))

    # پروکسی‌های سالم در محدوده رنگی
    candidates = [p for p in good_sorted if p.get("status")=="ok" and ping_min <= p.get("ping",0) <= ping_max]
    candidates.sort(key=lambda x: x.get("ping", 99999))

    # اگر تعداد کافی نبود، از کل پروکسی‌های سالم استفاده شود
    if len(candidates) < min_proxies:
        backup = [p for p in good_sorted if p.get("status")=="ok"]
        backup.sort(key=lambda x: x.get("ping", 99999))
        for p in backup:
            if p not in candidates:
                candidates.append(p)
            if len(candidates) >= min_proxies:
                break

    return candidates[:min_proxies] if candidates else []

config = {
    "proxies": final_proxies,
    "proxy-groups": [
    
        {"name": Select, "type": "select", "proxies":[Auto, Stable, Fallback, "DIRECT"] + proxy_names},
        
        {"name": Auto, "type": "url-test", "url":"https://www.gstatic.com/generate_204", "interval": GROUP_SETTINGS[Auto]["interval"], "tolerance": GROUP_SETTINGS[Auto]["tolerance"], "proxies":[p["name"] for p in get_group_proxies(Auto)]},
        
        {"name": Stable, "type": "fallback", "url":"https://www.gstatic.com/generate_204", "interval": GROUP_SETTINGS[Stable]["interval"], "proxies":[p["name"] for p in get_group_proxies(Stable)]},
        
        {"name": Fallback, "type": "fallback", "url":"https://www.gstatic.com/generate_204", "interval": GROUP_SETTINGS[Fallback]["interval"], "timeout": GROUP_SETTINGS[Fallback]["timeout"], "tolerance": GROUP_SETTINGS[Fallback]["tolerance"], "proxies":[p["name"] for p in get_group_proxies(Fallback)]},
        
    ],
    "rules": [f"MATCH,{Select}"]
}

# ذخیره YAML اولیه
with open(OUT_PATH, "w", encoding="utf-8") as f:
    yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False)
    
    # ----------------- سوئیچ هوشمند پیشرفته و تنظیمات دلخواه -----------------
MIN_PROXIES = min(30, len(good_sorted))  # تعداد پروکسی برای سویچ هوشمند
stable_proxies = good_sorted[:MIN_PROXIES]

# تاریخچه پینگ و stability
ping_history = {p['name']: deque(maxlen=50) for p in stable_proxies}
stability_score = {p['name']: 0 for p in stable_proxies}

# تنظیمات هوشمند
DEFAULT_PING = 2500
ACTIVE_AVG_THRESHOLD = 1000
SLEEP_SLOW = 15
SLEEP_FAST = 1
PING_TIMEOUT = 2


# ================== SMART SWITCHING (ONE-PIECE) ==================

# ---------- Ping ranges (ms) ----------
PING_GREEN_MIN = 1
PING_GREEN_MAX = 800

PING_YELLOW_MIN = 801
PING_YELLOW_MAX = 2500

PING_TIMEOUT_MAX = 5000   # بالاتر = حذف
DEFAULT_PING = 2500

# ---------- Group limits ----------
GROUP_SETTINGS = {
    Auto:     {"min_proxies": 20,  "ping_color": "green"},
    Stable:   {"min_proxies": 20, "ping_color": "green"},
    Fallback: {"min_proxies": 30, "ping_color": "green"},
}

# ---------- Helper: classify proxies ----------
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

# ---------- Helper: get proxies for group ----------
def get_group_proxies(group_name):
    settings = GROUP_SETTINGS[group_name]
    limit = settings["min_proxies"]

    green, yellow = classify_good_proxies()
    combined = green + yellow

    return combined[:limit]

# ---------- Update all groups ----------
def update_groups_with_ping():
    for group in config["proxy-groups"]:
        name = group["name"]
        if name in GROUP_SETTINGS:
            group["proxies"] = [p["name"] for p in get_group_proxies(name)]

# ---------- Smart switch settings ----------
MIN_PROXIES = min(50, len(good_sorted))
stable_proxies = good_sorted[:MIN_PROXIES]

ping_history = {p["name"]: deque(maxlen=50) for p in stable_proxies}
stability_score = {p["name"]: 0 for p in stable_proxies}

# ---------- Smart switch ----------
def smart_auto_switch_advanced():
    if not stable_proxies:
        return

    active = stable_proxies[0]

    while True:
        best = active

        for p in stable_proxies:
            ping = tcp_ping_ms(p["server"], p["port"], timeout=PING_TIMEOUT)

            if ping is None or ping < 1 or ping > PING_TIMEOUT_MAX:
                stability_score[p["name"]] = 0
                continue

            ping_history[p["name"]].append(ping)
            stability_score[p["name"]] += 1

            avg_ping = sum(ping_history[p["name"]]) / len(ping_history[p["name"]])
            best_avg = (
                sum(ping_history[best["name"]]) / len(ping_history[best["name"]])
                if ping_history[best["name"]] else DEFAULT_PING
            )

            if avg_ping < best_avg:
                best = p

        if best["name"] != active["name"]:
            active = best
            print(f"[⚡] Switched → {active['name']} ({avg_ping:.0f}ms)")

        # update groups (only green/yellow, sorted, limited)
        update_groups_with_ping()

        # ensure active is first in Fallback
        for group in config["proxy-groups"]:
            if group["name"] == Fallback:
                if active["name"] in group["proxies"]:
                    group["proxies"].remove(active["name"])
                group["proxies"].insert(0, active["name"])
                break

        with open(OUT_PATH, "w", encoding="utf-8") as f:
            yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False)

        active_avg = (
            sum(ping_history[active["name"]]) / len(ping_history[active["name"]])
            if ping_history[active["name"]] else DEFAULT_PING
        )

        time.sleep(SLEEP_SLOW if active_avg < ACTIVE_AVG_THRESHOLD else SLEEP_FAST)

# ---------- Start thread ----------
threading.Thread(
    target=smart_auto_switch_advanced,
    daemon=True
).start()


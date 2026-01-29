#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Ultra Live AutoSwitch Parser – Clash Meta Generator
با سوئیچینگ زنده و خودکار
"""

import os, re, socket, time, base64, yaml, subprocess
from urllib.parse import unquote
from concurrent.futures import ThreadPoolExecutor

# ---------------- Paths ----------------
BASE_DIR = "/storage/emulated/0/Download/ClashMetaParser"
os.makedirs(BASE_DIR, exist_ok=True)
INPUT_PATH = os.path.join(BASE_DIR, "input.txt")

# باز کردن nano برای ورودی
with open(INPUT_PATH,"w",encoding="utf-8") as f: f.write("")
try: subprocess.call(["nano", INPUT_PATH])
except: pass

# مسیر خروجی
out_folder = input("Enter output folder name in Download: ").strip() or "ClashMetaExport"
OUT_DIR = os.path.join("/storage/emulated/0/Download", out_folder)
os.makedirs(OUT_DIR, exist_ok=True)
out_file = input("Enter output file name (without extension): ").strip() or "proxies"
OUT_PATH = os.path.join(OUT_DIR, f"{out_file}.yaml")

# ---------------- Helpers ----------------
def b64fix(s): return s.replace("-", "+").replace("_", "/") + "=" * (-len(s) % 4)
def safe_int(x,d=0): 
    try: return int(x)
    except: return d
def sanitize(s): return re.sub(r'[\n\r]+','',str(s).strip())

_used_names=set()
def uniq_name(base):
    name=base; c=1
    while name in _used_names:
        name=f"{base}-{c}"; c+=1
    _used_names.add(name)
    return name

def split_host_port(hostport):
    if ":" in hostport: h,p=hostport.split(":",1); return h.strip(), safe_int(p)
    return hostport.strip(), None

# ---------------- TCP Ping ----------------
def tcp_ping_once(host,port,timeout=1.0):
    try:
        s=socket.socket(); s.settimeout(timeout)
        t0=time.time(); s.connect((host,port)); s.close()
        return int((time.time()-t0)*1000)
    except: return None

def tcp_ping_median(host,port,n=3):
    results=[p for _ in range(n) if (p:=tcp_ping_once(host,port))]
    if not results: return None
    results.sort(); m=len(results)//2
    return results[m] if len(results)%2 else (results[m-1]+results[m])//2

def attach_ping(proxy):
    proxy["ping"]=tcp_ping_median(proxy["server"],proxy["port"])
    proxy["status"]="ok" if proxy["ping"] is not None else "fail"
    return proxy

# ---------------- Parsers ----------------
def parse_vless(line):
    try:
        if not line.startswith("vless://"): return None
        raw=line[8:]; name=None
        if "#" in raw: raw,name=raw.split("#",1); name=unquote(name)
        creds,_,params=raw.partition("?"); uuid,_,hostport=creds.partition("@")
        host,port=split_host_port(hostport)
        param_dict=dict(p.split("=",1) for p in params.split("&") if "=" in p)
        proxy={"name":uniq_name(name or f"VLESS-{host}-{port}"),"type":"vless","server":host,"port":safe_int(port,443),
               "uuid":uuid,"tls":param_dict.get("security")=="tls","network":param_dict.get("type","tcp"),"mptcp":True,"tfo":True}
        if proxy["network"]=="ws": proxy["ws-opts"]={"path":param_dict.get("path","/"),"headers":{"Host":param_dict.get("host",host)}}
        return proxy
    except: return None

def parse_trojan(line):
    try:
        if not line.startswith("trojan://"): return None
        raw=line[9:]; name=None
        if "#" in raw: raw,name=raw.split("#",1); name=unquote(name)
        creds,_,params=raw.partition("?"); password,_,hostport=creds.partition("@")
        host,port=split_host_port(hostport)
        param_dict=dict(p.split("=",1) for p in params.split("&") if "=" in p)
        proxy={"name":uniq_name(name or f"Trojan-{host}-{port}"),"type":"trojan","server":host,"port":safe_int(port,443),
               "password":password,"tls":True,"network":param_dict.get("type","tcp"),"mptcp":True,"tfo":True}
        if proxy["network"]=="ws": proxy["ws-opts"]={"path":param_dict.get("path","/"),"headers":{"Host":param_dict.get("host",host)}}
        return proxy
    except: return None

def parse_ss(line):
    try:
        if not line.startswith("ss://"): return None
        raw=line[5:]; decoded=base64.urlsafe_b64decode(b64fix(raw.split("#")[0])).decode()
        method_pass,_,hostport=decoded.partition("@"); cipher,password=method_pass.split(":",1)
        host,port=split_host_port(hostport)
        return {"name":uniq_name(f"SS-{host}-{port}"),"type":"ss","server":host,"port":safe_int(port),"cipher":cipher,"password":password,"udp":True}
    except: return None

def parse_ssr(line):
    try:
        if not line.startswith("ssr://"): return None
        raw=base64.urlsafe_b64decode(b64fix(line[6:])).decode()
        items=raw.split(":"); 
        if len(items)<6: return None
        host,port,protocol,method,obfs,pass_b64=items[:6]
        password=base64.urlsafe_b64decode(b64fix(pass_b64)).decode()
        return {"name":uniq_name(f"SSR-{host}-{port}"),"type":"ssr","server":host,"port":safe_int(port),
                "protocol":protocol,"cipher":method,"obfs":obfs,"password":password}
    except: return None

def parse_line(line):
    line=sanitize(line)
    for p in (parse_vless,parse_trojan,parse_ss,parse_ssr):
        if (res:=p(line)): return res
    return None
    
# ---------------- Live AutoSwitch YAML ----------------
def live_autoswitch(proxies):
    # فقط پراکسی‌های OK
    ok = [p for p in proxies if p["status"] == "ok"]
    ok.sort(key=lambda x: x["ping"] if x["ping"] else 9999)

    fast = ok
    fast = ok

    groups = [
        {
            "name": "🌟SELECT",
            "type": "fallback",
            "proxies": [p["name"] for p in ok]
        },
        {
            "name": "🌐 All Proxies",
            "type": "fallback",
            "proxies": [p["name"] for p in ok],
            "url": "https://www.gstatic.com/generate_204",
            "interval": 1
        },
        {
            "name": "⚡ STABLE",
            "type": "fallback",
            "url": "http://clients3.google.com/generate_204",
            "tolerance": 80,
            "interval": 2,
            "proxies": [p["name"] for p in ok]
        },
        {
            "name": "🪀GLOBAL-90",
            "type": "fallback",
            "url": "http://connectivitycheck.gstatic.com/generate_204",
            "interval": 25,
            "proxies": [p["name"] for p in ok]
        },
        {
            "name": "🏆 BestPing",
            "type": "url-test",
            "url": "http://www.gstatic.com/ipranges/cloud.json",
            "tolerance": 10,
            "interval": 15,
            "proxies": [p["name"] for p in ok]
        }
    ]

    return {
        "proxies": proxies,
        "proxy-groups": groups
    }

# ---------------- Main ----------------
if __name__ == "__main__":
    import threading, time
    lines = open(INPUT_PATH, "r", encoding="utf-8").read().splitlines()
    raw_proxies = [p for ln in lines if (p := parse_line(ln))]

    def update_loop():
        while True:
            with ThreadPoolExecutor(max_workers=30) as exe:
                final = list(exe.map(attach_ping, raw_proxies))
            data = live_autoswitch(final)
            with open(OUT_PATH, "w", encoding="utf-8") as f:
                yaml.dump(data, f, allow_unicode=True)
            print(f"[Live AutoSwitch] YAML updated at {time.strftime('%H:%M:%S')}")
            time.sleep(5)  # هر ۵ ثانیه آپدیت خودکار

    threading.Thread(target=update_loop, daemon=True).start()
    print(f"\n✅ Ultra Live AutoSwitch running. Output: {OUT_PATH}")
    print("Press Ctrl-C to exit and stop live updates.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopped by user.")    


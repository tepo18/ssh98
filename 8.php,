#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Ultra Premium AutoSwitch Stable – Live ping filtered, Top Fast & Stable groups
"""

import os, re, socket, time, base64, yaml, subprocess
from urllib.parse import unquote, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor

# ---------------- Paths ----------------
BASE_DIR = "/storage/emulated/0/Download/ClashMetaParser"
os.makedirs(BASE_DIR, exist_ok=True)
INPUT_PATH = os.path.join(BASE_DIR, "input.txt")

with open(INPUT_PATH,"w",encoding="utf-8") as f: f.write("")
try: subprocess.call(["nano", INPUT_PATH])
except: pass

out_folder = input("Enter output folder name in Download: ").strip() or "ClashMetaAutoSwitch"
OUT_DIR = os.path.join("/storage/emulated/0/Download", out_folder)
os.makedirs(OUT_DIR, exist_ok=True)
out_file = input("Enter output file name (without extension): ").strip() or "autoswitch_proxies"
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
def tcp_ping_once(host,port,timeout=0.5):
    try:
        s=socket.socket(); s.settimeout(timeout)
        t0=time.time(); s.connect((host,port)); s.close()
        return int((time.time()-t0)*1000)
    except: return None

def tcp_ping_median(host,port,n=3):
    pings=[p for _ in range(n) if (p:=tcp_ping_once(host,port))]
    if not pings: return None
    pings.sort(); m=len(pings)//2
    return pings[m] if len(pings)%2 else (pings[m-1]+pings[m])//2

def attach_ping(proxy):
    proxy["ping"]=tcp_ping_median(proxy["server"],proxy["port"])
    proxy["status"]="✅" if proxy["ping"] is not None else "❌"
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
        proxy={"name":uniq_name(name or f"VLESS-{host}-{port}"),"type":"vless","server":host,
               "port":safe_int(port,443),"uuid":uuid,"tls":param_dict.get("security")=="tls",
               "network":param_dict.get("type","tcp"),"mptcp":True,"tfo":True}
        if proxy["network"]=="ws": proxy["ws-opts"]={"path":param_dict.get("path","/"),"headers":{"Host":param_dict.get("host",host)}}
        return proxy
    except: return None

def parse_vmess(line):
    try:
        if not line.startswith("vmess://"): return None
        raw=line[8:]; js=None
        try: import json; js=json.loads(base64.b64decode(b64fix(raw)).decode())
        except: js=json.loads(unquote(raw))
        host=js.get("add") or js.get("address"); port=js.get("port"); uuid=js.get("id") or js.get("uuid")
        proxy={"name":uniq_name(js.get("ps") or f"VMESS-{host}-{uuid[-6:]}"),"type":"vmess",
               "server":host,"port":safe_int(port),"uuid":uuid,"alterId":int(js.get("aid",0)),
               "cipher":js.get("scy","auto"),"network":js.get("net","tcp"),"tls":js.get("tls")=="tls"}
        return proxy
    except: return None

def parse_trojan(line):
    try:
        if not line.startswith("trojan://"): return None
        raw=line[9:]; name=None
        if "#" in raw: raw,name=raw.split("#",1); name=unquote(name)
        creds,_,params=raw.partition("?"); password,_,hostport=creds.partition("@")
        host,port=split_host_port(hostport)
        proxy={"name":uniq_name(name or f"Trojan-{host}-{port}"),"type":"trojan","server":host,
               "port":safe_int(port,443),"password":password,"tls":True,"network":params.get("type","tcp"),
               "mptcp":True,"tfo":True}
        return proxy
    except: return None

def parse_ss(line):
    try:
        if not line.startswith("ss://"): return None
        raw=line[5:]; decoded=base64.urlsafe_b64decode(b64fix(raw.split("#")[0])).decode()
        method_pass,_,hostport=decoded.partition("@"); cipher,password=method_pass.split(":",1)
        host,port=split_host_port(hostport)
        return {"name":uniq_name(f"SS-{host}-{port}"),"type":"ss","server":host,"port":safe_int(port),
                "cipher":cipher,"password":password,"udp":True}
    except: return None

def parse_ssr(line):
    try:
        if not line.startswith("ssr://"): return None
        raw=base64.urlsafe_b64decode(b64fix(line[6:])).decode()
        items=raw.split(":")
        if len(items)<6: return None
        host,port,protocol,method,obfs,pass_b64=items[:6]
        password=base64.urlsafe_b64decode(b64fix(pass_b64)).decode()
        return {"name":uniq_name(f"SSR-{host}-{port}"),"type":"ssr","server":host,"port":safe_int(port),
                "protocol":protocol,"cipher":method,"obfs":obfs,"password":password}
    except: return None

def parse_hysteria(line):
    try:
        if not line.lower().startswith("hysteria://"): return None
        raw=line[len("hysteria://"):]
        host,port=split_host_port(raw.split("?")[0])
        return {"name":uniq_name(f"Hysteria-{host}-{port}"),"type":"hysteria","server":host,"port":safe_int(port),
                "protocol":"udp","auth":"","obfs":""}
    except: return None

def parse_tuic(line):
    return {"name":uniq_name("TUIC"),"type":"tuic"} if line.lower().startswith("tuic://") else None

def parse_wireguard(line):
    return {"name":uniq_name("WireGuard"),"type":"wireguard"} if line.lower().startswith("wg://") else None

def parse_line(line):
    line=sanitize(line)
    for p in (parse_vless,parse_vmess,parse_trojan,parse_ss,parse_ssr,parse_hysteria,parse_tuic,parse_wireguard):
        if (res:=p(line)): return res
    return None

# ---------------- Groups ----------------
def generate_groups(proxies):
    alive = [p for p in proxies if p["status"] == "✅" and p.get("ping")]
    alive.sort(key=lambda x: x["ping"])

    top_fast = alive[:15]
    stable = [p for p in alive if p["ping"] < 350][:9]
    top3 = alive[:15]
    all_names = [p["name"] for p in alive]

    return [
        {
            "name": "🥌 Selector",
            "type": "select",
            "proxies": [
                "💚 Top Fast",
                "💛 Top Stable <350ms",
                "⚡ Top 3 AutoSwitch",
                "🔰 Fallback Stable",
                "🌐 All Proxies"
            ]
        },
        {
            "name": "🌐 All Proxies",
            "type": "select",
            "proxies": all_names
        },
        {
            "name": "🔰 Fallback Stable",
            "type": "fallback",
            "proxies": all_names,
            "url": "http://www.google.com/generate_204",
            "interval": 250
        },
        {
            "name": "💚 Top Fast",
            "type": "fallback",
            "proxies": [p["name"] for p in top_fast],
            "url": "http://cp.cloudflare.com/generate_204",
            "interval": 1800  
        },
        {
            "name": "💛 Top Stable <350ms",
            "type": "fallback",
            "proxies": [p["name"] for p in stable],
            "url": "http://cp.cloudflare.com/generate_204",
            "interval": 900
        },
        {
            "name": "⚡ Top 3 AutoSwitch",
            "type": "fallback",
            "proxies": [p["name"] for p in top3],
            "url": "http://www.google.com/generate_204",
            "interval": 800
        }
    ]

# ---------------- Main ----------------
if __name__=="__main__":
    lines=open(INPUT_PATH,"r",encoding="utf-8").read().splitlines()
    proxies=[p for ln in lines if (p:=parse_line(ln))]
    
    with ThreadPoolExecutor(max_workers=30) as exe:
        proxies=list(exe.map(attach_ping, proxies))
    
    alive=[p for p in proxies if p["status"]=="✅"]
    if not alive:
        print("[ERROR] No alive proxies found.")
        exit(1)
    
    alive.sort(key=lambda x:x["ping"])
    
    data={"proxies":alive,"proxy-groups":generate_groups(alive)}
    
    with open(OUT_PATH,"w",encoding="utf-8") as f: yaml.dump(data,f,allow_unicode=True)
    
    print(f"[DONE] Ultra Premium AutoSwitch Stable YAML saved: {OUT_PATH}")


# ---------------- Groups ----------------

def generate_groups(proxies):
    alive = [p for p in proxies if p["status"] == "✅" and p.get("ping")]
    alive.sort(key=lambda x: x["ping"])

    top_fast = alive[:15]
    stable = [p for p in alive if p["ping"] < 150][:15]
    top3 = alive[:13]
    all_names = [p["name"] for p in alive]

    return [
        {
            "name": "🥌 Selector",
            "type": "select",
            "proxies": [
                "💚 Top Fast",
                "💛 Top Stable <150ms",
                "⚡ Top 3 AutoSwitch",
                "🪀Fallback Stable",
                "🌐 All Proxies"
            ]
        },
        {
            "name": "💚 Top Fast",
            "type": "url-test",
            "proxies": [p["name"] for p in top_fast],
            "url": "http://www.google.com/generate_204",
            "interval": 1,
            "tolerance": 50
        },
        {
            "name": "💛 Top Stable <150ms",
            "type": "url-test",
            "proxies": [p["name"] for p in stable],
            "url": "https://www.gstatic.com/generate_204",
            "interval": 1,
            "tolerance": 50
        },
        {
            "name": "⚡ Top 3 AutoSwitch",
            "type": "url-test",
            "proxies": [p["name"] for p in top3],
            "url": "http://clients3.google.com/generate_204",
            "interval": 1,
            "tolerance": 50
        },
        {
            "name": "🪀Fallback Stable",
            "type": "fallback",
            "proxies": all_names,
            "url": "http://www.google.com/generate_204",
            "interval": 2
        },
        {
            "name": "🌐 All Proxies",
            "type": "select",
            "proxies": all_names
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


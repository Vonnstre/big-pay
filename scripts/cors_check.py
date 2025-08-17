#!/usr/bin/env python3
import os, json, subprocess, hashlib, re, time
from urllib.parse import urlparse

SCORING = json.load(open("config/scoring.json"))

def curl(url, origin):
    h = [
        "curl", "-i", "-sS", "-m", "15", "-H", f"Origin: {origin}",
        "-H", "User-Agent: BB-Funnel/1.0", url
    ]
    return subprocess.run(h, capture_output=True, text=True, timeout=20)

def parse_headers(raw):
    headers={}
    for line in raw.splitlines():
        if ":" in line and not line.lower().startswith("http/"):
            k,v=line.split(":",1)
            headers[k.strip().lower()]=v.strip()
    return headers

def run_target(target):
    tdir=f"findings/{target}"
    os.makedirs(tdir, exist_ok=True)
    try:
        endpoints=json.load(open(f"{tdir}/endpoints.json"))
    except: 
        return
    hits=[]
    for url in endpoints[:800]:  # cap per target
        origin=f"https://{hashlib.md5(url.encode()).hexdigest()}.evil.tld"
        r=curl(url, origin)
        raw=r.stdout
        if not raw: continue
        headers=parse_headers(raw)
        acao=headers.get("access-control-allow-origin","")
        acac=headers.get("access-control-allow-credentials","").lower()
        setcookie=True if "set-cookie" in headers else False
        auth_header=any(k in headers for k in ["www-authenticate","authorization"])
        # tight signature
        if acac=="true" and acao==origin and (setcookie or auth_header):
            hits.append({"url":url,"acao":acao,"acac":acac,"set_cookie":setcookie,"auth_hdr":auth_header})
    with open(f"{tdir}/cors.json","w") as f:
        json.dump(hits,f,indent=2)

if __name__=="__main__":
    import sys
    run_target(sys.argv[1])

#!/usr/bin/env python3
import argparse, json, requests, urllib.parse, time
from concurrent.futures import ThreadPoolExecutor

parser = argparse.ArgumentParser()
parser.add_argument('endpoints_json')
parser.add_argument('--out', default='params.json')
parser.add_argument('--threads', type=int, default=10)
args = parser.parse_args()

with open(args.endpoints_json) as f:
    endpoints = json.load(f)

CANDIDATE_PARAMS = ['redirect','next','return','url','callback','dest','continue','redirect_uri','post_login']
ATTACKER = 'https://attacker.example'

results = []

def probe(host):
    findings = []
    base = 'https://' + host
    # add candidate params found in JS/pages
    for p in CANDIDATE_PARAMS:
        try:
            q = {p: ATTACKER}
            r = requests.head(base, params=q, timeout=8, allow_redirects=False)
            loc = r.headers.get('Location','')
            if loc and ATTACKER in loc:
                findings.append({'host':host,'param':p,'location':loc,'code':r.status_code})
        except Exception:
            continue
    return findings

with ThreadPoolExecutor(max_workers=args.threads) as ex:
    futures = [ex.submit(probe, h) for h in endpoints.keys()]
    for f in futures:
        r = f.result()
        if r:
            results.extend(r)

with open(args.out,'w') as f:
    json.dump(results,f,indent=2)
print(f"[+] param fuzz results -> {args.out}")

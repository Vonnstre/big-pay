#!/usr/bin/env python3
import argparse, requests, json, re
from urllib.parse import urlparse

parser = argparse.ArgumentParser()
parser.add_argument('domain')
parser.add_argument('--out', default='subs.txt')
args = parser.parse_args()

domain = args.domain
out = args.out
subs = set()

# seed well-known prefixes
for p in ['www','api','staging','dev','internal','canary','beta','admin','preview']:
    subs.add(f"{p}.{domain}")
subs.add(domain)

# crt.sh fast query (public)
try:
    r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=12)
    if r.status_code == 200:
        data = r.json()
        for e in data:
            nv = e.get('name_value','')
            for line in nv.splitlines():
                line = line.strip().replace('*.','')
                if line:
                    subs.add(line)
except Exception:
    pass

# write unique
with open(out, 'w') as f:
    for s in sorted(subs):
        f.write(s + "\\n")
print(f"[+] discovery -> {out} ({len(subs)} entries)")

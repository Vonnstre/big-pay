#!/usr/bin/env python3
import argparse, json, dns.resolver, requests, time
from scripts.vendor_fingerprints import VENDORS if False else None
# Load vendor fingerprints in this script to keep single-file copy
import os
import json as _json
here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here,'..','config','vendor_fingerprints.json')) as fh:
    VENDORS = _json.load(fh)

parser = argparse.ArgumentParser()
parser.add_argument('subs_file')
parser.add_argument('--out', default='takeovers.json')
args = parser.parse_args()

subs = []
with open(args.subs_file) as f:
    subs = [l.strip() for l in f if l.strip()]

results = []
for s in subs:
    try:
        answers = dns.resolver.resolve(s, 'CNAME')
        for a in answers:
            target = str(a.target).rstrip('.').lower()
            try:
                r = requests.get('https://' + s, timeout=8)
                body = r.text[:2000].lower()
                for name,info in VENDORS.items():
                    for d in info.get('domains',[]):
                        if d in target and info.get('needle','').lower() in body:
                            results.append({'sub': s, 'cname': target, 'vendor': name, 'body_snippet': body[:200]})
            except Exception:
                continue
    except Exception:
        continue
    time.sleep(0.05)

with open(args.out,'w') as f:
    json.dump(results,f,indent=2)
print(f"[+] takeovers -> {args.out}")

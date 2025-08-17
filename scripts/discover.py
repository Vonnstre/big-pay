#!/usr/bin/env python3
import sys, requests, argparse, re

parser = argparse.ArgumentParser()
parser.add_argument('domain')
parser.add_argument('--out', default='subs.txt')
args = parser.parse_args()

domain = args.domain
out = args.out
subs = set()

# seed with base domain and common prefixes
subs.add(domain)
for p in ['www','staging','dev','internal','canary','beta','api','admin']:
    subs.add(f"{p}.{domain}")

# query crt.sh
try:
    url = f'https://crt.sh/?q=%25.{domain}&output=json'
    r = requests.get(url, timeout=15)
    if r.status_code == 200:
        try:
            data = r.json()
            for entry in data:
                name = entry.get('name_value') or ''
                for n in name.split('\n'):
                    n = n.strip()
                    if n:
                        # filter wildcards
                        n = n.replace('*.', '')
                        subs.add(n)
        except Exception:
            pass
except Exception:
    pass

# write out
with open(out, 'w') as f:
    for s in sorted(subs):
        f.write(s + '\n')
print(f'[+] wrote {out} ({len(subs)} entries)')

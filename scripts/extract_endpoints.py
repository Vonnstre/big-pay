#!/usr/bin/env python3
import argparse, requests, json, re
from bs4 import BeautifulSoup

parser = argparse.ArgumentParser()
parser.add_argument('subs_file')
parser.add_argument('--out', default='endpoints.json')
args = parser.parse_args()

param_re = re.compile(r'(?:\\?|&)([a-zA-Z0-9_\\-]+)=')

endpoints = {}
with open(args.subs_file) as f:
    subs = [l.strip() for l in f if l.strip()]

for s in subs:
    url = 'https://' + s
    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
        if r.status_code >= 500:
            continue
        soup = BeautifulSoup(r.text, 'html.parser')
        scripts = [t.get('src') for t in soup.find_all('script') if t.get('src')]
        forms = [str(f) for f in soup.find_all('form')]
        params = set(param_re.findall(r.text))
        title = soup.title.string.strip() if soup.title else ''
        endpoints[s] = {'status': r.status_code, 'title': title, 'scripts': scripts, 'forms': len(forms), 'params': sorted(list(params))}
    except Exception:
        continue

with open(args.out, 'w') as f:
    json.dump(endpoints, f, indent=2)
print(f"[+] endpoints -> {args.out}")

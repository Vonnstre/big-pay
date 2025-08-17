#!/usr/bin/env python3
import argparse, json, os
parser = argparse.ArgumentParser()
parser.add_argument('outdir')
parser.add_argument('--scoring', default='config/scoring.json')
parser.add_argument('--whitelist', default='config/program_whitelist/default.json')
parser.add_argument('--out', default=None)
args = parser.parse_args()

sc = json.load(open(args.scoring))
wl = json.load(open(args.whitelist))

validated = []
# load cors
cors_file = os.path.join(args.outdir,'cors.json')
if os.path.exists(cors_file):
    cors = json.load(open(cors_file))
    for c in cors:
        if c.get('vulnerable'):
            score = int((sc['exploitability']['cors'] * sc['impact']['auth_data_read']) / sc['noise_penalty_default'])
            validated.append({'type':'cors','host':c['host'],'score':score,'meta':c})

# redirects
reds = []
rfile = os.path.join(args.outdir,'redirects.json')
if os.path.exists(rfile):
    try:
        reds = json.load(open(rfile))
    except:
        import json as _j
        for l in open(rfile):
            if l.strip():
                try:
                    reds.append(_j.loads(l.strip()))
                except:
                    pass
for r in reds:
    score = int((sc['exploitability']['redirect_in_auth'] * sc['impact']['phishing']) / sc['noise_penalty_default'])
    validated.append({'type':'redirect','host':r.get('host'),'score':score,'meta':r})

# takeovers
tfile = os.path.join(args.outdir,'takeovers.json')
if os.path.exists(tfile):
    toks = json.load(open(tfile))
    for t in toks:
        score = int((sc['exploitability']['takeover'] * sc['impact']['phishing']) / sc['noise_penalty_default'])
        validated.append({'type':'takeover','host':t.get('sub'),'score':score,'meta':t})

# whitelist filtering
outv = []
for v in validated:
    host = v.get('host') or v['meta'].get('sub')
    skip = False
    for p in wl.get('paths',[]):
        if p in (host or ''):
            skip = True; break
    if not skip:
        # action
        if v['score'] >= sc['auto_draft_threshold']:
            v['action'] = 'auto-draft'
        elif v['score'] >= sc['manual_threshold']:
            v['action'] = 'manual'
        else:
            v['action'] = 'archive'
        outv.append(v)

outf = args.out or os.path.join(args.outdir,'validated.json')
with open(outf,'w') as fh:
    json.dump(outv, fh, indent=2)
print(f"[+] validated -> {outf}")

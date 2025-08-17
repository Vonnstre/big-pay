#!/usr/bin/env python3
# scripts/audit_finalize.py
"""
Read out/findings.json and produce out/decision.csv using conservative finality rules.
"""
import json, csv
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
OUT = BASE_DIR / "out"
data_file = OUT / "findings.json"
if not data_file.exists():
    raise SystemExit("[!] Run scripts/recon_probe.py first.")

j = json.loads(data_file.read_text(encoding="utf-8"))
decisions = []
for item in j:
    host = item["host"]
    flags = [f[1] for f in item.get("flags", [])]
    verdict = "NO"
    rationale = []
    for f in flags:
        lowf = f.lower()
        if "acao * + access-control-allow-credentials: true" in lowf:
            verdict = "HIGH"
            rationale.append(f)
        elif "reflected acao" in lowf and "credentials=true" in lowf:
            verdict = "HIGH"
            rationale.append(f)
        elif "reflected acao" in lowf and verdict != "HIGH":
            verdict = "MEDIUM"
            rationale.append(f)
        elif "expose-headers contains sensitive" in lowf and verdict not in ["HIGH", "MEDIUM"]:
            verdict = "LOW"
            rationale.append(f)
        else:
            rationale.append(f)
    if not flags:
        rationale = ["no flags found"]
    decisions.append({"host": host, "verdict": verdict, "rationale": " | ".join(rationale)})

OUT.mkdir(parents=True, exist_ok=True)
with open(OUT / "decision.csv", "w", newline='', encoding="utf-8") as cf:
    writer = csv.DictWriter(cf, fieldnames=["host","verdict","rationale"])
    writer.writeheader()
    for d in decisions:
        writer.writerow(d)

print(f"[+] Wrote {OUT/'decision.csv'} — review HIGHs first.")

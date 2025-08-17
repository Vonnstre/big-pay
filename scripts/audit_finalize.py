#!/usr/bin/env python3
# scripts/audit_finalize.py
"""
Reads out/findings.json produced by recon_probe.py and writes out/decision.csv.
Finality rules (conservative/aggressive mix).
Fixes: imports and robust handling to avoid NameError on CI.
"""
import os
import json
import csv
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
OUT = BASE_DIR / "out"
file = OUT / "findings.json"
if not file.exists():
    raise SystemExit("[!] run scripts/recon_probe.py first (no findings.json)")

# attacker origin may be supplied from env in CI or local runs
ATTACKER_ORIGIN = os.getenv("ATTACKER_ORIGIN", "https://attacker.test")

data = json.loads(file.read_text(encoding="utf-8"))
decisions = []

for host_entry in data:
    host = host_entry.get("host", "<unknown>")
    verdict = "NO"
    rationale = []

    # collect header-derived info across probes
    header_flags = []
    auth_content_flags = []

    for p in host_entry.get("probes", []):
        # probe-level header checks
        for res in p.get("results", []):
            if not isinstance(res, dict) or "headers" not in res:
                continue
            h = {k.lower(): v for k, v in res["headers"].items()}
            aca = h.get("access-control-allow-origin", "")
            acc = h.get("access-control-allow-credentials", "")
            aceh = h.get("access-control-expose-headers", "")

            # wildcard + creds
            if aca and aca.strip() == "*" and acc and "true" in acc.lower():
                header_flags.append("ACAO * + ACC:true")

            # reflected origin
            if aca and (ATTACKER_ORIGIN.lower() in aca.lower() or (aca.lower().startswith("http") and aca.strip() != "*")):
                header_flags.append(f"Reflected ACAO: {aca}")

            # expose headers sensitive
            if aceh and any(x in aceh.lower() for x in ["authorization", "set-cookie", "cookie", "x-"]):
                header_flags.append(f"Expose-Headers: {aceh}")

        # probe-level heuristics (auth-content heuristics set by recon_probe)
        for (pth, fmsg) in p.get("flags", []):
            # look for phrases used by recon_probe
            if ("Auth response larger" in fmsg) or ("likely authenticated content" in fmsg):
                auth_content_flags.append((p.get("path", pth), fmsg))

    # Decide finality
    # HIGH checks
    if any("ACAO * + ACC:true" in hf for hf in header_flags):
        verdict = "HIGH"
        rationale.append("ACAO * with Access-Control-Allow-Credentials:true")

    # If any reflected ACAO AND ACC:true
    if any("Reflected ACAO" in hf for hf in header_flags) and any("acc:true" in hf.lower() for hf in header_flags):
        verdict = "HIGH"
        rationale.append("Reflected ACAO + Access-Control-Allow-Credentials:true")

    # Authenticated content + ACAO allows read (reflected or wildcard)
    if auth_content_flags and any(hf.startswith("ACAO *") or "Reflected ACAO" in hf for hf in header_flags):
        verdict = "HIGH"
        rationale.append("Authenticated content present AND ACAO allows read")

    # MEDIUM: reflected ACAO without creds
    if verdict != "HIGH" and any("Reflected ACAO" in hf for hf in header_flags):
        verdict = "MEDIUM"
        rationale.append("Reflected ACAO (no ACC:true) — manual PoC required")

    # LOW: expose-headers sensitive
    if verdict == "NO" and any("Expose-Headers" in hf for hf in header_flags):
        verdict = "LOW"
        rationale.append("Access-Control-Expose-Headers contains potentially sensitive items")

    if verdict == "NO" and not header_flags and not auth_content_flags:
        rationale = ["no flags found"]

    # aggregate details
    if header_flags:
        rationale.extend(header_flags)
    if auth_content_flags:
        for pth, fm in auth_content_flags:
            rationale.append(f"Auth-content heuristic: {pth} -> {fm}")

    decisions.append({"host": host, "verdict": verdict, "rationale": " | ".join(rationale)})

# Save CSV
OUT.mkdir(parents=True, exist_ok=True)
out_csv = OUT / "decision.csv"
with open(out_csv, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["host", "verdict", "rationale"])
    writer.writeheader()
    for d in decisions:
        writer.writerow(d)

print(f"[+] Wrote {out_csv} — review HIGHs first.")

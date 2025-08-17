#!/usr/bin/env python3
# scripts/audit_finalize.py
"""
Reads out/findings.json produced by recon_probe.py and writes out/decision.csv.
Finality rules (aggressive):
 - HIGH: any of:
    - ACAO "*" + Access-Control-Allow-Credentials: true (from any probe)
    - Reflected ACAO (echoed origin / ACAO contains attacker origin or http) AND Access-Control-Allow-Credentials:true
    - Authenticated response appears to contain authenticated content (heuristic from recon_probe flags) AND ACAO allows cross-origin read (reflected or *)
 - MEDIUM: Reflected ACAO or ACAO=origin with no credentials header (needs manual PoC)
 - LOW: Expose-Headers contains Authorization/Set-Cookie but ACC false
 - NO: nothing flagged
"""
import json, csv
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
OUT = BASE_DIR / "out"
file = OUT / "findings.json"
if not file.exists():
    raise SystemExit("[!] run scripts/recon_probe.py first")

ATTACKER_ORIGIN = os.getenv("ATTACKER_ORIGIN", "https://attacker.test")

data = json.loads(file.read_text(encoding="utf-8"))
decisions = []
for host_entry in data:
    host = host_entry["host"]
    verdict = "NO"
    rationale = []
    # collect header-derived info across probes
    header_flags = []
    auth_content_flags = []
    for p in host_entry.get("probes", []):
        for res in p.get("results", []):
            if not isinstance(res, dict) or "headers" not in res:
                continue
            h = {k.lower(): v for k,v in res["headers"].items()}
            aca = h.get("access-control-allow-origin","")
            acc = h.get("access-control-allow-credentials","")
            aceh = h.get("access-control-expose-headers","")
            # wildcard + creds
            if aca.strip() == "*" and "true" in acc.lower():
                header_flags.append("ACAO * + ACC:true")
            # reflected origin
            if ATTACKER_ORIGIN.lower() in aca.lower() or (aca.lower().startswith("http") and aca.strip() != "*"):
                header_flags.append(f"Reflected ACAO: {aca}")
            if aceh and any(x in aceh.lower() for x in ["authorization","set-cookie","cookie","x-"]):
                header_flags.append(f"Expose-Headers: {aceh}")
        # aggregate probe-level flags (e.g., auth content heuristics)
        for (path, fmsg) in p.get("flags", []):
            if "Auth response larger" in fmsg or "likely authenticated content" in fmsg:
                auth_content_flags.append((p.get("path"), fmsg))

    # decide
    # HIGH checks
    if any("ACAO * + ACC:true" in hf for hf in header_flags):
        verdict = "HIGH"
        rationale.append("ACAO * with Access-Control-Allow-Credentials:true")
    if any("Reflected ACAO" in hf for hf in header_flags) and any("acc:true" in hf.lower() or "acc:true" in hf for hf in header_flags):
        verdict = "HIGH"
        rationale.append("Reflected ACAO + Access-Control-Allow-Credentials:true")
    # if auth content present and header allows read
    if auth_content_flags and any(("Reflected ACAO" in hf or hf.startswith("ACAO *")) for hf in header_flags):
        verdict = "HIGH"
        rationale.append("Authenticated content present AND ACAO allows read")
    # MEDIUM: reflected ACAO without creds
    if verdict != "HIGH" and any("Reflected ACAO" in hf for hf in header_flags):
        verdict = "MEDIUM"
        rationale.append("Reflected ACAO (no ACC:true)")
    # LOW: expose-headers sensitive
    if verdict == "NO" and any("Expose-Headers" in hf for hf in header_flags):
        verdict = "LOW"
        rationale.append("Expose-Headers contains sensitive items")
    if verdict == "NO" and not header_flags and not auth_content_flags:
        rationale = ["no flags found"]
    # aggregate reasons
    if header_flags:
        rationale.extend(header_flags)
    if auth_content_flags:
        for pth,fm in auth_content_flags:
            rationale.append(f"Auth-content heuristic: {pth} -> {fm}")

    decisions.append({"host": host, "verdict": verdict, "rationale": " | ".join(rationale)})

# save
OUT.mkdir(parents=True, exist_ok=True)
with open(OUT / "decision.csv", "w", newline='', encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["host","verdict","rationale"])
    w.writeheader()
    for d in decisions:
        w.writerow(d)

print(f"[+] Wrote {OUT/'decision.csv'} — review HIGHs first.")

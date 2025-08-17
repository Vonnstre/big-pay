#!/usr/bin/env python3
# scripts/recon_probe.py
"""
Targeted active probes for CORS / GraphQL / header behavior against a list of hosts.
Writes to out/ (create if missing).
"""
import os
import requests
import json
import csv
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
OUT = BASE_DIR / "out"
RAW = OUT / "raw"
OUT.mkdir(parents=True, exist_ok=True)
RAW.mkdir(parents=True, exist_ok=True)

ATTACKER_ORIGIN = os.getenv("ATTACKER_ORIGIN", "https://attacker.test")
TEST_COOKIE = os.getenv("TEST_COOKIE", "session=test")
TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "12"))

hosts_file = BASE_DIR / "hosts.txt"
if not hosts_file.exists():
    raise SystemExit("[!] hosts.txt not found in repo root. Create it with one host per line.")

hosts = [l.strip() for l in hosts_file.read_text().splitlines() if l.strip()]

def safe_req(method, url, headers=None, allow_redirects=True, data=None, json_body=None):
    try:
        if json_body is not None:
            r = requests.request(method, url, headers=headers, json=json_body, timeout=TIMEOUT, allow_redirects=allow_redirects)
        else:
            r = requests.request(method, url, headers=headers, data=data, timeout=TIMEOUT, allow_redirects=allow_redirects)
        return r
    except Exception as e:
        return e

findings = []

for host in hosts:
    base = f"https://{host}"
    entry = {"host": host, "base": base, "probes": []}
    endpoints = ["/", "/.well-known/security.txt", "/graphql", "/api", "/v1", "/version", "/health"]
    endpoints = list(dict.fromkeys(endpoints))

    for path in endpoints:
        url = base.rstrip("/") + (path if path.startswith("/") else "/" + path)
        stamp = int(time.time())
        probe = {"path": path, "url": url, "results": []}

        # OPTIONS preflight simulation
        headers = {
            "Origin": ATTACKER_ORIGIN,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Authorization,Content-Type"
        }
        r = safe_req("OPTIONS", url, headers=headers)
        if isinstance(r, Exception):
            probe["results"].append({"type": "options", "err": str(r)})
        else:
            probe["results"].append({"type": "options", "status_code": r.status_code, "headers": dict(r.headers), "body_sample": (r.text or "")[:2000]})
            raw_file = RAW / f"{host}__options__{path.strip('/').replace('/', '_') or 'root'}__{stamp}.txt"
            raw_file.write_text(f"URL: {url}\n\n==HEADERS==\n{json.dumps(dict(r.headers), indent=2)}\n\n==BODY==\n{r.text[:5000]}", encoding="utf-8")

        # GET with Origin only
        headers = {"Origin": ATTACKER_ORIGIN}
        r2 = safe_req("GET", url, headers=headers)
        if isinstance(r2, Exception):
            probe["results"].append({"type": "get_origin", "err": str(r2)})
        else:
            probe["results"].append({"type": "get_origin", "status_code": r2.status_code, "headers": dict(r2.headers), "body_sample": (r2.text or "")[:2000]})
            raw_file = RAW / f"{host}__get_origin__{path.strip('/').replace('/', '_') or 'root'}__{stamp}.txt"
            raw_file.write_text(f"URL: {url}\n\n==HEADERS==\n{json.dumps(dict(r2.headers), indent=2)}\n\n==BODY==\n{r2.text[:5000]}", encoding="utf-8")

        # GET with Origin + test Cookie
        headers = {"Origin": ATTACKER_ORIGIN, "Cookie": TEST_COOKIE}
        r3 = safe_req("GET", url, headers=headers)
        if isinstance(r3, Exception):
            probe["results"].append({"type": "get_origin_cookie", "err": str(r3)})
        else:
            probe["results"].append({"type": "get_origin_cookie", "status_code": r3.status_code, "headers": dict(r3.headers), "body_sample": (r3.text or "")[:2000]})
            raw_file = RAW / f"{host}__get_origin_cookie__{path.strip('/').replace('/', '_') or 'root'}__{stamp}.txt"
            raw_file.write_text(f"URL: {url}\n\n==HEADERS==\n{json.dumps(dict(r3.headers), indent=2)}\n\n==BODY==\n{r3.text[:5000]}", encoding="utf-8")

        # GraphQL introspection
        if "graphql" in path.lower():
            headers = {"Origin": ATTACKER_ORIGIN, "Content-Type": "application/json"}
            introspect = {"query": "query Introspect{__schema{queryType{name}mutationType{name}types{name kind fields{name}}}}"}
            r4 = safe_req("POST", url, headers=headers, json_body=introspect)
            if isinstance(r4, Exception):
                probe["results"].append({"type": "graphql_introspection", "err": str(r4)})
            else:
                probe["results"].append({"type": "graphql_introspection", "status_code": r4.status_code, "headers": dict(r4.headers), "body_sample": (r4.text or "")[:4000]})
                raw_file = RAW / f"{host}__graphql_introspect__{stamp}.txt"
                raw_file.write_text(f"URL: {url}\n\n==HEADERS==\n{json.dumps(dict(r4.headers), indent=2)}\n\n==BODY==\n{r4.text[:20000]}", encoding="utf-8")

        entry["probes"].append(probe)

    summary_flags = []
    for p in entry["probes"]:
        for r in p["results"]:
            if isinstance(r, dict) and "headers" in r:
                h = {k.lower(): v for k, v in r["headers"].items()}
                aca = h.get("access-control-allow-origin", "")
                acc = h.get("access-control-allow-credentials", "")
                aceh = h.get("access-control-expose-headers", "")
                if aca.strip() == "*" and "true" in acc.lower():
                    summary_flags.append((p["path"], "ACAO * + Access-Control-Allow-Credentials: true"))
                if ATTACKER_ORIGIN.lower() in aca.lower() or aca.lower().startswith("http"):
                    if aca.strip() != "*":
                        summary_flags.append((p["path"], f"Reflected ACAO: {aca}"))
                if "authorization" in (aceh or "").lower() or "set-cookie" in (aceh or "").lower() or "cookie" in (aceh or "").lower():
                    summary_flags.append((p["path"], f"Expose-Headers contains sensitive tokens: {aceh}"))
    entry["flags"] = summary_flags
    findings.append(entry)

with open(OUT / "findings.json", "w", encoding="utf-8") as f:
    json.dump(findings, f, indent=2)

csv_rows = []
for e in findings:
    host = e["host"]
    flags = e.get("flags", [])
    if not flags:
        csv_rows.append({"host": host, "path": "", "flag": "no_flags_detected"})
    else:
        for path, flag in flags:
            csv_rows.append({"host": host, "path": path, "flag": flag})

with open(OUT / "findings.csv", "w", newline='', encoding="utf-8") as csvf:
    writer = csv.DictWriter(csvf, fieldnames=["host","path","flag"])
    writer.writeheader()
    for r in csv_rows:
        writer.writerow(r)

print(f"[+] Done. Wrote {OUT/'findings.json'} and {OUT/'findings.csv'} and raw responses to {RAW}")

#!/usr/bin/env python3
# scripts/recon_probe.py
"""
Aggressive recon probe with authenticated checks and robust evidence saving.

Outputs to out/:
 - out/findings.json  (detailed per-host probes + flags)
 - out/findings.csv   (flattened quick view)
 - out/decision.csv   (HIGH/MEDIUM/LOW/NO final verdicts)
 - out/raw/           (raw saved bodies + .meta.json for headers/status)

Env:
 - ATTACKER_ORIGIN   (optional) default https://attacker.test
 - TEST_COOKIE       (optional)
 - AUTH_BEARER       (optional) Bearer token for authenticated tests
 - SESSION_COOKIE    (optional) session cookie for authenticated tests
 - REQUEST_TIMEOUT   (optional) default 12
"""
from pathlib import Path
import os, time, json, sys, mimetypes
from urllib.parse import urljoin
import requests

BASE_DIR = Path(__file__).resolve().parent.parent
OUT = BASE_DIR / "out"
RAW = OUT / "raw"
OUT.mkdir(parents=True, exist_ok=True)
RAW.mkdir(parents=True, exist_ok=True)

ATTACKER_ORIGIN = os.getenv("ATTACKER_ORIGIN", "https://attacker.test")
TEST_COOKIE = os.getenv("TEST_COOKIE", "")
AUTH_BEARER = os.getenv("AUTH_BEARER", "").strip()
SESSION_COOKIE = os.getenv("SESSION_COOKIE", "").strip()
TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "12"))

# Retry wrapper
def do_request(method, url, headers=None, data=None, json_body=None, allow_redirects=True, retries=2):
    last_exc = None
    for attempt in range(retries+1):
        try:
            if json_body is not None:
                r = requests.request(method, url, headers=headers, json=json_body, timeout=TIMEOUT, allow_redirects=allow_redirects)
            else:
                r = requests.request(method, url, headers=headers, data=data, timeout=TIMEOUT, allow_redirects=allow_redirects)
            return r
        except Exception as e:
            last_exc = e
            time.sleep(1 + attempt*2)
    return last_exc

def safe_filename(s: str) -> str:
    return "".join(c if (c.isalnum() or c in "._-") else "_" for c in s)[:200]

def ext_from_content_type(ct: str) -> str:
    if not ct:
        return ".bin"
    ct = ct.split(";", 1)[0].strip().lower()
    if ct.endswith("/json") or ct == "application/json":
        return ".json"
    if ct.startswith("text/"):
        if "html" in ct:
            return ".html"
        return ".txt"
    guess = mimetypes.guess_extension(ct)
    return guess or ".bin"

def write_meta_and_body(host, path, probe_type, resp):
    ts = int(time.time())
    base_name = f"{safe_filename(host)}__{safe_filename(path or 'root')}__{probe_type}__{ts}"
    meta = {
        "host": host,
        "path": path,
        "probe": probe_type,
        "url": getattr(resp, "url", ""),
        "status_code": getattr(resp, "status_code", None),
        "headers": dict(getattr(resp, "headers", {}) or {}),
        "timestamp": ts
    }
    ct = meta["headers"].get("content-type", "")
    ext = ext_from_content_type(ct)
    # write bytes
    try:
        body_bytes = resp.content
    except Exception:
        body_bytes = b""

    target = RAW / (base_name + ext)
    try:
        if ext in (".txt", ".json", ".html"):
            enc = getattr(resp, "encoding", None) or "utf-8"
            text = body_bytes.decode(enc, errors="replace")
            target.write_text(text, encoding="utf-8")
        else:
            target.write_bytes(body_bytes)
    except Exception:
        # fallback to writing raw bytes as .bin
        (RAW / (base_name + ".bin")).write_bytes(body_bytes if body_bytes else b"")
    # write meta
    (RAW / (base_name + ".meta.json")).write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return str(target), (RAW / (base_name + ".meta.json")).name

def probe_one(host, path, attacker_origin=ATTACKER_ORIGIN):
    base = f"https://{host}"
    url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
    base_headers = {
        "User-Agent": "AggressiveRecon/1.0",
        "Accept": "application/json, text/*;q=0.8, */*;q=0.1"
    }
    results = []
    # 1) OPTIONS (preflight)
    headers = dict(base_headers)
    headers.update({
        "Origin": attacker_origin,
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "Authorization,Content-Type"
    })
    r = do_request("OPTIONS", url, headers=headers)
    if isinstance(r, Exception):
        results.append({"type":"options","err":str(r)})
    else:
        path_saved, meta_name = write_meta_and_body(host, path, "options", r)
        results.append({"type":"options","status":r.status_code,"path_saved":path_saved,"meta":meta_name, "headers": dict(r.headers)})

    # 2) GET with Origin only (unauth)
    headers = dict(base_headers); headers["Origin"] = attacker_origin
    r2 = do_request("GET", url, headers=headers)
    if isinstance(r2, Exception):
        results.append({"type":"get_origin","err":str(r2)})
        unauth_len = 0
    else:
        path_saved, meta_name = write_meta_and_body(host, path, "get_origin", r2)
        results.append({"type":"get_origin","status":r2.status_code,"path_saved":path_saved,"meta":meta_name,"headers": dict(r2.headers)})
        unauth_len = len(r2.content or b"")

    # 3) GET with Origin + test cookie (if provided)
    if TEST_COOKIE:
        headers = dict(base_headers); headers["Origin"]=attacker_origin; headers["Cookie"]=TEST_COOKIE
        r3 = do_request("GET", url, headers=headers)
        if isinstance(r3, Exception):
            results.append({"type":"get_origin_testcookie","err":str(r3)})
        else:
            path_saved, meta_name = write_meta_and_body(host, path, "get_origin_testcookie", r3)
            results.append({"type":"get_origin_testcookie","status":r3.status_code,"path_saved":path_saved,"meta":meta_name,"headers": dict(r3.headers)})

    # 4) GraphQL introspection if path suggests graphql
    if "graphql" in path.lower():
        headers = dict(base_headers); headers["Origin"]=attacker_origin; headers["Content-Type"]="application/json"
        introspect = {"query":"query Introspect{__schema{queryType{name}mutationType{name}types{name kind fields{name}}}}"}
        r4 = do_request("POST", url, headers=headers, json_body=introspect)
        if isinstance(r4, Exception):
            results.append({"type":"graphql_introspection","err":str(r4)})
        else:
            path_saved, meta_name = write_meta_and_body(host, path, "graphql_introspect", r4)
            results.append({"type":"graphql_introspection","status":r4.status_code,"path_saved":path_saved,"meta":meta_name,"headers": dict(r4.headers)})

    # AUTHENTICATED PROBES
    # 5) GET with Bearer token (if provided)
    auth_len = 0
    if AUTH_BEARER:
        headers = dict(base_headers); headers["Origin"]=attacker_origin; headers["Authorization"]=f"Bearer {AUTH_BEARER}"
        r_auth = do_request("GET", url, headers=headers)
        if isinstance(r_auth, Exception):
            results.append({"type":"get_origin_authorization","err":str(r_auth)})
        else:
            path_saved, meta_name = write_meta_and_body(host, path, "get_origin_authorization", r_auth)
            results.append({"type":"get_origin_authorization","status":r_auth.status_code,"path_saved":path_saved,"meta":meta_name,"headers": dict(r_auth.headers)})
            auth_len = len(r_auth.content or b"")

    # 6) GET with session cookie (if provided)
    sess_len = 0
    if SESSION_COOKIE:
        headers = dict(base_headers); headers["Origin"]=attacker_origin; headers["Cookie"]=SESSION_COOKIE
        r_sess = do_request("GET", url, headers=headers)
        if isinstance(r_sess, Exception):
            results.append({"type":"get_origin_session_cookie","err":str(r_sess)})
        else:
            path_saved, meta_name = write_meta_and_body(host, path, "get_origin_session_cookie", r_sess)
            results.append({"type":"get_origin_session_cookie","status":r_sess.status_code,"path_saved":path_saved,"meta":meta_name,"headers": dict(r_sess.headers)})
            sess_len = len(r_sess.content or b"")

    # Collate quick heuristics for flags:
    flags = []
    # Check headers of the unauth OPTIONS/GET for CORS leakage
    for ritem in results:
        if not isinstance(ritem, dict) or "headers" not in ritem:
            continue
        h = {k.lower(): v for k, v in ritem["headers"].items()}
        aca = h.get("access-control-allow-origin","")
        acc = h.get("access-control-allow-credentials","")
        aceh = h.get("access-control-expose-headers","")
        # wildcard + creds
        if aca.strip() == "*" and "true" in acc.lower():
            flags.append((path, "ACAO * + Access-Control-Allow-Credentials: true"))
        # reflected origin heuristic
        if ATTACKER_ORIGIN.lower() in aca.lower() or (aca.lower().startswith("http") and aca.strip() != "*"):
            flags.append((path, f"Reflected ACAO: {aca}"))
        if aceh and any(token in aceh.lower() for token in ["authorization","set-cookie","cookie","x-"]):
            flags.append((path, f"Expose-Headers contains sensitive tokens: {aceh}"))

    # Compare authenticated vs unauth body lengths for a quick auth-content heuristic
    if (auth_len and auth_len > unauth_len * 2):
        flags.append((path, f"Auth response larger than unauth (auth_len={auth_len}, unauth_len={unauth_len}) - likely authenticated content"))
    if (sess_len and sess_len > unauth_len * 2):
        flags.append((path, f"Session-auth response larger than unauth (sess_len={sess_len}, unauth_len={unauth_len}) - likely authenticated content"))

    return {"host":host, "path":path, "url":url, "results":results, "flags": flags}

def main():
    hosts_file = BASE_DIR / "hosts.txt"
    if not hosts_file.exists():
        print("[!] hosts.txt missing in repo root")
        sys.exit(1)
    hosts = [l.strip() for l in hosts_file.read_text().splitlines() if l.strip()]
    endpoints = ["/", "/.well-known/security.txt", "/graphql", "/api", "/v1", "/version", "/health"]
    findings = []
    for host in hosts:
        print(f"=== probing {host}")
        host_entry = {"host": host, "probes": []}
        for path in endpoints:
            try:
                res = probe_one(host, path)
                host_entry["probes"].append(res)
                if res.get("flags"):
                    print(f"[FLAG] {host} {path} -> {res['flags']}")
            except Exception as e:
                print(f"[ERR] {host} {path}: {e}")
        # flatten host flags
        all_flags = []
        for p in host_entry["probes"]:
            all_flags.extend(p.get("flags", []))
        host_entry["flags"] = all_flags
        findings.append(host_entry)

    # Save detailed JSON
    (OUT / "findings.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")

    # Flatten CSV
    import csv
    rows = []
    for h in findings:
        if not h["flags"]:
            rows.append({"host": h["host"], "path": "", "flag": "no_flags_detected"})
        else:
            for path,flag in h["flags"]:
                rows.append({"host": h["host"], "path": path, "flag": flag})
    with open(OUT / "findings.csv", "w", newline='', encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["host","path","flag"])
        w.writeheader()
        for r in rows:
            w.writerow(r)

    print(f"[+] Wrote {OUT/'findings.json'} and {OUT/'findings.csv'} and raw responses to {RAW}")

if __name__ == "__main__":
    BASE_DIR = Path(__file__).resolve().parent.parent
    main()

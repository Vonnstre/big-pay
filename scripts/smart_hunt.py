#!/usr/bin/env python3
import argparse, asyncio, aiohttp, os, json, hashlib, re, time, zipfile, tldextract, socket
from collections import defaultdict
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl
from vendor_fingerprints import VENDORS

REDACTION_PATTERNS = [
    re.compile(r'(api|secret|token|key|pwd|pass|bearer|authorization)[=:]\s*([A-Za-z0-9._-]{10,})', re.I),
    re.compile(r'["\']([A-Za-z0-9_\-]{16,})["\']')
]

AUTH_HINT = re.compile(r'(login|sign[\s_-]*in|reset password|2fa|mfa|oauth|authorize)', re.I)
ADMIN_MARKERS = re.compile(r'grafana|kibana|jenkins|sonarqube|nexus repository|pgadmin|prometheus|kubernetes dashboard|rabbitmq|airflow|superset|laravel horizon', re.I)

AUTO_DRAFT_THRESHOLD = 50

def sha256(s: bytes) -> str:
    return hashlib.sha256(s).hexdigest()

def redacted_snippet(b: bytes, limit_kb=64):
    if len(b) > limit_kb*1024:
        head = b[:200]
        tail = b[-200:]
        h = sha256(b)
        return h, head, tail, True
    return sha256(b), b, b"", False

def redact_text(txt: str) -> str:
    out = txt
    for pat in REDACTION_PATTERNS:
        out = pat.sub(lambda m: m.group(0)[:min(20, len(m.group(0)))] + "[REDACTED]", out)
    return out

def mkcurl(url, headers=None):
    h = headers or {}
    parts = ' '.join([f"-H '{k}: {v}'" for k,v in h.items()])
    return f"curl -i -s '{url}' {parts}"

def ensure_dir(p):
    os.makedirs(p, exist_ok=True)

def score(kind, auth=False, noisy=2):
    weight_auth = 1.6 if auth else 1.0
    table_ex = dict(cors=9, redirect_auth=8, takeover=7, admin=7, nuclei=6)
    table_im = dict(cors=9 if auth else 5, redirect_auth=7, takeover=6, admin=5, nuclei=5)
    ex = table_ex.get(kind, 5)
    im = table_im.get(kind, 4)
    s = int((ex*im*weight_auth) // max(noisy,1))
    return s

async def fetch(session, method, url, headers=None, allow_redirects=False):
    try:
        async with session.request(method, url, headers=headers or {}, allow_redirects=allow_redirects, timeout=15) as r:
            body = await r.read()
            return dict(
                ok=True, status=r.status, url=str(r.url),
                headers={k.lower(): v for k,v in r.headers.items()},
                body=body
            )
    except Exception as e:
        return dict(ok=False, error=str(e), status=0, url=url, headers={}, body=b"")

def with_query(u, kv):
    p = urlparse(u)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q.update(kv)
    return urlunparse(p._replace(query=urlencode(q, doseq=True)))

def host_only(u):
    try:
        return urlparse(u).hostname or ""
    except:
        return ""

async def check_cors(session, url):
    origin = "https://evil.attacker.tld"
    base = await fetch(session, "GET", url, headers={})
    test = await fetch(session, "GET", url, headers={"Origin": origin, "Cookie": "session=stub"})
    if not base["ok"] or not test["ok"]:
        return None
    h = {k.lower():v for k,v in test["headers"].items()}
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "")
    set_cookie_present = "set-cookie" in h
    authish = set_cookie_present or ("www-authenticate" in h) or base["status"] in (401,403)

    if acac.lower() == "true" and acao and acao != "*" and origin in acao:
        return dict(kind="cors", auth=authish, base=base, test=test, origin=origin)
    return None

REDIRECT_PARAMS = ["next","redirect","redirect_uri","return","return_to","continue","url","goto","dest","destination","post_auth_return"]
ATTACK_URL = "https://example.org/"

async def check_redirects(session, url):
    # Only bother with likely auth-y paths
    if not AUTH_HINT.search(url):  # (we also catch simple /login etc because httpx included titles)
        parsed = urlparse(url)
        if not re.search(r'/login|/signin|/auth|/oauth|/reset', parsed.path, re.I):
            return None

    for p in REDIRECT_PARAMS:
        test_url = with_query(url, {p: ATTACK_URL})
        r = await fetch(session, "GET", test_url, allow_redirects=False)
        loc = r["headers"].get("location","")
        if r["ok"] and r["status"] in (301,302,303,307,308) and ATTACK_URL in loc:
            return dict(kind="redirect_auth", param=p, resp=r, test_url=test_url)
    return None

def takeover_vendor(cnames: list[str]) -> str|None:
    for c in cnames or []:
        for vendor, fp in VENDORS.items():
            if any(pat in c for pat in fp.get("cname_contains", [])):
                return vendor
    return None

async def check_takeover(session, host, scheme="https"):
    # We trust httpx json for CNAMEs first, else a quick HEAD to scheme://host/
    url = f"{scheme}://{host}/"
    r = await fetch(session, "GET", url)
    body = r["body"].decode(errors="ignore")
    hdrs = r["headers"]
    for vendor, fp in VENDORS.items():
        ok = False
        for sig in fp.get("body_contains", []):
            if sig.lower() in body.lower():
                ok = True; break
        if not ok:
            for sig in fp.get("header_contains", []):
                if sig.lower() in json.dumps(hdrs).lower():
                    ok = True; break
        if ok:
            return dict(kind="takeover", vendor=vendor, resp=r)
    return None

async def check_admin_panel(session, url):
    r = await fetch(session, "GET", url)
    if not r["ok"] or r["status"] in (401,403):
        return None
    text = r["body"].decode(errors="ignore")
    if ADMIN_MARKERS.search(text) and not re.search(r'csrf token|forbidden', text, re.I):
        return dict(kind="admin", resp=r)
    return None

def write_evidence(base_dir, finding):
    ensure_dir(base_dir)
    now = int(time.time())
    ftype = finding["kind"]
    fid = f"{ftype}-{now}-{hashlib.md5(finding.get('url','').encode()).hexdigest()[:6]}"
    fdir = os.path.join(base_dir, fid)
    ensure_dir(fdir)

    # Common fields
    meta = {
        "id": fid,
        "kind": ftype,
        "domain": finding["domain"],
        "url": finding.get("url"),
        "score": finding["score"],
        "timestamp_utc": now,
        "notes": finding.get("notes",""),
    }
    with open(os.path.join(fdir,"meta.json"),"w") as f: json.dump(meta,f,indent=2)

    # Request/Response summaries (redacted)
    def dump_resp(prefix, resp):
        hdrs = "\n".join([f"{k}: {v}" for k,v in resp["headers"].items()])
        h, head, tail, clipped = redacted_snippet(resp["body"])
        with open(os.path.join(fdir, f"{prefix}_summary.txt"),"w",encoding="utf-8",errors="ignore") as f:
            f.write(f"URL: {resp['url']}\nStatus: {resp['status']}\n\nHeaders:\n{hdrs}\n\nBodySHA256: {h}\nClipped: {clipped}\n")
        return h

    if "base" in finding: dump_resp("base", finding["base"])
    if "test" in finding: dump_resp("test", finding["test"])
    if "resp" in finding: dump_resp("resp", finding["resp"])

    # PoC (safe)
    if ftype == "cors":
        poc = f"""<!doctype html> <meta charset="utf-8"/> <h1>CORS with credentials PoC (safe)</h1> <script> (async () => {{   try {{     const r = await fetch("{finding['url']}", {{       method: 'GET',       credentials: 'include',       mode: 'cors',       headers: {{Origin: '{finding['origin']}' }}     }});     const t = await r.text();     document.body.insertAdjacentHTML('beforeend', '<pre>'+t.slice(0,400)+'</pre>');   }} catch(e) {{ console.log(e); }} }})(); </script> """
        with open(os.path.join(fdir,"poc.html"),"w") as f: f.write(poc)

    if ftype == "redirect_auth":
        with open(os.path.join(fdir,"poc.txt"),"w") as f:
            f.write(f"Trigger URL:\n{finding['test_url']}\n\nResponse status: {finding['resp']['status']}\nLocation: {finding['resp']['headers'].get('location','')}\n")

    # finding.md (auto-draft)
    abuse = {
        "cors": "Cross-origin read of authenticated endpoints via ACAO reflection + ACAC:true — leads to data read from attacker origin.",
        "redirect_auth": "Open redirect inside authentication/consent flow — enables phishing/OAuth redirection chaining.",
        "takeover": "CNAME points to unprovisioned third-party service with vendor 404 — subdomain takeover candidate.",
        "admin": "Unauthenticated access to admin/monitoring panel."
    }.get(finding["kind"], "Security weakness.")
    md = f"""# {finding['kind'].upper()} on {finding['domain']} **URL/Host**: {finding.get('url', finding.get('host',''))}  **Impact (story)**: {abuse}  **Evidence**: see attached summaries & PoC.   **Score (auto)**: {finding['score']}  **Repro (quick)**: ` 
{mkcurl(finding.get('url',''), {'Origin': finding.get('origin','')}) if finding['kind']=='cors' else finding.get('test_url','')}
 `"""
    with open(os.path.join(fdir,"finding.md"),"w") as f: f.write(md)

    # Zip it
    zpath = os.path.join(base_dir, f"{fid}.zip")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for fn in os.listdir(fdir):
            z.write(os.path.join(fdir,fn), arcname=fn)

    return fid

async def gather_checks(domain, alive_file, httpx_json, outdir, per_target):
    ensure_dir(outdir)
    # Parse httpx json lines
    urls = []
    titles = {}
    host_to_scheme = defaultdict(lambda: "https")
    host_cnames = defaultdict(list)

    if os.path.isfile(httpx_json):
        with open(httpx_json,"r",encoding="utf-8",errors="ignore") as f:
            for line in f:
                try:
                    j = json.loads(line)
                except:
                     continue
                if "url" in j:
                    urls.append(j["url"].rstrip("/"))
                    titles[j["url"].rstrip("/")] = j.get("title","")
                if "host" in j and j.get("scheme"):
                    host_to_scheme[j["host"]] = j.get("scheme")
                # cnames (if provided by httpx)
                if "cnames" in j and j["cnames"]:
                    host_cnames[j["host"]] = j["cnames"]

    # Concurrency
    sem = asyncio.Semaphore(per_target)

    findings = []
    async with aiohttp.ClientSession() as session:
        async def bounded(task, *a, **kw):
            async with sem:
                return await task(*a, **kw)

        # Targeted CORS + Redirects + Admin
        cors_tasks = [bounded(check_cors, session, u) for u in urls if u.startswith("http")]
        redir_tasks = [bounded(check_redirects, session, u) for u in urls if u.startswith("http")]
        admin_tasks = [bounded(check_admin_panel, session, u) for u in urls if u.startswith("http") and ("admin" in u or "dashboard" in u or AUTH_HINT.search(titles.get(u,"")))]

        cors_res, redir_res, admin_res = await asyncio.gather(asyncio.gather(*cors_tasks), asyncio.gather(*redir_tasks), asyncio.gather(*admin_tasks))

        for u, r in zip([u for u in urls if u.startswith("http")], cors_res):
            if r:
                s = score("cors", auth=r["auth"], noisy=2)
                findings.append(dict(kind="cors", domain=domain, url=u, origin=r["origin"], base=r["base"], test=r["test"], auth=r["auth"], score=s, notes="ACAC:true + ACAO reflects Origin"))

        for u, r in zip([u for u in urls if u.startswith("http")], redir_res):
            if r:
                s = score("redirect_auth", auth=True, noisy=2)
                r.update(dict(domain=domain, url=u, score=s))
                findings.append(r)

        for u, r in zip([u for u in urls if u.startswith("http") and ("admin" in u or "dashboard" in u or AUTH_HINT.search(titles.get(u,"")))], admin_res):
            if r:
                s = score("admin", auth=False, noisy=3)
                findings.append(dict(kind="admin", domain=domain, url=u, resp=r["resp"], score=s))

        # Subdomain takeover (by host)
        hosts = sorted(set([host_only(u) for u in urls if u]))
        tk_tasks = [bounded(check_takeover, session, h, host_to_scheme.get(h,"https")) for h in hosts]
        tk_res = await asyncio.gather(*tk_tasks)
        for h, r in zip(hosts, tk_res):
            if r:
                s = score("takeover", auth=False, noisy=1)
                findings.append(dict(kind="takeover", domain=domain, host=h, resp=r["resp"], score=s, notes=f"Vendor:{r['vendor']}"))

    # Write evidence
    summary_lines = []
    auto = 0
    for f in findings:
        f["url"] = f.get("url") or (f"http{s and 's' or ''}://{f.get('host')}/")
        fid = write_evidence(outdir, f)
        line = f"[{domain}] {f['kind']} -> score {f['score']} :: {fid}"
        summary_lines.append(line)
        if f["score"] >= AUTO_DRAFT_THRESHOLD:
            auto += 1

    with open(os.path.join(outdir, "summary.txt"),"a") as s:
        for l in summary_lines:
            s.write(l + "\n")
        s.write(f"Auto-drafts (>= {AUTO_DRAFT_THRESHOLD}): {auto}\n")

def fold_nuclei(domain, nuclei_json, outdir):
    if not os.path.isfile(nuclei_json):
         return
    ensure_dir(outdir)
    count = 0
    with open(nuclei_json,"r",encoding="utf-8",errors="ignore") as f:
        for line in f:
            try:
                j = json.loads(line)
            except:
                 continue
            url = j.get("matched-at") or j.get("host") or j.get("url")
            if not url: continue
            # Lightweight finding from nuclei
            s = score("nuclei", auth=False, noisy=3)
            f = dict(kind="nuclei", domain=domain, url=url, resp=dict(status=0, headers=j, body=b""), score=s, notes=j.get("template-id",""))
            write_evidence(outdir, f); count += 1
    with open(os.path.join(outdir, "summary.txt"),"a") as s:
        s.write(f"[{domain}] folded nuclei findings: {count}\n")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain", required=True)
    ap.add_argument("--httpx-json")
    ap.add_argument("--alive")
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--per-target", type=int, default=6)
    ap.add_argument("--nuclei-json")
    ap.add_argument("--fold-nuclei", action="store_true")
    args = ap.parse_args()

    if args.fold_nuclei:
        fold_nuclei(args.domain, args.nuclei_json, args.outdir)
        return

    asyncio.run(gather_checks(args.domain, args.alive, args.httpx_json, args.outdir, args.per_target))

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
smart_hunt.py — async targeted checks and evidence packaging
"""

import argparse
import asyncio
import aiohttp
import os
import json
import hashlib
import re
import time
import zipfile
from collections import defaultdict
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl

from vendor_fingerprints import VENDORS

REDACTION_PATTERNS = [
    re.compile(r'(api|secret|token|key|pwd|pass|bearer|authorization)[=:]\s*([A-Za-z0-9._-]{8,})', re.I),
    re.compile(r'["\']([A-Za-z0-9_\-]{16,})["\']')
]

AUTH_HINT = re.compile(r'(login|sign[\s_-]*in|reset password|2fa|mfa|oauth|authorize)', re.I)
ADMIN_MARKERS = re.compile(r'grafana|kibana|jenkins|sonarqube|nexus repository|pgadmin|prometheus|kubernetes dashboard|rabbitmq|airflow|superset|laravel horizon', re.I)

AUTO_DRAFT_THRESHOLD = 50  # normalized 0-100

def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def redacted_snippet(b: bytes, limit_kb=64):
    if len(b) > limit_kb * 1024:
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
    parts = ' '.join([f"-H '{k}: {v}'" for k, v in h.items()])
    return f"curl -i -s '{url}' {parts}"

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

BASE_WEIGHTS = {"cors": 0.9, "redirect_auth": 0.8, "takeover": 0.85, "admin": 0.7, "nuclei": 0.6}

def score(kind: str, auth: bool=False, noisy: int=2) -> int:
    w = BASE_WEIGHTS.get(kind, 0.5)
    auth_mult = 1.4 if auth else 1.0
    raw = w * auth_mult * (10.0 / max(1.0, float(noisy)))
    return int(max(0, min(100, raw * 10)))

async def fetch(session: aiohttp.ClientSession, method: str, url: str, headers=None, allow_redirects=False):
    try:
        async with session.request(method, url, headers=headers or {}, allow_redirects=allow_redirects, timeout=15) as r:
            body = await r.read()
            return dict(ok=True, status=r.status, url=str(r.url), headers={k.lower(): v for k, v in r.headers.items()}, body=body)
    except Exception as e:
        return dict(ok=False, error=str(e), status=0, url=url, headers={}, body=b"")

def with_query(u, kv):
    p = urlparse(u)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q.update(kv)
    return urlunparse(p._replace(query=urlencode(q, doseq=True)))

async def check_cors(session, url):
    origin = "https://evil.attacker.example"
    base = await fetch(session, "GET", url, headers={})
    test = await fetch(session, "GET", url, headers={"Origin": origin, "Cookie": "session=stub"})
    if not base["ok"] or not test["ok"]:
        return None
    h = {k.lower(): v for k, v in test["headers"].items()}
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "")
    set_cookie = "set-cookie" in h
    authish = set_cookie or ("www-authenticate" in h) or base["status"] in (401, 403)
    if acac.lower() == "true" and acao and acao != "*" and origin in acao:
        return dict(kind="cors", auth=authish, base=base, test=test, origin=origin)
    return None

REDIRECT_PARAMS = ["next", "redirect", "redirect_uri", "return", "return_to", "continue", "url", "goto", "dest", "destination", "post_auth_return"]
ATTACK_URL = "https://example.org/"

async def check_redirects(session, url):
    if not AUTH_HINT.search(url):
        parsed = urlparse(url)
        if not re.search(r'/login|/signin|/auth|/oauth|/reset', parsed.path, re.I):
            return None
    for p in REDIRECT_PARAMS:
        test_url = with_query(url, {p: ATTACK_URL})
        r = await fetch(session, "GET", test_url, allow_redirects=False)
        loc = r["headers"].get("location", "")
        if r["ok"] and r["status"] in (301, 302, 303, 307, 308) and ATTACK_URL in loc:
            return dict(kind="redirect_auth", param=p, resp=r, test_url=test_url)
    return None

async def check_admin_panel(session, url):
    r = await fetch(session, "GET", url)
    if not r["ok"] or r["status"] in (401, 403):
        return None
    text = r["body"].decode(errors="ignore")
    if ADMIN_MARKERS.search(text) and not re.search(r'csrf token|forbidden', text, re.I):
        return dict(kind="admin", resp=r)
    return None

def takeover_vendor(cnames):
    for c in (cnames or []):
        for vendor, fp in VENDORS.items():
            for pat in fp.get("cname_contains", []):
                if pat in c:
                    return vendor
    return None

async def check_takeover(session, host, scheme="https"):
    url = f"{scheme}://{host}/"
    r = await fetch(session, "GET", url)
    if not r["ok"]:
        return None
    body = r["body"].decode(errors="ignore")
    hdrs = r["headers"]
    for vendor, fp in VENDORS.items():
        ok = False
        for sig in fp.get("body_contains", []):
            if sig.lower() in body.lower():
                ok = True; break
        for sig in fp.get("header_contains", []):
            if sig.lower() in json.dumps(hdrs).lower():
                ok = True; break
        if ok:
            return dict(kind="takeover", vendor=vendor, resp=r)
    return None

def write_evidence(base_dir, finding):
    ensure_dir(base_dir)
    now = int(time.time())
    ftype = finding.get("kind", "finding")
    url_or_host = finding.get("url") or finding.get("host") or ""
    fid = f"{ftype}-{now}-{hashlib.md5(url_or_host.encode()).hexdigest()[:6]}"
    fdir = os.path.join(base_dir, fid)
    ensure_dir(fdir)
    meta = {"id": fid, "kind": ftype, "url": url_or_host, "score": finding.get("score", 0), "notes": finding.get("notes", ""), "timestamp": now}
    with open(os.path.join(fdir, "meta.json"), "w") as fh:
        json.dump(meta, fh, indent=2)
    def dump_resp(prefix, resp):
        if not resp:
            return
        hdrs = "\n".join([f"{k}: {v}" for k, v in resp.get("headers", {}).items()])
        h, head, tail, clipped = redacted_snippet(resp.get("body", b""))
        with open(os.path.join(fdir, f"{prefix}_summary.txt"), "w", encoding="utf-8", errors="ignore") as fh:
            fh.write(f"URL: {resp.get('url')}\nStatus: {resp.get('status')}\n\nHeaders:\n{hdrs}\n\nBodySHA256: {h}\nClipped: {clipped}\n")
        return h
    if "base" in finding: dump_resp("base", finding["base"])
    if "test" in finding: dump_resp("test", finding["test"])
    if "resp" in finding: dump_resp("resp", finding["resp"])
    if ftype == "cors":
        poc = f"""<!doctype html>
<meta charset="utf-8"/>
<h1>CORS PoC (safe - non-exfil)</h1>
<script>
(async () => {{
  try {{
    const r = await fetch("{finding.get('url')}", {{
      method: 'GET',
      credentials: 'include',
      mode: 'cors',
      headers: {{ Origin: '{finding.get('origin')}' }}
    }});
    document.body.innerText = 'fetched: ' + (await r.text()).slice(0,400);
  }} catch(e) {{ console.log(e); document.body.innerText = 'error'; }}
}})();
</script>"""
        with open(os.path.join(fdir, "poc.html"), "w") as fh:
            fh.write(poc)
    if ftype == "redirect_auth":
        with open(os.path.join(fdir, "poc.txt"), "w") as fh:
            fh.write(f"Trigger URL: {finding.get('test_url')}\nLocation: {finding.get('resp', {}).get('headers', {}).get('location','')}\nStatus: {finding.get('resp', {}).get('status')}\n")
    md = f"# {ftype.upper()} finding\nURL/Host: {url_or_host}\nScore (auto): {finding.get('score', 0)}\nNotes: {finding.get('notes','')}\n"
    with open(os.path.join(fdir, "finding.md"), "w") as fh:
        fh.write(md)
    zpath = os.path.join(base_dir, f"{fid}.zip")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for fn in os.listdir(fdir):
            z.write(os.path.join(fdir, fn), arcname=fn)
    return fid

async def gather_checks(target, httpx_json, outdir, per_target):
    ensure_dir(outdir)
    urls = []
    titles = {}
    host_to_scheme = defaultdict(lambda: "https")
    if httpx_json and os.path.isfile(httpx_json):
        with open(httpx_json, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                try:
                    j = json.loads(line)
                except:
                    continue
                if "url" in j:
                    urls.append(j["url"].rstrip("/"))
                    titles[j["url"].rstrip("/")] = j.get("title", "")
                if "host" in j and j.get("scheme"):
                    host_to_scheme[j["host"]] = j.get("scheme")
    if not urls:
        if target.startswith("http"):
            urls = [target.rstrip("/")]
        else:
            urls = [f"https://{target.rstrip('/')}"]
    sem = asyncio.Semaphore(per_target)
    findings = []
    async with aiohttp.ClientSession() as session:
        async def bounded(fn, *a, **kw):
            async with sem:
                return await fn(*a, **kw)
        cors_tasks = [bounded(check_cors, session, u) for u in urls if u.startswith("http")]
        redir_tasks = [bounded(check_redirects, session, u) for u in urls if u.startswith("http")]
        admin_tasks = [bounded(check_admin_panel, session, u) for u in urls if u.startswith("http") and ("admin" in u or "dashboard" in u or AUTH_HINT.search(titles.get(u, "")))]
        cors_res, redir_res, admin_res = await asyncio.gather(asyncio.gather(*cors_tasks), asyncio.gather(*redir_tasks), asyncio.gather(*admin_tasks))
        for u, r in zip([u for u in urls if u.startswith("http")], cors_res):
            if r:
                s = score("cors", auth=r.get("auth", False), noisy=2)
                findings.append(dict(kind="cors", url=u, origin=r.get("origin"), base=r.get("base"), test=r.get("test"), auth=r.get("auth"), score=s, notes="ACAC:true + ACAO reflected"))
        for u, r in zip([u for u in urls if u.startswith("http")], redir_res):
            if r:
                s = score("redirect_auth", auth=True, noisy=2)
                r.update(dict(url=u, score=s))
                findings.append(r)
        for u, r in zip([u for u in urls if u.startswith("http") and ("admin" in u or "dashboard" in u or AUTH_HINT.search(titles.get(u, "")))], admin_res):
            if r:
                s = score("admin", auth=False, noisy=3)
                findings.append(dict(kind="admin", url=u, resp=r.get("resp"), score=s))
        hosts = sorted(set([urlparse(u).hostname for u in urls if u]))
        tk_tasks = [bounded(check_takeover, session, h, host_to_scheme.get(h, "https")) for h in hosts]
        tk_res = await asyncio.gather(*tk_tasks)
        for h, r in zip(hosts, tk_res):
            if r:
                s = score("takeover", auth=False, noisy=1)
                findings.append(dict(kind="takeover", host=h, resp=r.get("resp"), vendor=r.get("vendor"), score=s))
    summary_lines = []
    auto_count = 0
    for f in findings:
        f_url = f.get("url") or f.get("host") or target
        f["url"] = f_url
        fid = write_evidence(outdir, f)
        summary_lines.append(f"[{target}] {f['kind']} -> score {f['score']} :: {fid}")
        if f["score"] >= AUTO_DRAFT_THRESHOLD:
            auto_count += 1
    with open(os.path.join(outdir, "summary.txt"), "a") as fh:
        for l in summary_lines:
            fh.write(l + "\n")
        fh.write(f"Auto-drafts (>= {AUTO_DRAFT_THRESHOLD}): {auto_count}\n")

def fold_nuclei(domain, nuclei_json, outdir):
    if not nuclei_json or not os.path.isfile(nuclei_json):
        return
    ensure_dir(outdir)
    count = 0
    with open(nuclei_json, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            try:
                j = json.loads(line)
            except:
                continue
            url = j.get("matched-at") or j.get("host") or j.get("url")
            if not url:
                continue
            s = score("nuclei", auth=False, noisy=3)
            f = dict(kind="nuclei", url=url, resp=dict(status=0, headers=j, body=b""), score=s, notes=j.get("template-id", ""))
            write_evidence(outdir, f)
            count += 1
    with open(os.path.join(outdir, "summary.txt"), "a") as fh:
        fh.write(f"[{domain}] folded nuclei findings: {count}\n")

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--target", required=False, help="Target (URL or domain)")
    p.add_argument("--httpx-json", required=False)
    p.add_argument("--outdir", required=True)
    p.add_argument("--per-target", type=int, default=6)
    p.add_argument("--nuclei-json", required=False)
    p.add_argument("--fold-nuclei", action="store_true")
    return p.parse_args()

def main():
    args = parse_args()
    if args.fold_nuclei:
        fold_nuclei(args.target or "local", args.nuclei_json, args.outdir)
        return
    target = args.target
    if not target:
        raise SystemExit("No --target provided. Provide a target URL/domain.")
    asyncio.run(gather_checks(target, args.httpx_json, args.outdir, args.per_target))

if __name__ == "__main__":
    main()

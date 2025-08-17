#!/usr/bin/env python3
"""
smart_hunt.py — greedy Low/Med harvester

Inputs: httpx JSON + alive sample list

Output: per-finding evidence zip + summary
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
from collections import defaultdict, Counter
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl
from vendor_fingerprints import VENDORS

# helpers / markers
REDACTION_PATTERNS = [
    re.compile(r'(?i)(?:api|secret|token|key|pwd|pass|bearer|authorization)[=:]\s*([A-Za-z0-9._-]{8,})'),
]
AUTH_HINT = re.compile(r'(login|sign[\s_-]*in|reset\s*password|2fa|mfa|oauth|authorize)', re.I)
ADMIN_MARKERS = re.compile(r'(grafana|kibana|jenkins|sonarqube|nexus\s+repository|pgadmin|prometheus|kubernetes\s+dashboard|rabbitmq|airflow|superset|laravel\s+horizon|minio|gitlab|portainer)', re.I)
DIRLIST_MARKERS = re.compile(r'Index of /|<title>Index of', re.I)
GIT_HEAD_MARKER = re.compile(r'^ref:\s+refs/heads/', re.I | re.M)
ENV_MARKERS = re.compile(r'(APP_KEY|DB_PASSWORD|DB_HOST|SECRET|AWS_|REDIS_|TOKEN=)', re.I)

BASE = {
    "dirlist": 0.65, "env": 0.80, "git": 0.72,
    "cors": 0.85, "redirect_auth": 0.78,
    "admin": 0.72, "takeover": 0.88, "backup": 0.75, "graphql": 0.68, "nuclei": 0.60
}
AUTO_DRAFT_THRESHOLD = 45

def score(kind, auth=False, signal=1.0):
    w = BASE.get(kind, 0.6)
    m = 1.3 if auth else 1.0
    s = int(max(0, min(100, round(w * m * signal * 100))))
    return s

def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def redact_bytes(b: bytes) -> bytes:
    text = b.decode(errors="ignore")
    for rx in REDACTION_PATTERNS:
        text = rx.sub(r"\1[REDACTED]", text)
    return text.encode()

def redacted_snippet(b: bytes, limit_kb=64):
    if len(b) > limit_kb*1024:
        body = redact_bytes(b)
        head = body[:200]; tail = body[-200:]; h = sha256(body)
        return h, head, tail, True
    body = redact_bytes(b)
    return sha256(body), body, b"", False

def ensure_dir(p): os.makedirs(p, exist_ok=True)

def with_query(u, kv):
    p = urlparse(u)
    q = dict(parse_qsl(p.query, keep_blank_values=True)); q.update(kv)
    return urlunparse(p._replace(query=urlencode(q, doseq=True)))

def base_of(u):
    pu = urlparse(u)
    return f"{pu.scheme}://{pu.hostname}" + (f":{pu.port}" if pu.port else "")

# HTTP helpers
DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=20, connect=10, sock_read=15, sock_connect=10)

async def fetch(session, method, url, headers=None, allow_redirects=False):
    try:
        async with session.request(method, url, headers=headers or {}, allow_redirects=allow_redirects) as r:
            b = await r.read()
            return dict(ok=True, status=r.status, url=str(r.url), headers={k.lower(): v for k,v in r.headers.items()}, body=b)
    except Exception as e:
        return dict(ok=False, status=0, error=str(e), url=url, headers={}, body=b"")

# checks
async def check_dirlisting(session, url):
    r = await fetch(session, "GET", url)
    if r["ok"] and r["status"] == 200 and DIRLIST_MARKERS.search(r["body"].decode(errors="ignore")):
        return dict(kind="dirlist", resp=r)
    return None

async def check_git_exposed(session, url_base):
    r = await fetch(session, "GET", url_base + "/.git/HEAD")
    if r["ok"] and r["status"] == 200 and GIT_HEAD_MARKER.search(r["body"].decode(errors="ignore")):
        return dict(kind="git", resp=r, url=url_base + "/.git/HEAD")
    return None

async def check_env_exposed(session, url_base):
    r = await fetch(session, "GET", url_base + "/.env")
    if r["ok"] and r["status"] == 200:
        text = r["body"].decode(errors="ignore")
        if ENV_MARKERS.search(text):
            return dict(kind="env", resp=r, url=url_base + "/.env")
    return None

REDIRECT_PARAMS = ["next","redirect","redirect_uri","return","return_to","continue","url","goto","dest","destination","post_auth_return"]
ATTACK_URL = "https://example.org/"

async def check_redirects(session, url):
    if not AUTH_HINT.search(url):
        p = urlparse(url)
        if not re.search(r'/login|/signin|/auth|/oauth|/reset', p.path, re.I):
            return None
    for k in REDIRECT_PARAMS:
        test_url = with_query(url, {k: ATTACK_URL})
        r = await fetch(session, "GET", test_url, allow_redirects=False)
        loc = r["headers"].get("location","")
        if r["ok"] and r["status"] in (301,302,303,307,308) and ATTACK_URL in loc:
            return dict(kind="redirect_auth", param=k, resp=r, test_url=test_url)
    return None

async def check_cors(session, url):
    origin = "https://attacker.example"
    base = await fetch(session, "GET", url)
    test = await fetch(session, "GET", url, headers={"Origin": origin, "Cookie": "session=stub"})
    if not base["ok"] or not test["ok"]:
        return None
    h = test["headers"]
    acao = h.get("access-control-allow-origin","")
    acac = h.get("access-control-allow-credentials","")
    set_cookie = "set-cookie" in h
    authish = set_cookie or ("www-authenticate" in h) or base["status"] in (401,403)
    # Creds + reflected origin (not wildcard)
    if acac.lower() == "true" and acao and acao != "*" and origin in acao:
        out = dict(kind="cors", auth=authish, base=base, test=test, origin=origin)
        out["url"] = url
        return out
    return None

async def check_admin_panel(session, url):
    r = await fetch(session, "GET", url)
    if not r["ok"] or r["status"] in (401,403):
        return None
    text = r["body"].decode(errors="ignore")
    if ADMIN_MARKERS.search(text) and not re.search(r'csrf token|forbidden', text, re.I):
        return dict(kind="admin", resp=r)
    return None

async def check_backup_files(session, url_base):
    candidates = ["/backup.zip","/db.sql","/database.sql","/backup.sql","/dump.sql","/config.php.bak","/config.php~","/wp-config.php.bak","/env.bak"]
    tasks = [fetch(session,"GET", url_base+p) for p in candidates]
    rs = await asyncio.gather(*tasks, return_exceptions=False)
    for r,p in zip(rs,candidates):
        if r["ok"] and r["status"] == 200 and len(r["body"]) > 512:
            return dict(kind="backup", resp=r, url=url_base+p)
    return None

def takeover_from_text(body: str, headers: dict, cnames=None):
    blob = (body or "").lower() + "\n" + json.dumps(headers or {}).lower()
    for vendor, fp in VENDORS.items():
        for sig in fp.get("body_contains", []):
            if sig.lower() in blob:
                return vendor
        for sig in fp.get("header_contains", []):
            if sig.lower() in blob:
                return vendor
        if cnames:
            for c in cnames:
                for s in fp.get("cname_contains", []):
                    if s.lower() in str(c).lower():
                        return vendor
    return None

async def check_takeover(session, host, scheme="https"):
    url = f"{scheme}://{host}/"
    r = await fetch(session, "GET", url)
    if not r["ok"]:
        return None
    vendor = takeover_from_text(r["body"].decode(errors="ignore"), r["headers"])
    if vendor:
        return dict(kind="takeover", vendor=vendor, resp=r)
    return None

GRAPHQL_INTROSPECTION_QUERY = {"query": "{ __schema { types { name } } }"}

async def check_graphql(session, base_url):
    # try GET and POST variants
    get_url = with_query(base_url + "/graphql", {"query": "{__schema{types{name}}}"})
    r1 = await fetch(session, "GET", get_url)
    r2 = await fetch(session, "POST", base_url + "/graphql", headers={"content-type": "application/json"}, allow_redirects=False)
    body1 = r1["body"].decode(errors="ignore") if r1["ok"] else ""
    body2 = r2["body"].decode(errors="ignore") if r2["ok"] else ""
    if ("__schema" in body1) or ("__schema" in body2):
        return dict(kind="graphql", resp=(r1 if "__schema" in body1 else r2), url=base_url + "/graphql")
    return None

# evidence writing
def write_evidence(base_dir, finding, target):
    ensure_dir(base_dir)
    now = int(time.time())
    ftype = finding["kind"]
    id_base = finding.get("url") or finding.get("host") or target
    fid = f"{ftype}-{now}-{hashlib.md5(id_base.encode()).hexdigest()[:6]}"
    fdir = os.path.join(base_dir, fid); ensure_dir(fdir)

    meta = {
        "id": fid, "kind": ftype, "target": target,
        "url": finding.get("url") or finding.get("host"),
        "score": finding.get("score", 0),
        "notes": finding.get("notes",""),
        "timestamp": now
    }
    with open(os.path.join(fdir,"meta.json"),"w") as fh: json.dump(meta, fh, indent=2)

    def dump_resp(prefix, resp):
        if not resp: return
        hdrs = "\n".join([f"{k}: {v}" for k,v in resp.get("headers",{}).items()])
        h, head, tail, clipped = redacted_snippet(resp.get("body", b""))
        with open(os.path.join(fdir,f"{prefix}_summary.txt"),"w",encoding="utf-8",errors="ignore") as fh:
            fh.write(f"URL: {resp.get('url')}\nStatus: {resp.get('status')}\n\nHeaders:\n{hdrs}\n\nBodySHA256: {h}\nClipped: {clipped}\n")
        with open(os.path.join(fdir,f"{prefix}_head.bin"),"wb") as fh: fh.write(head)
        if tail:
            with open(os.path.join(fdir,f"{prefix}_tail.bin"),"wb") as fh: fh.write(tail)

    for k in ("base","test","resp"):
        if k in finding: dump_resp(k, finding[k])

    # simple PoCs
    if ftype == "cors":
        poc = f"""<!doctype html><meta charset="utf-8"><h1>CORS (with credentials) PoC</h1>
<script>(async()=>{{try{{const r=await fetch("{finding.get('url')}",{{credentials:"include",mode:"cors",headers:{{Origin:"{finding.get('origin')}"}}}});document.body.innerText=(await r.text()).slice(0,400)}}catch(e){{console.log(e)}}}})();</script>"""
        with open(os.path.join(fdir,"poc.html"),"w") as fh: fh.write(poc)
    if ftype == "redirect_auth":
        with open(os.path.join(fdir,"poc.txt"),"w") as fh:
            fh.write(f"Trigger: {finding.get('test_url')}\nStatus: {finding['resp'].get('status')}\nLocation: {finding['resp'].get('headers',{}).get('location','')}\n")

    with open(os.path.join(fdir,"finding.md"),"w") as fh:
        fh.write(f"# {ftype.upper()} (auto)\nTarget: {target}\nURL/Host: {meta.get('url')}\nScore: {meta['score']}\nNotes: {meta['notes']}\n")

    zpath = os.path.join(base_dir, f"{fid}.evidence.zip")
    with zipfile.ZipFile(zpath,"w",zipfile.ZIP_DEFLATED) as z:
        for fn in os.listdir(fdir):
            z.write(os.path.join(fdir,fn), arcname=fn)
    return fid

async def gather_checks(target, httpx_json, alive_file, outdir, per_target, path_check_top_hosts):
    ensure_dir(outdir)

    urls, titles, by_host = [], {}, defaultdict(list)
    techs = defaultdict(set)
    schemes = defaultdict(lambda: "https")
    cnames = defaultdict(list)

    if httpx_json and os.path.isfile(httpx_json):
        with open(httpx_json,"r",encoding="utf-8",errors="ignore") as fh:
            for line in fh:
                try:
                    j = json.loads(line)
                except Exception:
                    continue
                u = j.get("url"); h = j.get("host"); t = (j.get("title") or "")
                if not u or not h: continue
                u = u.rstrip("/")
                urls.append(u); titles[u] = t
                schemes[h] = j.get("scheme","https")
                for tech in (j.get("tech","") or "").split(","):
                    if tech.strip(): techs[h].add(tech.strip().lower())
                cval = j.get("cname")
                if isinstance(cval, list):
                    cnames[h].extend([str(x) for x in cval])
                elif isinstance(cval, str) and cval:
                    cnames[h].append(cval)
                by_host[h].append(u)

    alive = []
    if alive_file and os.path.isfile(alive_file):
        alive = [l.strip() for l in open(alive_file,"r",encoding="utf-8",errors="ignore") if l.strip()]

    # Rank hosts
    host_scores = Counter()
    for h, lst in by_host.items():
        t_hits = sum(1 for u in lst if AUTH_HINT.search(titles.get(u,"")))
        tech_hits = sum(1 for te in techs[h] if te in {"grafana","kibana","jenkins","wordpress","gitlab","minio","sonarqube","prometheus"})
        host_scores[h] = (2*t_hits) + tech_hits + len(lst)/50.0

    top_hosts = [h for h,_ in host_scores.most_common(path_check_top_hosts or 100)]
    base_urls = [f"{schemes[h]}://{h}" for h in top_hosts]

    findings = []
    sem = asyncio.Semaphore(per_target)
    conn = aiohttp.TCPConnector(limit=per_target*4, ssl=False)
    async with aiohttp.ClientSession(timeout=DEFAULT_TIMEOUT, connector=conn) as session:

        async def bounded(fn, *a, **kw):
            async with sem: return await fn(*a, **kw)

        # per-URL checks
        cors_tasks  = [bounded(check_cors, session, u) for u in alive]
        redir_tasks = [bounded(check_redirects, session, u) for u in alive]
        admin_candidates = [u for u in alive if ("admin" in u or "dashboard" in u or AUTH_HINT.search(titles.get(u,"")))]
        admin_tasks = [bounded(check_admin_panel, session, u) for u in admin_candidates]

        cors_res, redir_res, admin_res = await asyncio.gather(
            asyncio.gather(*cors_tasks), asyncio.gather(*redir_tasks), asyncio.gather(*admin_tasks)
        )

        for u, r in zip(alive, cors_res):
            if r:
                s = score("cors", auth=r.get("auth", False), signal=1.0)
                findings.append(dict(kind="cors", url=u, base=r["base"], test=r["test"], origin=r["origin"], auth=r["auth"], score=s, notes="ACAC:true & ACAO reflects Origin"))

        for u, r in zip(alive, redir_res):
            if r:
                s = score("redirect_auth", auth=True, signal=1.0)
                r.update(dict(url=u, score=s))
                findings.append(r)

        for u, r in zip(admin_candidates, admin_res):
            if r:
                s = score("admin", signal=0.9)
                findings.append(dict(kind="admin", url=u, resp=r["resp"], score=s))

        # per-host path checks
        dir_tasks = [bounded(check_dirlisting, session, b + "/") for b in base_urls]
        git_tasks = [bounded(check_git_exposed, session, b) for b in base_urls]
        env_tasks = [bounded(check_env_exposed, session, b) for b in base_urls]
        bak_tasks = [bounded(check_backup_files, session, b) for b in base_urls]
        gql_tasks = [bounded(check_graphql, session, b) for b in base_urls]

        dir_res, git_res, env_res, bak_res, gql_res = await asyncio.gather(
            asyncio.gather(*dir_tasks), asyncio.gather(*git_tasks),
            asyncio.gather(*env_tasks), asyncio.gather(*bak_tasks), asyncio.gather(*gql_tasks)
        )

        for b, r in zip(base_urls, dir_res):
            if r:
                s = score("dirlist", signal=0.8)
                findings.append(dict(kind="dirlist", url=b + "/", resp=r["resp"], score=s, notes="Auto index enabled"))
        for b, r in zip(base_urls, git_res):
            if r:
                s = score("git", signal=0.9)
                findings.append(dict(kind="git", url=r["url"], resp=r["resp"], score=s, notes="Exposed .git/HEAD"))
        for b, r in zip(base_urls, env_res):
            if r:
                s = score("env", signal=1.0)
                findings.append(dict(kind="env", url=r["url"], resp=r["resp"], score=s, notes="Exposed .env (secrets likely)"))
        for b, r in zip(base_urls, bak_res):
            if r:
                s = score("backup", signal=0.95)
                findings.append(dict(kind="backup", url=r["url"], resp=r["resp"], score=s, notes="Backup artifact accessible"))
        for b, r in zip(base_urls, gql_res):
            if r:
                s = score("graphql", signal=0.75)
                findings.append(dict(kind="graphql", url=r["url"], resp=r["resp"], score=s, notes="GraphQL introspection enabled"))

        # takeover checks (per-host)
        hosts = list({h for h in by_host.keys()})
        tk_tasks = [bounded(check_takeover, session, h, schemes.get(h,"https")) for h in hosts]
        tk_res = await asyncio.gather(*tk_tasks)
        for h, r in zip(hosts, tk_res):
            if r:
                s = score("takeover", signal=1.0)
                findings.append(dict(kind="takeover", host=h, resp=r["resp"], score=s, notes=f"Vendor:{r['vendor']}"))

    # write evidence & summary
    auto = 0
    with open(os.path.join(outdir,"summary.txt"),"a",encoding="utf-8") as S:
        for f in findings:
            fid = write_evidence(outdir, f, target)
            line = f"[{target}] {f['kind']} -> score {f['score']} :: {fid}"
            S.write(line + "\n")
            if f["score"] >= AUTO_DRAFT_THRESHOLD:
                auto += 1
        S.write(f"Auto-drafts (>= {AUTO_DRAFT_THRESHOLD}): {auto}\n")

def fold_nuclei(target, nuclei_json, outdir):
    if not nuclei_json or not os.path.isfile(nuclei_json): return
    ensure_dir(outdir)
    count = 0
    with open(nuclei_json,"r",encoding="utf-8",errors="ignore") as fh:
        for line in fh:
            try:
                j = json.loads(line)
            except Exception:
                continue
            url = j.get("matched-at") or j.get("host") or j.get("url")
            if not url: continue
            s = score("nuclei", signal=0.7)
            f = dict(kind="nuclei", url=url, resp=dict(status=0, headers=j, body=b""), score=s, notes=j.get("template-id",""))
            write_evidence(outdir, f, target); count += 1
    with open(os.path.join(outdir,"summary.txt"),"a") as S:
        S.write(f"[{target}] folded nuclei findings: {count}\n")

def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=False)
    ap.add_argument("--httpx-json", required=False)
    ap.add_argument("--alive", required=False)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--per-target", type=int, default=8)
    ap.add_argument("--path-check-top-hosts", type=int, default=150)
    ap.add_argument("--nuclei-json", required=False)
    ap.add_argument("--fold-nuclei", action="store_true")
    return ap.parse_args()

def main():
    a = parse_args()
    if a.fold_nuclei:
        fold_nuclei(a.target or "root", a.nuclei_json, a.outdir)
        return
    if not a.target:
        raise SystemExit("smart_hunt.py: --target required unless --fold-nuclei")
    asyncio.run(gather_checks(a.target, a.httpx_json, a.alive, a.outdir, a.per_target, a.path_check_top_hosts))

if __name__ == "__main__":
    main()

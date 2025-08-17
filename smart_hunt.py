#!/usr/bin/env python3
"""
smart_hunt.py — greedy Low/Med harvester:
- Inputs: httpx JSON + alive sample list
- Targets: CORS creds, auth redirects, admin panels, takeover, dir listing,
           exposed .git/.env, backup dumps, GraphQL introspection
- Output: per-finding evidence zip + summary
"""
import argparse, asyncio, aiohttp, os, json, hashlib, re, time, zipfile
from collections import defaultdict, Counter
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl
from vendor_fingerprints import VENDORS

# ---------- helpers ----------
REDACTION_PATTERNS = [
    re.compile(r'(api|secret|token|key|pwd|pass|bearer|authorization)[=:]\s*([A-Za-z0-9._\-]{8,})', re.I),
    re.compile(r'["\']([A-Za-z0-9_\-]{16,})["\']')
]

AUTH_HINT = re.compile(r'(login|sign[\s_-]*in|reset password|2fa|mfa|oauth|authorize)', re.I)
ADMIN_MARKERS = re.compile(r'grafana|kibana|jenkins|sonarqube|nexus repository|pgadmin|prometheus|kubernetes dashboard|rabbitmq|airflow|superset|laravel horizon', re.I)

DIRLIST_MARKERS = re.compile(r'Index of /|<title>Index of', re.I)
GIT_HEAD_MARKER = re.compile(r'^ref:\s+refs/heads/', re.I | re.M)
ENV_MARKERS = re.compile(r'(APP_KEY|DB_PASSWORD|DB_HOST|SECRET|AWS_|\bREDIS_|TOKEN=)', re.I)

# scoring normalized 0..100 tilted to Low/Med
BASE = {
    "dirlist": 0.65, "env": 0.75, "git": 0.7,
    "cors": 0.85 if True else 0.6, "redirect_auth": 0.78,
    "admin": 0.72, "takeover": 0.88, "backup": 0.7, "graphql": 0.68, "nuclei": 0.6
}
AUTO_DRAFT_THRESHOLD = 45

def score(kind, auth=False, signal=1.0):
    w = BASE.get(kind, 0.6)
    m = 1.3 if auth else 1.0
    s = int(max(0, min(100, round(w * m * signal * 100))))
    return s

def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def redacted_snippet(b: bytes, limit_kb=64):
    if len(b) > limit_kb*1024:
        head = b[:200]; tail = b[-200:]; h = sha256(b)
        return h, head, tail, True
    return sha256(b), b, b"", False

def ensure_dir(p): os.makedirs(p, exist_ok=True)

def with_query(u, kv):
    p = urlparse(u)
    q = dict(parse_qsl(p.query, keep_blank_values=True)); q.update(kv)
    return urlunparse(p._replace(query=urlencode(q, doseq=True)))

def base_of(u):
    pu = urlparse(u)
    return f"{pu.scheme}://{pu.hostname}" + (f":{pu.port}" if pu.port else "")

def mkcurl(url, headers=None):
    h = headers or {}; parts = ' '.join([f"-H '{k}: {v}'" for k,v in h.items()])
    return f"curl -i -s '{url}' {parts}"

# ---------- HTTP ----------
async def fetch(session, method, url, headers=None, allow_redirects=False):
    try:
        async with session.request(method, url, headers=headers or {}, allow_redirects=allow_redirects, timeout=15) as r:
            b = await r.read()
            return dict(ok=True, status=r.status, url=str(r.url),
                        headers={k.lower(): v for k,v in r.headers.items()},
                        body=b)
    except Exception as e:
        return dict(ok=False, status=0, error=str(e), url=url, headers={}, body=b"")

# ---------- checks (easy L/M) ----------
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
    h = {k.lower():v for k,v in test["headers"].items()}
    acao = h.get("access-control-allow-origin","")
    acac = h.get("access-control-allow-credentials","")
    set_cookie = "set-cookie" in h
    authish = set_cookie or ("www-authenticate" in h) or base["status"] in (401,403)
    if acac.lower() == "true" and acao and acao != "*" and origin in acao:
        return dict(kind="cors", auth=authish, base=base, test=test, origin=origin)
    return None

async def check_admin_panel(session, url):
    r = await fetch(session, "GET", url)
    if not r["ok"] or r["status"] in (401,403):
        return None
    text = r["body"].decode(errors="ignore")
    if ADMIN_MARKERS.search(text) and not re.search(r'csrf token|forbidden', text, re.I):
    # found a recognizable dashboard without auth wall
        return dict(kind="admin", resp=r)
    return None

async def check_backup_files(session, url_base):
    candidates = [
        "/backup.zip","/db.sql","/database.sql","/backup.sql","/dump.sql",
        "/config.php.bak","/config.php~","/wp-config.php.bak","/env.bak",
    ]
    tasks = [fetch(session,"GET", url_base+p) for p in candidates]
    rs = await asyncio.gather(*tasks, return_exceptions=False)
    for r,p in zip(rs,candidates):
        if r["ok"] and r["status"] == 200 and len(r["body"]) > 512:  # crude but effective
            return dict(kind="backup", resp=r, url=url_base+p)
    return None

def takeover_from_text(body: str, headers: dict):
    blob = body.lower() + "\n" + json.dumps(headers).lower()
    for vendor, fp in VENDORS.items():
        for sig in fp.get("body_contains", []):
            if sig.lower() in blob:
                return vendor
        for sig in fp.get("header_contains", []):
            if sig.lower() in blob:
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

# ---------- evidence ----------
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
    for k in ("base","test","resp"):
        if k in finding: dump_resp(k, finding[k])

    # PoCs
    if ftype == "cors":
        poc = f"""<!doctype html><meta charset="utf-8"><h1>CORS (with credentials) PoC</h1>
<script>(async()=>{{try{{const r=await fetch("{finding.get('url')}",{{credentials:"include",mode:"cors",headers:{{Origin:"{finding.get('origin')}"}}}});document.body.innerText=(await r.text()).slice(0,400)}}catch(e){{console.log(e)}}}})();</script>"""
        with open(os.path.join(fdir,"poc.html"),"w") as fh: fh.write(poc)
    if ftype == "redirect_auth":
        with open(os.path.join(fdir,"poc.txt"),"w") as fh:
            fh.write(f"Trigger: {finding.get('test_url')}\nStatus: {finding['resp'].get('status')}\nLocation: {finding['resp'].get('headers',{}).get('location','')}\n")

    with open(os.path.join(fdir,"finding.md"),"w") as fh:
        fh.write(f"# {ftype.upper()} (auto)\nTarget: {target}\nURL/Host: {meta.get('url')}\nScore: {meta['score']}\nNotes: {meta['notes']}\n")

    zpath = os.path.join(base_dir, f"{fid}.zip")
    with zipfile.ZipFile(zpath,"w",zipfile.ZIP_DEFLATED) as z:
        for fn in os.listdir(fdir):
            z.write(os.path.join(fdir,fn), arcname=fn)
    return fid

# ---------- orchestrator ----------
async def gather_checks(target, httpx_json, alive_file, outdir, per_target, path_check_top_hosts):
    ensure_dir(outdir)

    # Parse httpx JSON lines
    urls, titles, techs, by_host = [], {}, defaultdict(set), defaultdict(list)
    schemes = defaultdict(lambda: "https")
    if httpx_json and os.path.isfile(httpx_json):
        with open(httpx_json,"r",encoding="utf-8",errors="ignore") as fh:
            for line in fh:
                try:
                    j = json.loads(line)
                except: continue
                u = j.get("url"); h = j.get("host"); t = (j.get("title") or "")
                if not u or not h: continue
                u = u.rstrip("/")
                urls.append(u); titles[u] = t
                schemes[h] = j.get("scheme","https")
                for tech in (j.get("tech","") or "").split(","):
                    if tech.strip(): techs[h].add(tech.strip().lower())
                by_host[h].append(u)

    alive = []
    if alive_file and os.path.isfile(alive_file):
        alive = [l.strip() for l in open(alive_file,"r",encoding="utf-8",errors="ignore") if l.strip()]

    # Rank hosts by interestingness (more login/admin keywords, tech hints)
    host_scores = Counter()
    for h, lst in by_host.items():
        t_hits = sum(1 for u in lst if AUTH_HINT.search(titles.get(u,"")))
        tech_hits = sum(1 for te in techs[h] if te in {"grafana","kibana","jenkins","wordpress","gitlab","minio","sonarqube","prometheus"})
        host_scores[h] = (2*t_hits) + tech_hits + len(lst)/50.0

    top_hosts = [h for h,_ in host_scores.most_common(path_check_top_hosts or 100)]
    # Build path candidates on BASE of each host
    base_urls = [f"{schemes[h]}://{h}" for h in top_hosts]

    findings = []
    sem = asyncio.Semaphore(per_target)
    async with aiohttp.ClientSession() as session:
        async def bounded(fn, *a, **kw):
            async with sem: return await fn(*a, **kw)

        # 1) Per-URL checks that use live endpoints list (auth redirects, CORS, admin)
        cors_tasks   = [bounded(check_cors, session, u) for u in alive]
        redir_tasks  = [bounded(check_redirects, session, u) for u in alive]
        admin_tasks  = [bounded(check_admin_panel, session, u) for u in alive if ("admin" in u or "dashboard" in u or AUTH_HINT.search(titles.get(u,"")))]
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
        for u, r in zip([u for u in alive if ("admin" in u or "dashboard" in u or AUTH_HINT.search(titles.get(u,"")))], admin_res):
            if r:
                s = score("admin", signal=0.9)
                findings.append(dict(kind="admin", url=u, resp=r["resp"], score=s))

        # 2) Per-host path checks (.env, .git, backup files, dir listing)
        dir_tasks   = [bounded(check_dirlisting, session, b + "/") for b in base_urls]
        git_tasks   = [bounded(check_git_exposed, session, b) for b in base_urls]
        env_tasks   = [bounded(check_env_exposed, session, b) for b in base_urls]
        bak_tasks   = [bounded(check_backup_files, session, b) for b in base_urls]
        dir_res, git_res, env_res, bak_res = await asyncio.gather(
            asyncio.gather(*dir_tasks), asyncio.gather(*git_tasks),
            asyncio.gather(*env_tasks), asyncio.gather(*bak_tasks)
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

        # 3) Subdomain takeover (by host)
        hosts = list(by_host.keys())
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
            if f["score"] >= AUTO_DRAFT_THRESHOLD: auto += 1
        S.write(f"Auto-drafts (>= {AUTO_DRAFT_THRESHOLD}): {auto}\n")

def fold_nuclei(target, nuclei_json, outdir):
    if not nuclei_json or not os.path.isfile(nuclei_json): return
    ensure_dir(outdir)
    count = 0
    with open(nuclei_json,"r",encoding="utf-8",errors="ignore") as fh:
        for line in fh:
            try: j = json.loads(line)
            except: continue
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

#!/usr/bin/env python3
# Smart post-httpx filter + validators + evidence packer.
import argparse, asyncio, aiohttp, os, json, re, hashlib, time, zipfile
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl
from collections import defaultdict
from vendor_fingerprints import VENDORS

AUTO_DRAFT_THRESHOLD = 50  # 0..100

ADMIN_MARKERS = re.compile(
    r'(grafana|kibana|jenkins|sonarqube|nexus repository|pgadmin|prometheus|kubernetes dashboard|rabbitmq|airflow|superset|laravel horizon)',
    re.I,
)
AUTH_HINT = re.compile(r'(login|sign[\s_-]*in|oauth|authorize|sso|reset)', re.I)

def ensure_dir(p): os.makedirs(p, exist_ok=True)
def sha256(b): return hashlib.sha256(b).hexdigest()

def redacted_snippet(b: bytes, limit_kb=64):
    if len(b) > limit_kb*1024:
        return sha256(b), b[:200], b[-200:], True
    return sha256(b), b, b"", False

BASE_WEIGHTS = {"cors": 0.9, "redirect_auth": 0.8, "takeover": 0.85, "admin": 0.7, "nuclei": 0.6}
def score(kind: str, auth=False, noisy=2) -> int:
    w = BASE_WEIGHTS.get(kind, 0.5)
    mult = 1.4 if auth else 1.0
    s = w * mult * (10.0 / max(1.0, float(noisy)))
    return int(max(0, min(100, s * 10)))

def with_query(u, kv):
    p = urlparse(u); q = dict(parse_qsl(p.query, keep_blank_values=True)); q.update(kv)
    return urlunparse(p._replace(query=urlencode(q, doseq=True)))

async def fetch(session, method, url, headers=None, allow_redirects=False):
    try:
        async with session.request(method, url, headers=headers or {}, allow_redirects=allow_redirects, timeout=15) as r:
            return dict(ok=True, status=r.status, url=str(r.url),
                        headers={k.lower(): v for k,v in r.headers.items()},
                        body=await r.read())
    except Exception as e:
        return dict(ok=False, error=str(e), status=0, url=url, headers={}, body=b"")

async def check_cors(session, url):
    base = await fetch(session, "GET", url)
    test = await fetch(session, "GET", url, headers={"Origin": "https://evil.example"})
    if not base["ok"] or not test["ok"]: return None
    h = test["headers"]
    if h.get("access-control-allow-credentials","").lower() == "true":
        acao = h.get("access-control-allow-origin","")
        if acao and acao != "*" and "evil.example" in acao:
            authish = ("set-cookie" in h) or ("www-authenticate" in h) or base["status"] in (401,403)
            return dict(kind="cors", base=base, test=test, origin="https://evil.example", auth=authish)
    return None

REDIRECT_PARAMS = ["next","redirect","redirect_uri","return","return_to","continue","url","goto","dest","destination","post_auth_return"]
ATTACK_URL = "https://example.org/"

async def check_redirect(session, url):
    if not (AUTH_HINT.search(url) or re.search(r'/login|/signin|/auth|/oauth|/reset', url, re.I)):
        return None
    for p in REDIRECT_PARAMS:
        u = with_query(url, {p: ATTACK_URL})
        r = await fetch(session, "GET", u, allow_redirects=False)
        loc = r["headers"].get("location","")
        if r["ok"] and r["status"] in (301,302,303,307,308) and ATTACK_URL in loc:
            return dict(kind="redirect_auth", test_url=u, resp=r)
    return None

async def check_admin(session, url):
    r = await fetch(session, "GET", url)
    if not r["ok"] or r["status"] in (401,403): return None
    text = r["body"].decode(errors="ignore")
    if ADMIN_MARKERS.search(text):
        return dict(kind="admin", resp=r)
    return None

async def check_takeover(session, host, scheme="https"):
    r = await fetch(session, "GET", f"{scheme}://{host}/")
    if not r["ok"]: return None
    body = r["body"].decode(errors="ignore"); hdrs = r["headers"]
    for vendor, fp in VENDORS.items():
        if any(sig.lower() in body.lower() for sig in fp.get("body_contains", [])) or \
           any(sig.lower() in json.dumps(hdrs).lower() for sig in fp.get("header_contains", [])):
            return dict(kind="takeover", vendor=vendor, resp=r)
    return None

def write_evidence(outdir, finding):
    ensure_dir(outdir)
    now = int(time.time())
    url_or_host = finding.get("url") or finding.get("host") or ""
    fid = f"{finding.get('kind','finding')}-{now}-{hashlib.md5(url_or_host.encode()).hexdigest()[:6]}"
    fdir = os.path.join(outdir, fid); ensure_dir(fdir)

    with open(os.path.join(fdir, "meta.json"), "w") as fh:
        json.dump({"id": fid, "kind": finding.get("kind"), "url": url_or_host, "score": finding.get("score",0), "timestamp": now}, fh, indent=2)

    def dump_resp(prefix, resp):
        if not resp: return
        h, head, tail, clipped = redacted_snippet(resp.get("body", b""))
        with open(os.path.join(fdir, f"{prefix}_summary.txt"), "w", encoding="utf-8", errors="ignore") as fh:
            fh.write(f"URL: {resp.get('url')}\nStatus: {resp.get('status')}\n\nHeaders:\n" +
                     "\n".join([f"{k}: {v}" for k,v in resp.get("headers",{}).items()]) +
                     f"\n\nBodySHA256: {h}\nClipped: {clipped}\n")

    for k in ("base","test","resp"):
        if k in finding: dump_resp(k, finding[k])

    if finding["kind"] == "cors":
        with open(os.path.join(fdir, "poc.html"), "w") as fh:
            fh.write(f"""<!doctype html><h1>CORS PoC</h1><script>
(async()=>{{try{{const r=await fetch('{finding.get('url')}',{{credentials:'include',headers:{{Origin:'{finding.get('origin')}'}}}});document.body.innerText=(await r.text()).slice(0,400)}}catch(e){{console.log(e)}}}})();
</script>""")

    if finding["kind"] == "redirect_auth":
        with open(os.path.join(fdir, "poc.txt"), "w") as fh:
            fh.write(f"Trigger: {finding['test_url']}\nLocation: {finding['resp'].get('headers',{}).get('location','')}\n")

    with open(os.path.join(fdir, "finding.md"), "w") as fh:
        fh.write(f"# {finding['kind'].upper()} \nURL/Host: {url_or_host}\nScore: {finding['score']}\n")

    # zip bundle
    z = os.path.join(outdir, f"{fid}.zip")
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zp:
        for fn in os.listdir(fdir): zp.write(os.path.join(fdir, fn), arcname=fn)
    return fid

async def run_checks(target, httpx_json, outdir, per_target):
    ensure_dir(outdir)
    urls, titles, host_scheme = [], {}, defaultdict(lambda: "https")

    if httpx_json and os.path.isfile(httpx_json):
        with open(httpx_json, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                try: j = json.loads(line)
                except: continue
                u = j.get("url"); 
                if u:
                    u = u.rstrip("/")
                    urls.append(u)
                    titles[u] = j.get("title","")
                if j.get("host") and j.get("scheme"):
                    host_scheme[j["host"]] = j["scheme"]

    if not urls:
        urls = [target if target.startswith("http") else f"https://{target}"]

    sem = asyncio.Semaphore(per_target)
    async with aiohttp.ClientSession() as session:
        async def b(f,*a,**k):
            async with sem: return await f(*a,**k)

        cors = await asyncio.gather(*[b(check_cors, session, u) for u in urls])
        redr = await asyncio.gather(*[b(check_redirect, session, u) for u in urls])
        admin_candidates = [u for u in urls if ("admin" in u or "dashboard" in u or AUTH_HINT.search(titles.get(u,"")))]
        admin = await asyncio.gather(*[b(check_admin, session, u) for u in admin_candidates])
        hosts = sorted(set([urlparse(u).hostname for u in urls if urlparse(u).hostname]))
        tk = await asyncio.gather(*[b(check_takeover, session, h, host_scheme[h]) for h in hosts])

    findings, autos = [], 0
    for u, r in zip(urls, cors):
        if r:
            s = score("cors", auth=r.get("auth", False), noisy=2)
            findings.append(dict(kind="cors", url=u, score=s, **r))
    for u, r in zip(urls, redr):
        if r:
            s = score("redirect_auth", auth=True, noisy=2)
            r.update(dict(url=u, score=s)); findings.append(r)
    for u, r in zip(admin_candidates, admin):
        if r:
            s = score("admin", noisy=3)
            findings.append(dict(kind="admin", url=u, resp=r["resp"], score=s))
    for h, r in zip(hosts, tk):
        if r:
            s = score("takeover", noisy=1)
            findings.append(dict(kind="takeover", host=h, resp=r["resp"], vendor=r["vendor"], score=s))

    lines = []
    for f in findings:
        fid = write_evidence(outdir, f)
        lines.append(f"[{target}] {f['kind']} -> score {f['score']} :: {fid}")
        if f["score"] >= AUTO_DRAFT_THRESHOLD: autos += 1

    with open(os.path.join(outdir, "summary.txt"), "a") as fh:
        for l in lines: fh.write(l + "\n")
        fh.write(f"Auto-drafts (>= {AUTO_DRAFT_THRESHOLD}): {autos}\n")

def fold_nuclei(domain, nuclei_json, outdir):
    if not nuclei_json or not os.path.isfile(nuclei_json): return
    ensure_dir(outdir)
    c = 0
    with open(nuclei_json, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            try: j = json.loads(line)
            except: continue
            url = j.get("matched-at") or j.get("host") or j.get("url")
            if not url: continue
            s = score("nuclei", noisy=3)
            write_evidence(outdir, dict(kind="nuclei", url=url, score=s, resp=dict(status=0, headers=j, body=b"")))
            c += 1
    with open(os.path.join(outdir, "summary.txt"), "a") as fh:
        fh.write(f"[{domain}] folded nuclei findings: {c}\n")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target")
    ap.add_argument("--httpx-json")
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--per-target", type=int, default=8)
    ap.add_argument("--nuclei-json")
    ap.add_argument("--fold-nuclei", action="store_true")
    a = ap.parse_args()
    if a.fold_nuclei:
        fold_nuclei(a.target or "local", a.nuclei_json, a.outdir)
    else:
        if not a.target: raise SystemExit("Provide --target")
        asyncio.run(run_checks(a.target, a.httpx_json, a.outdir, a.per_target))

if __name__ == "__main__":
    main()

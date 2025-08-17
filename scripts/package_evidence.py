#!/usr/bin/env python3
import argparse, json, os, shutil, hashlib, time, zipfile, re
parser = argparse.ArgumentParser()
parser.add_argument('outdir')
parser.add_argument('--out', default=None)
args = parser.parse_args()

validated_file = os.path.join(args.outdir,'validated.json')
if not os.path.exists(validated_file):
    print("[+] no validated findings to package"); exit(0)

items = json.load(open(validated_file))
packdir = os.path.join(args.outdir,'evidence')
if os.path.exists(packdir):
    shutil.rmtree(packdir)
os.makedirs(packdir)

meta = {'runner_id': os.environ.get('GITHUB_RUN_ID','local'), 'timestamp_utc': int(time.time()), 'items': []}
token_re = re.compile(r'([A-Za-z0-9_\\-]{24,})')

for i,it in enumerate(items):
    fid = f"finding_{i+1}"
    fdir = os.path.join(packdir,fid); os.makedirs(fdir)
    with open(os.path.join(fdir,'finding.md'),'w') as fh:
        fh.write(f"# {fid}\\nType: {it['type']}\\nScore: {it['score']}\\n\\nMeta:\\n")
        fh.write(json.dumps(it['meta'], indent=2))
    # sanitized request placeholder
    with open(os.path.join(fdir,'request.txt'),'w') as fh:
        fh.write("# sanitized curl examples (no credentials)\\n")
        fh.write("curl -I https://example\\n")
    # response summary (header only + sha)
    sh = hashlib.sha256(json.dumps(it['meta']).encode()).hexdigest()
    with open(os.path.join(fdir,'response-summary.txt'),'w') as fh:
        fh.write("headers: redacted\\nbody-sha256: " + sh + "\\n")
    # minimal PoC
    poc = "<!-- safe PoC placeholder -> opens a page that fetches a benign endpoint using credentials: include (no exfil) -->\\n"
    with open(os.path.join(fdir,'poc.html'),'w') as fh:
        fh.write(poc)
    meta['items'].append({'id':fid,'type':it['type'],'score':it['score']})

with open(os.path.join(packdir,'meta.json'),'w') as fh:
    json.dump(meta, fh, indent=2)

outzip = args.out or os.path.join(args.outdir,'evidence.zip')
with zipfile.ZipFile(outzip,'w', zipfile.ZIP_DEFLATED) as zf:
    for root, _, files in os.walk(packdir):
        for f in files:
            zf.write(os.path.join(root,f), arcname=os.path.relpath(os.path.join(root,f), packdir))
print(f"[+] evidence packaged -> {outzip}")

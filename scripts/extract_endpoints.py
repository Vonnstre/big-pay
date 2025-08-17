#!/usr/bin/env python3
import json, os, re, glob, hashlib
ROOT="findings"
PARAMS = ["next","return","redirect","redirect_uri","continue","url","target","dest","post_auth_return","callback"]
for tdir in glob.glob(f"{ROOT}/*"):
    target=os.path.basename(tdir)
    live=os.path.join(tdir,"live.txt")
    endpoints=set()
    if os.path.exists(live):
        with open(live) as f:
            for u in f:
                u=u.strip()
                if not u: continue
                # seed common auth paths
                for p in ("/login","/signin","/reset","/oauth/authorize"):
                    endpoints.add(u.rstrip("/")+p)
                endpoints.add(u)
    # save
    with open(os.path.join(tdir,"endpoints.json"),"w") as f:
        json.dump(sorted(endpoints), f, indent=2)
    # params list
    with open(os.path.join(tdir,"params.json"),"w") as f:
        json.dump(PARAMS, f)

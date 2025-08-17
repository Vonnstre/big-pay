#!/usr/bin/env python3
import json, os
here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here,'..','config','vendor_fingerprints.json')) as f:
    VENDORS = json.load(f)

def match_vendor(cname, body):
    cname = (cname or '').lower()
    body = (body or '').lower()
    for name,info in VENDORS.items():
        for d in info.get('domains',[]):
            if d in cname and info.get('needle','').lower() in body:
                return name
    return None

if __name__ == '__main__':
    import sys
    print(match_vendor(sys.argv[1], sys.argv[2]))

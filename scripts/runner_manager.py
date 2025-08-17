#!/usr/bin/env python3
import json, os, time
STATE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'state', 'pain.json')
os.makedirs(os.path.dirname(STATE), exist_ok=True)
try:
    data = json.load(open(STATE))
except:
    data = {}

def inc(host):
    v = data.get(host, {'pain':0})
    v['pain'] = v.get('pain',0) + 1
    v['last'] = int(time.time())
    data[host] = v
    json.dump(data, open(STATE,'w'), indent=2)
    return v['pain']

def getp(host):
    return data.get(host, {}).get('pain',0)

def should_throttle(host):
    return getp(host) >= 3

if __name__ == '__main__':
    import sys
    if len(sys.argv) >= 3 and sys.argv[1] == 'inc':
        print(inc(sys.argv[2]))
    elif len(sys.argv) >= 3 and sys.argv[1] == 'get':
        print(getp(sys.argv[2]))
    else:
        print("usage: runner_manager.py inc|get <host>")

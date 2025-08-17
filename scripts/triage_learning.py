#!/usr/bin/env python3
import sys, json, os
STATE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'state', 'triage_learning.json')
os.makedirs(os.path.dirname(STATE), exist_ok=True)
try:
    data = json.load(open(STATE))
except:
    data = {}

prog, ftype, result = sys.argv[1], sys.argv[2], sys.argv[3]
key = f"{prog}::{ftype}"
entry = data.get(key, {'accepted':0,'informational':0,'duplicate':0})
entry[result] = entry.get(result,0) + 1
data[key] = entry
json.dump(data, open(STATE,'w'), indent=2)
print(f"[+] triage_learning updated: {key} -> {entry}")

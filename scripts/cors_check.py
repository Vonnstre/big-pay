#!/usr/bin/env python3
import argparse, json, requests, time

parser = argparse.ArgumentParser()
parser.add_argument('endpoints_json')
parser.add_argument('--out', default='cors.json')
parser.add_argument('--origin', default='https://attacker.example')
args = parser.parse_args()

with open(args.endpoints_json) as f:
    endpoints = json.load(f)

results = []
for host in endpoints.keys():
    url = 'https://' + host
    try:
        headers = {'Origin': args.origin, 'User-Agent': 'agg-scanner/1.0'}
        r = requests.get(url, headers=headers, timeout=12, allow_redirects=True)
        acao = r.headers.get('Access-Control-Allow-Origin','')
        acac = r.headers.get('Access-Control-Allow-Credentials','')
        setcookie = 'Set-Cookie' in r.headers
        auth_hint = ('WWW-Authenticate' in r.headers) or (r.status_code==401)
        vulnerable = False
        reason = ''
        if acac and acac.lower()=='true' and acao and acao != '*':
            # require either cookie or auth behavior
            if setcookie or auth_hint:
                vulnerable = True
                reason = f"ACAO={acao} ACAC={acac}"
        results.append({'host':host,'status':r.status_code,'acao':acao,'acac':acac,'setcookie':setcookie,'auth_hint':auth_hint,'vulnerable':vulnerable,'reason':reason})
    except Exception as e:
        results.append({'host':host,'error':str(e)})
    time.sleep(0.15)

with open(args.out,'w') as f:
    json.dump(results,f,indent=2)
print(f"[+] cors -> {args.out}")

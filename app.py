import argparse
import datetime as dt
import json
from urllib.error import HTTPError
from urllib.request import Request
from common import serve
from security_utils import bounded_read, open_no_redirect, validate_url

def analyze(values):
    try: base=validate_url(values.get('url',''), resolve=True)
    except ValueError as exc:
        raw=values.get('url','').strip(); base=validate_url('https://'+raw, resolve=True) if raw and '://' not in raw else None
        if base is None: return {'error':str(exc)}
    target=f'{base.scheme}://{base.netloc}/.well-known/security.txt'; req=Request(target,headers={'User-Agent':'defensive-security-txt-checker/2.0'})
    try:
        with open_no_redirect(req,timeout=8) as response: text=bounded_read(response).decode('utf-8','replace'); status=response.status
    except HTTPError as exc:
        return {'checked_url':target,'status':exc.code,'errors':['security.txt could not be fetched without following a redirect'],'valid':False,'redirects_followed':False}
    except Exception as exc: return {'error':f'security.txt fetch failed: {type(exc).__name__}'}
    fields={}; errors=[]; warnings=[]
    for line in text.splitlines():
        if len(line)>4096: errors.append('A line exceeds the 4096 character limit.'); continue
        if not line or line.startswith('#') or ':' not in line: continue
        key,value=line.split(':',1); key=key.strip(); value=value.strip()
        if key: fields.setdefault(key,[]).append(value)
    if 'Contact' not in fields: errors.append('Required Contact field is missing.')
    elif not all(v.startswith(('mailto:','https://','http://')) for v in fields['Contact']): errors.append('Contact must contain mailto or HTTP(S) URIs.')
    if 'Expires' not in fields: errors.append('Required Expires field is missing.')
    else:
        try:
            expiry=dt.datetime.fromisoformat(fields['Expires'][0].replace('Z','+00:00'))
            if expiry.tzinfo is None: raise ValueError
            if expiry<=dt.datetime.now(dt.timezone.utc): warnings.append('Expires is in the past.')
        except ValueError: errors.append('Expires is not a valid RFC 3339 timestamp with timezone.')
    return {'checked_url':target,'status':status,'fields':fields,'errors':errors,'warnings':warnings,'valid':not errors,'redirects_followed':False,'note':'Checks only the well-known file and does not submit reports or follow its links.'}
def main():
    parser=argparse.ArgumentParser(description='Check one authorized site security.txt file.')
    parser.add_argument('url',nargs='?'); parser.add_argument('--web',action='store_true'); parser.add_argument('--port',type=int,default=8092)
    args=parser.parse_args()
    if args.web: serve('security.txt Checker',[('url','Site URL or hostname','text','https://example.com')],analyze,args.port)
    elif args.url: print(json.dumps(analyze({'url':args.url}),indent=2))
    else: parser.print_help()
if __name__=='__main__': main()

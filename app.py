import argparse
import datetime as dt
import json
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from common import serve

def analyze(values):
    raw = values.get('url','').strip()
    if not raw: return {'error':'Enter one site URL or hostname.'}
    if '://' not in raw: raw = 'https://' + raw
    parsed = urlsplit(raw)
    if parsed.scheme not in ('http','https') or not parsed.netloc: return {'error':'Enter one valid hostname or http(s) URL.'}
    target = f'{parsed.scheme}://{parsed.netloc}/.well-known/security.txt'
    req = Request(target, headers={'User-Agent':'defensive-security-txt-checker/1.0'})
    with urlopen(req, timeout=8) as response: text = response.read(256000).decode('utf-8','replace')
    fields = {}
    for line in text.splitlines():
        if not line or line.startswith('#') or ':' not in line: continue
        key, value = line.split(':',1); fields.setdefault(key.strip(), []).append(value.strip())
    errors=[]; warnings=[]
    if 'Contact' not in fields: errors.append('Required Contact field is missing.')
    if 'Expires' not in fields: errors.append('Required Expires field is missing.')
    else:
        try:
            expiry = dt.datetime.fromisoformat(fields['Expires'][0].replace('Z','+00:00'))
            if expiry <= dt.datetime.now(dt.timezone.utc): warnings.append('Expires is in the past.')
        except ValueError: errors.append('Expires is not a valid RFC 3339 timestamp.')
    return {'checked_url':target,'fields':fields,'errors':errors,'warnings':warnings,'valid':not errors,'note':'This checks only the well-known file and does not submit reports or follow its links.'}

def main():
    parser = argparse.ArgumentParser(description='Check one authorized site security.txt file.')
    parser.add_argument('url', nargs='?'); parser.add_argument('--web', action='store_true'); parser.add_argument('--port', type=int, default=8092)
    args = parser.parse_args()
    if args.web: serve('security.txt Checker', [('url','Site URL or hostname','text','https://example.com')], analyze, args.port)
    elif args.url: print(json.dumps(analyze({'url':args.url}), indent=2))
    else: parser.print_help()

if __name__ == '__main__': main()

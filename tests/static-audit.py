from pathlib import Path
from bs4 import BeautifulSoup
import re, subprocess, sys

ROOT = Path(__file__).resolve().parents[1]
errors=[]
index=(ROOT/'index.html').read_text(encoding='utf-8')
soup=BeautifulSoup(index,'html.parser')

# Local resource existence
for tag, attr in [('script','src'),('link','href'),('img','src')]:
    for el in soup.find_all(tag):
        value=el.get(attr)
        if not value or value.startswith(('#','data:','http://','https://','mailto:')): continue
        path=value.split('?',1)[0]
        if path == '/': path='/index.html'
        p=ROOT/path.lstrip('/') if path.startswith('/') else ROOT/path
        if not p.exists(): errors.append(f'Missing asset referenced by {tag}: {value}')


# UI selector consistency: every direct $('#id') reference in app.js must exist in index.html.
app=(ROOT/'js/app.js').read_text()
ids_in_html={el.get('id') for el in soup.find_all(attrs={'id': True})}
for ident in sorted(set(re.findall(r"\$\('#([A-Za-z0-9_-]+)'\)", app))):
    if ident not in ids_in_html: errors.append(f'app.js references missing element id: {ident}')

# IDs must be unique.
all_ids=[el.get('id') for el in soup.find_all(attrs={'id': True})]
for ident in sorted(set(x for x in all_ids if all_ids.count(x)>1)):
    errors.append(f'Duplicate HTML id: {ident}')

if len(soup.select('[data-step-panel]')) != 7: errors.append('Generator must contain exactly 7 step panels.')

# No third-party executable dependencies
for el in soup.find_all('script'):
    src=el.get('src','')
    if src.startswith(('http://','https://')): errors.append(f'External script: {src}')
for el in soup.find_all('link'):
    href=el.get('href','')
    rel=' '.join(el.get('rel') or [])
    if href.startswith(('http://','https://')) and ('stylesheet' in rel or 'preload' in rel): errors.append(f'External style/preload: {href}')

if (ROOT/'functions').exists(): errors.append('functions/ directory exists; would invoke Pages Functions.')
if '_headers' not in [p.name for p in ROOT.iterdir()]: errors.append('Missing _headers.')
headers=(ROOT/'_headers').read_text()
for required in ['Content-Security-Policy','frame-ancestors \'none\'','Permissions-Policy','Referrer-Policy']:
    if required not in headers: errors.append(f'Missing security header/policy: {required}')

# No obvious submission/network code in app modules (service worker is allowed to fetch same-origin assets).
for p in [ROOT/'js/app.js', ROOT/'js/crypto.js', ROOT/'js/policy.js']:
    text=p.read_text()
    if re.search(r'\bfetch\s*\(', text): errors.append(f'Unexpected fetch() in application module: {p.name}')
    if re.search(r'XMLHttpRequest|WebSocket\s*\(', text): errors.append(f'Unexpected network primitive in application module: {p.name}')

# Syntax check all JS/MJS
for p in list(ROOT.rglob('*.js')) + list(ROOT.rglob('*.mjs')):
    cp=subprocess.run(['node','--check',str(p)],capture_output=True,text=True)
    if cp.returncode: errors.append(f'JS syntax failed {p}: {cp.stderr.strip()}')

files=[p for p in ROOT.rglob('*') if p.is_file()]
if len(files) >= 20000: errors.append(f'File count {len(files)} exceeds Cloudflare Free static file limit.')
large=[p for p in files if p.stat().st_size > 25*1024*1024]
if large: errors.append('Static file exceeds 25 MiB: '+', '.join(str(x) for x in large))

# Ensure no actual secrets accidentally packaged.
secret_patterns=[r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', r'AKIA[0-9A-Z]{16}', r'ghp_[A-Za-z0-9]{30,}']
for p in files:
    if p.suffix.lower() not in {'.html','.js','.mjs','.md','.json','.txt','.xml','.webmanifest',''}: continue
    try: text=p.read_text(errors='ignore')
    except: continue
    for pat in secret_patterns:
        if re.search(pat,text): errors.append(f'Possible packaged secret in {p.relative_to(ROOT)}')

print(f'Files: {len(files)}')
print(f'Total bytes: {sum(p.stat().st_size for p in files)}')
if errors:
    print('AUDIT FAILED')
    for e in errors: print('-',e)
    sys.exit(1)
print('Static audit passed.')

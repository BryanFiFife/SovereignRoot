#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
OLD = 'https://sovereignroot.pages.dev'
if len(sys.argv) != 2:
    raise SystemExit('Usage: python tools/set-domain.py https://your-project.pages.dev')
new = sys.argv[1].rstrip('/')
if not (new.startswith('https://') or new.startswith('http://localhost')):
    raise SystemExit('Use an https:// URL (or http://localhost for local testing).')
files = [
    ROOT/'index.html', ROOT/'404.html', ROOT/'robots.txt', ROOT/'sitemap.xml',
    ROOT/'protocol/sovereignty.schema.json'
]
for path in files:
    text = path.read_text(encoding='utf-8')
    path.write_text(text.replace(OLD, new), encoding='utf-8')
    print('updated', path.relative_to(ROOT))
print('Domain set to', new)

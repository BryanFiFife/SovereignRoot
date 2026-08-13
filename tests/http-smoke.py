from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from threading import Thread
from urllib.request import urlopen
import os, socket

ROOT=Path(__file__).resolve().parents[1]
os.chdir(ROOT)
server=ThreadingHTTPServer(('127.0.0.1',0),SimpleHTTPRequestHandler)
Thread(target=server.serve_forever,daemon=True).start()
port=server.server_port
paths=['/','/css/styles.css','/js/sovereignroot.bundle.js','/js/app.js','/js/crypto.js','/js/policy.js','/assets/logo.svg','/assets/og-card.png','/protocol/sovereignty.schema.json','/protocol/SOVEREIGNROOT-SPEC.md','/manifest.webmanifest','/_headers']
try:
    for path in paths:
        with urlopen(f'http://127.0.0.1:{port}{path}',timeout=3) as r:
            body=r.read()
            assert r.status==200, (path,r.status)
            assert body, f'{path} returned empty body'
            print('✓',path,r.status,len(body))
finally:
    server.shutdown()
print('HTTP smoke test passed.')

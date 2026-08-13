from pathlib import Path
import re
root = Path(__file__).resolve().parents[1]
html = (root/'index.html').read_text(encoding='utf-8')
manifest = (root/'manifest.webmanifest').read_text(encoding='utf-8')
bundle = (root/'js/sovereignroot.bundle.js').read_text(encoding='utf-8')

checks = {
    'stylesheet is relative': 'href="./css/styles.css"' in html,
    'logo is relative': 'src="./assets/logo.svg"' in html,
    'manifest is relative': 'href="./manifest.webmanifest"' in html,
    'production script is classic bundle': '<script src="./js/sovereignroot.bundle.js"></script>' in html,
    'no root-relative local href/src': not re.search(r'(?:href|src)="/(?:assets|css|js|docs|protocol|reference|manifest)', html),
    'manifest icon is relative': '"src":"./assets/logo.svg"' in manifest,
    'bundle contains no ES module imports': not re.search(r'(?m)^\s*import\s', bundle),
    'bundle contains no ES module exports': not re.search(r'(?m)^\s*export\s', bundle),
    'bundle exists and is non-empty': len(bundle) > 10000,
}
failed = [name for name, ok in checks.items() if not ok]
for name, ok in checks.items(): print(('✓' if ok else '✗'), name)
if failed:
    raise SystemExit('Direct-open audit failed: ' + ', '.join(failed))
print('Direct-open structural audit passed.')

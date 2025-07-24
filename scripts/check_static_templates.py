import os
import re
from pathlib import Path

TEMPLATE_DIR = Path('WebAppIAM/core/templates')
STATIC_DIR = Path('WebAppIAM/core/static')

CSS_RE = re.compile(r"static ['\"](?P<path>css/[^'\"]+)['\"]")
JS_RE = re.compile(r"static ['\"](?P<path>js/[^'\"]+)['\"]")

missing = []

for html in TEMPLATE_DIR.rglob('*.html'):
    text = html.read_text()
    for match in CSS_RE.finditer(text):
        path = STATIC_DIR / match.group('path')
        if not path.exists():
            missing.append(f"{html}: missing {path}")
    for match in JS_RE.finditer(text):
        path = STATIC_DIR / match.group('path')
        if not path.exists():
            missing.append(f"{html}: missing {path}")

if missing:
    print("Missing static files:")
    for m in missing:
        print(m)
    exit(1)

print('All referenced static files exist.')

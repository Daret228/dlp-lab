#!/bin/bash
# Install only central UI files; keep endpoint policy and services unchanged.
set -euo pipefail
if [[ $(id -u) != 0 ]]; then echo 'Запустите через sudo.' >&2; exit 1; fi
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
target=/usr/lib/dlp-lab/src/dlp
[[ -f "$target/central.py" ]] || { echo 'Пакет DLP не установлен.' >&2; exit 1; }
# Verify that the server change is only the HTML loader, not a backend migration.
/usr/bin/python3 - "$target/central.py" "$project_dir/src/dlp/central.py" <<'PY'
import sys
from pathlib import Path

def backend(path):
    text=Path(path).read_text()
    a=text.index('PAGE = ')
    b=text.index('JS = ',a)
    return text[:a]+text[b:]
if backend(sys.argv[1]) != backend(sys.argv[2]):
    raise SystemExit('Версии серверной логики различаются. Используйте обновление DEB.')
PY
backup=$(mktemp -d /var/backups/dlp-central-ui.XXXXXXXX)
for name in central.py central_ui.js central_page.html; do
    if [[ -f "$target/$name" ]]; then cp -a -- "$target/$name" "$backup/$name"; fi
done
for name in central_page.html central_ui.js central.py; do
    install -o root -g root -m 0644 "$project_dir/src/dlp/$name" "$target/$name"
done
systemctl restart dlp-lab-central.service
systemctl is-active --quiet dlp-lab-central.service
printf 'Панель обновлена. Резервная копия: %s\nОбновите страницу http://127.0.0.1:8766/ и войдите снова.\n' "$backup"

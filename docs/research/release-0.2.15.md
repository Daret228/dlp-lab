# Проверка релиза 0.2.15 — 5 ноября 2026

- Debian13 amd64: сборка scripts/build-deb.sh --local-deps завершилась успешно.
- 282 unittest, 3 skip: привилегированные fanotify и явная SQLCipher-библиотека.
- Изолированный lifecycle: install, configure, upgrade0.2.14→0.2.15,
  сохранение админской политики, remove, purge — PASS.
- Из DEB извлечены и побайтово сверены центральные HTML/JS/Python,
  dlp-admin-token и policy.yaml; права команды0755.
- Compose2.26.1: config --quiet — PASS. Docker Engine отсутствует:
  сборка образа и запуск контейнера не проверены.
- Python-entrypoint проверен вне контейнера: HTTPS/CA,401, регистрация,
  подтверждение события, сохранение токена и события после перезапуска.
- JS syntax, bash syntax, git diff --check — PASS.
- Debian12: VM недоступна, новая сборка не выполнена.
- Системные рабочие службы не заменялись и не перезапускались.

SHA256 Debian13 DEB:
`38221abc3687bfa69d3b682eed0f4ac017cbe7007f26c482904814b8bf1751c7`

SHA256 архива установщика Debian13:
`08d62c632985131cd289ec293b763cb180b50f7d2d646024e2e1530693b5a707`

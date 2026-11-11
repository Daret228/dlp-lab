# Разработка и проверка

Для установки готового агента используйте [INSTALL](INSTALL.md).

## Сборка пакета

Собирайте на той же версии Debian, для которой предназначен агент. На Debian 13:

```bash
sudo apt install dpkg-dev gcc make python3 python3-yaml poppler-utils
make test        # тесты Python
make build       # native-компоненты
./scripts/build-deb.sh
```

Результат — `build/dlp-lab_<версия>_amd64.deb`; сборка повторно прогоняет
тесты и не устанавливает агент. Привилегированные тесты и SQLCipher требуют
своего окружения: пропуски не считаются проверкой этих механизмов. Зависимости
выполнения — в `Depends` файла `debian/control`.

Для Debian 12 нужен нативный пакет с суффиксом `~deb12u1` в `debian/changelog`
и проверенный SQLCipher4 DEB как входной артефакт (задайте абсолютный путь):

```bash
export DLP_SQLCIPHER_DEB="$HOME/dlp-build-input/libsqlcipher1_4.6.1-2~dlplab12.1_amd64.deb"
./scripts/build-deb.sh
```

Входной DEB нужен только сборщику. `packaging/sqlcipher_bundle.py` проверяет
SHA-256, имя, версию и архитектуру; неизвестный файл останавливает сборку.
Происхождение backport — [опыт Debian12](research/debian12_port_2026-10-30.md);
зафиксированный SHA-256: `1be243f9b4e36186990e93e951aec966ff67ed436ee0a05032349826a255670b`.
Артефакт в Git не хранится; при обновлении зависимости сопровождающий
проверяет новый файл и обновляет pin вместе с испытаниями.

## Проверка и ручной запуск

Ручной анализ из исходников:

```bash
./scripts/dlp analyze --text 'Обычная встреча'
./scripts/dlp analyze --text 'коммерческая тайна'
```

Файловый монитор из исходников не запускайте одновременно с установленной
службой. Ручной запуск установленного файлового контроля:

```bash
sudo systemctl stop dlp-lab-files.service
sudo dlp-lab-run-files
# после Ctrl+C верните службу:
sudo systemctl start dlp-lab-files.service
```

Docker-контур проверяется в отдельном временном проекте
(`sudo python3 scripts/test-docker.py`): тестовые контейнеры и данные,
HTTPS, аутентификация, приём события, сохранение состояния; рабочий сервер
не затрагивается. Изолированная проверка пакета Debian12 без системной
SQLCipher:

```bash
DLP_TEST_NO_SYSTEM_SQLCIPHER=1 DLP_TEST_DEP_DIR=/путь/тестовые-зависимости \
  bash scripts/test-deb-lifecycle.sh build/dlp-lab_<версия>~deb12u1_amd64.deb /путь/python3-yaml.deb
```

Каталог тестовых зависимостей содержит PyCryptodome, но не SQLCipher;
скрипт работает в одноразовом chroot и проверяет загрузку приватной
библиотеки, чтение синтетической зашифрованной базы и удаление пакета.
Это не проверка GUI или systemd на чистой виртуальной машине.

Карта исходников: `native/` — файловый перехват; `src/dlp/` — анализ,
адаптеры, сервер; `src/dlp/ml_assets/` — модель; `tests/` — тесты;
`packaging/` и `debian/` — пакет и службы; `docker/` — серверный контейнер;
`data/ml/` — наборы и отчёты ML. Опыты — в `docs/research/`, журнал решений
и проверок — в `docs/PROJECT_CONTEXT.md`.

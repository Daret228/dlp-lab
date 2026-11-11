# Установка и обновление

Основной путь: **сервер Docker → профиль устройства → DEB → dlp-setup**.
Разделы идут в порядке первой установки; для работающего стенда — сразу
к разделу «Обновление».

## 1. Сервер

Docker нужен **только серверу**. На рабочей машине агент ставится DEB-пакетом.
Нужны Linux, Docker Engine, Compose v2, Git и HTTPS-сертификат для адреса сервера.

```bash
git clone https://github.com/Daret228/dlp-lab.git
cd dlp-lab
sudo docker version && sudo docker compose version
mkdir -p build/docker-tls
```

Сертификат (SAN должен содержать адрес сервера) положите в
`build/docker-tls/server.crt`, ключ — в `server.key`. Для лабораторного
самоподписанного сертификата см. [ADMIN](ADMIN.md#лабораторный-сертификат).

Права для контейнера UID/GID 10001:

```bash
sudo chown root:10001 build/docker-tls build/docker-tls/server.key build/docker-tls/server.crt
sudo chmod 750 build/docker-tls && sudo chmod 640 build/docker-tls/server.key && sudo chmod 644 build/docker-tls/server.crt
```

Создайте `.env` в корне (замените IP на адрес этого сервера; без `.env`
сервер слушает только 127.0.0.1):

```text
DLP_BIND_ADDRESS=192.168.17.131
DLP_HTTPS_PORT=8876
```

```bash
sudo docker compose config --quiet
sudo docker compose up -d --build
sudo docker compose ps
sudo docker compose exec central python3 /app/entrypoint.py admin-token
```

Откройте `https://АДРЕС_СЕРВЕРА:8876/`, войдите с показанным токеном.
Проверка сертификата с административной машины:

```bash
curl --cacert /путь/central-ca.crt https://АДРЕС_СЕРВЕРА:8876/ -o /dev/null
```

Состояние хранится в Docker-томе `central-data`. Не удаляйте его через
`down -v`: там база и регистрации. Healthcheck подтверждает доступность
сервера, но не доставку событий от агентов.

## 2. Профиль устройства

Для каждой машины — отдельная регистрация (замените адрес и имя):

```bash
sudo docker compose exec central python3 /app/entrypoint.py add-agent --name new-device --server https://АДРЕС_СЕРВЕРА:8876 --out /var/lib/dlp-central/new-device.json
mkdir -p -m 700 build/registration
sudo docker compose cp central:/var/lib/dlp-central/new-device.json build/registration/central-agent.json
sudo chown "$(id -u):$(id -g)" build/registration/central-agent.json && chmod 600 build/registration/central-agent.json
```

Объедините её с публичным CA в один профиль:

```bash
python3 scripts/build-connection.py --registration build/registration/central-agent.json --ca build/central-ca.crt --output build/registration/connection.json
```

Профиль (0600) содержит только регистрацию и CA; токен администратора туда
не входит. Передайте `connection.json` конкретной машине доверенным способом.
Один профиль — одно устройство.

## 3. Агент

Telegram установите заранее. Для Debian 13 amd64:

```bash
sudo apt install ./dlp-lab_*_amd64.deb
sudo dlp-setup connection.json
```

`dlp-setup` выбирает пользователя рабочего стола, находит Telegram и
дополнительно Signal, включает файловый контроль, сеансовый компонент,
отправщик и управление с сервера. Неоднозначный выбор — `--user ИМЯ`,
нестандартный Telegram — `--telegram /путь`, проверка без изменений — `--check`.

Debian 12 amd64 — то же самое с пакетом `dlp-lab_*~deb12u1_amd64.deb`;
SQLCipher 4 уже внутри, второй DEB не нужен, системная библиотека не
заменяется. Установка не автономная: остальные зависимости apt берёт из
репозиториев Debian. [Сборка пакетов](DEVELOPMENT.md#сборка-пакета).

**Автоматический postinst:** профиль можно заранее положить в
`/etc/dlp-lab/connection.json` (root, 0600) — при установке пакет сам
вызовет настройку. Нужны systemd, однозначный пользователь и установленный
Telegram; в образе/chroot настройка откладывается. Без профиля пакет не
угадывает адрес сервера — используйте обычный `dlp-setup`.

Уже настроенная машина обновляется через apt: подключение и политика
сохраняются, компоненты перезапускаются. `sudo dlp-setup` без профиля
повторно включает настроенные службы. При ошибке исправьте причину и
повторите команду — очередь и конфигурация не удаляются.

## 4. Проверка

```bash
sudo dlp-agent doctor
systemctl is-active dlp-lab-files.service dlp-lab-session.service dlp-lab-forwarder.service dlp-lab-admin-control.service
sudo journalctl -u dlp-lab-files.service -n 20 --no-pager
```

Ожидаются `active` и событие `monitor_started`. `doctor` не подтверждает
доставку: прикрепите в тестовом чате обычный и чувствительный файлы и
проверьте разрешение/блокировку и новое событие устройства в панели
через 15–30 секунд. Серия открытий даёт одну строку «Операция с файлом»
([семантика](SERVER.md#итоги-файловых-операций)).

## Обновление

Порядок: **сначала сервер, затем агенты** — старый сервер не принимает
новые поля событий.

Действующий стенд (мигрированный Compose в `/etc/dlp-lab/docker/compose.json`,
проект `dlp-central-migrated`): из корня исходников подготовленной версии

```bash
sudo python3 scripts/update-managed-agent.py
```

Скрипт согласованно обновляет оба образа, проверяет сервер, затем ставит
локальный DEB. Обычный `docker compose restart` образ не обновляет.
Затем обновите пакеты агентов обычным apt (Debian 12 — с сохранением
conffile):

```bash
sudo apt -o Dpkg::Options::="--force-confold" install ./dlp-lab_*~deb12u1_amd64.deb
sudo dlp-agent doctor
```

Новый сервер: перед обновлением сделайте резервную копию и пересоберите
образ (`up -d --build`); `restart` код не меняет.

```bash
backup_dir="build/central-backup-$(date +%Y%m%d-%H%M%S)" && mkdir -m 700 "$backup_dir"
sudo docker compose stop central
sudo docker compose cp central:/var/lib/dlp-central "$backup_dir/"
sudo docker compose up -d --build && sudo docker compose ps
```

Копия содержит секреты — не публикуйте её.

## Проверка перед демонстрацией

1. Панель: свежая связь нужных устройств.
2. На агенте `sudo dlp-agent doctor`; из панели — диагностика.
3. Тестовый чат: обычный и чувствительный файлы — разрешение/блокировка
   и события соответствующих машин.
4. Покажите группировку открытий и различие решения (BLOCK) и применения
   запрета (DENY).
5. Откройте поддерживаемое поле ввода с вымышленными чувствительными
   данными, не отправляя: состояние поля, предупреждение, событие.
   [Условия текстового контроля](ADMIN.md#текстовый-контроль).
6. Из панели запросите перезапуск текстового компонента, покажите результат.

Проверки локальных баз — отдельные исследовательские инструменты из
`docs/research/`; автоматически службами не запускаются. Используйте
вымышленные данные. BLOCK текста не означает запрет отправки.

# Сервер в Docker

Docker нужен **только серверу**. На рабочих машинах агент устанавливается
DEB-пакетом. Серверу без локального агента DEB не требуется.

## Текущий стенд Романа

Сервер уже установлен. Не повторяйте миграцию и не запускайте рядом новый
сервер командой `docker compose up` из репозитория.

| Что | Значение |
| --- | --- |
| Панель на сервере | http://127.0.0.1:8766/ |
| Адрес для агентов | https://192.168.17.131:8767 |
| Управление | Compose-проект `dlp-central-migrated`, сервисы `local` и `https` |
| Данные | `/var/lib/dlp-central` |
| Конфигурация | `/etc/dlp-lab/docker/compose.json` |

Проверка и получение существующего токена администратора:

```bash
sudo docker compose -p dlp-central-migrated -f /etc/dlp-lab/docker/compose.json ps
sudo docker compose -p dlp-central-migrated -f /etc/dlp-lab/docker/compose.json logs --tail 30
sudo dlp-admin-token
```

Регистрация **нового** устройства (для уже подключённого не повторять):

```bash
sudo docker compose -p dlp-central-migrated -f /etc/dlp-lab/docker/compose.json exec local python3 /app/entrypoint.py add-agent --name new-device --server https://192.168.17.131:8767 --out /var/lib/dlp-central/new-device.json
mkdir -p -m 700 "$HOME/dlp-provision"
sudo install -o "$(id -u)" -g "$(id -g)" -m 600 /var/lib/dlp-central/new-device.json "$HOME/dlp-provision/central-agent.json"
sudo install -o "$(id -u)" -g "$(id -g)" -m 644 /etc/dlp-lab/tls/ca.crt "$HOME/dlp-provision/central-ca.crt"
```

Соберите единый профиль из корня репозитория:

```bash
python3 scripts/build-connection.py --registration "$HOME/dlp-provision/central-agent.json" --ca "$HOME/dlp-provision/central-ca.crt" --output "$HOME/dlp-provision/connection.json"
```

Используйте уникальное имя, выходной файл и каталог подготовки для каждого
устройства. Передайте только `connection.json` конкретной машине по SSH/SCP
или другим доверенным способом. Токен администратора агенту не нужен.
Продолжайте с [установки пакета](OPERATIONS.md#3-установить-пакет-и-подключить-машину).

[Резервная копия и обновление текущего сервера](MAINTENANCE.md#сервер-текущего-стенда).
Старые центральные systemd-службы остаются выключенными; агентские службы работают.

## Новый сервер с нуля

Это отдельная установка с новой базой и регистрациями. Нужны Linux, Docker Engine,
Compose v2, Git и HTTPS-сертификат. Команды рассчитаны на обычный rootful Docker.

```bash
git clone https://github.com/Daret228/dlp-lab.git
cd dlp-lab
sudo docker version
sudo docker compose version
mkdir -p build/docker-tls
```

Администратор заранее получает сертификат для DNS-имени/IP сервера. Поместите
его в `build/docker-tls/server.crt`, приватный ключ — в `server.key`. Сертификат
должен содержать используемый адрес в SAN. Публичный CA сохраните для агентов.
Для лабораторного выпуска сертификата см.
[подготовку лабораторного сертификата](MAINTENANCE.md#лабораторный-сертификат).

Права для контейнера UID/GID 10001:

```bash
sudo chown root:10001 build/docker-tls build/docker-tls/server.key build/docker-tls/server.crt
sudo chmod 750 build/docker-tls
sudo chmod 640 build/docker-tls/server.key
sudo chmod 644 build/docker-tls/server.crt
```

Создайте в корне репозитория `.env`. Замените IP адресом этого сервера:

```text
DLP_BIND_ADDRESS=192.168.17.131
DLP_HTTPS_PORT=8876
```

Порт должен быть доступен рабочим машинам. По умолчанию без `.env` сервер
публикуется только на 127.0.0.1:8876.

```bash
sudo docker compose config --quiet
sudo docker compose up -d --build
sudo docker compose ps
sudo docker compose exec central python3 /app/entrypoint.py admin-token
```

Откройте `https://АДРЕС_СЕРВЕРА:8876/`, используйте показанный токен. Установите
доверие к CA на административном компьютере. Проверьте сертификат, подставив
реальные путь и адрес:

```bash
curl --cacert /путь/central-ca.crt https://АДРЕС_СЕРВЕРА:8876/ -o /dev/null
```

Регистрация устройства на **новом** сервере (замените адрес и имя):

```bash
sudo docker compose exec central python3 /app/entrypoint.py add-agent --name new-device --server https://АДРЕС_СЕРВЕРА:8876 --out /var/lib/dlp-central/new-device.json
mkdir -p -m 700 build/registration
sudo docker compose cp central:/var/lib/dlp-central/new-device.json build/registration/central-agent.json
sudo chown "$(id -u):$(id -g)" build/registration/central-agent.json
chmod 600 build/registration/central-agent.json
```

Соберите профиль (в примере CA находится в `build/central-ca.crt`):

```bash
python3 scripts/build-connection.py --registration build/registration/central-agent.json --ca build/central-ca.crt --output build/registration/connection.json
```

Передайте клиенту только `connection.json` и подходящий DEB, затем выполните
[подключение](OPERATIONS.md#3-установить-пакет-и-подключить-машину).
Проверка завершена после появления нового события устройства в панели.

## Хранение и обслуживание

Новая установка хранит состояние в Docker-томе `central-data`; текущий
перенесённый стенд использует `/var/lib/dlp-central`. Не удаляйте том через
`down -v`: в нём база и регистрации. Healthcheck подтверждает доступность
сервера, но не доставку событий от агента.

Для новой установки перед обновлением остановите сервер и скопируйте состояние
в новый приватный каталог:

```bash
backup_dir="build/central-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -m 700 "$backup_dir"
sudo docker compose stop central
sudo docker compose cp central:/var/lib/dlp-central "$backup_dir/"
sudo docker compose up -d --build
sudo docker compose ps
```

Не публикуйте резервную копию: она содержит секреты. Обновление исходников
выполняйте до пересборки после проверки выбранной версии. Перезапуск обычной
командой `restart` не обновляет Docker-образ. Для текущего стенда нужны команды
с `-p` и `-f` из [обслуживания](MAINTENANCE.md), а не этот блок.

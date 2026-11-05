# Центральный сервер в Docker Compose

Docker-вариант предназначен только для центрального сервера. Агенты остаются
DEB-службами на рабочих машинах. Нужны Docker Engine, Compose v2 и openssl.
Образ собирается локально, из разрешённого списка исходников; профили,
экспорты, токены и содержимое build/ в образ не попадают.

## Автоматическая проверка Docker

Из корня проекта выполните:

```bash
sudo python3 scripts/test-docker.py
```

Сценарий собирает образ и создаёт отдельный временный Compose-проект на случайном
локальном порту. Проверяет healthcheck, HTTPS, вход, регистрацию, приём события
и сохранение данных после перезапуска. Токены не печатает. При завершении удаляет
только свои тестовые контейнеры и том; образ остаётся. Рабочий сервер не переносит.
Успех обозначается строкой PASS. Для постоянного сервера используйте шаги ниже.

## Новый отдельный сервер

Команды выполняются из корня проекта. Этот вариант создаёт новую базу и новый
токен. Он не переносит автоматически регистрацию уже работающих агентов.
По умолчанию используется https://127.0.0.1:8876, чтобы не занимать порт8766
текущего systemd-сервера. Самоподписанный сертификат ниже — для локальной пробы.

```bash
mkdir -p build/docker-tls
chmod 700 build/docker-tls
openssl req -x509 -newkey rsa:3072 -nodes -days 365 \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -keyout build/docker-tls/server.key -out build/docker-tls/server.crt
sudo chown -R root:10001 build/docker-tls
sudo chmod 750 build/docker-tls
sudo chmod 640 build/docker-tls/server.key
sudo chmod 644 build/docker-tls/server.crt
sudo docker compose up -d --build
sudo docker compose ps
sudo docker compose exec central python3 /app/entrypoint.py admin-token
```

Последняя команда показывает токен для входа в новую панель. Контейнер работает
от UID/GID10001 без Linux capabilities, с файловой системой образа только для
чтения. Приватный ключ читается через отдельное монтирование только для чтения.
Не используйте UID10001 для обычного пользователя этой машины. При rootless
Docker сопоставление UID другое: права каталога сертификатов нужно подготовить
для его user namespace отдельно; команды выше рассчитаны на обычный Docker Engine.

Для доступа из сети установите сертификат сервера с SAN, соответствующим его
DNS-имени/IP, и передайте публичный CA агентам. Вместо локального сертификата
поместите выданные server.crt/server.key в тот же каталог с теми же правами.
В корне проекта создайте .env (не коммитится):

```text
DLP_BIND_ADDRESS=192.168.17.131
DLP_HTTPS_PORT=8876
```

Выполните `sudo docker compose up -d`. Подключайте агенты по HTTPS, доверяя
этому CA. Не отключайте проверку сертификата на агентах.

## Регистрация агента и управление

```bash
sudo docker compose exec central python3 /app/entrypoint.py add-agent \
  --name test-debian --server https://192.168.17.131:8876 \
  --out /var/lib/dlp-central/test-debian.json
mkdir -m 700 -p build/docker-registration
sudo docker compose cp central:/var/lib/dlp-central/test-debian.json build/docker-registration/agent.json
sudo chmod 600 build/docker-registration/agent.json
sudo docker compose logs --tail 30 central
sudo docker compose restart central
```

Файл регистрации содержит индивидуальный секрет: передайте его только нужному
агенту и установите как /etc/dlp-lab/central-agent.json по OPERATIONS.md.
Для отзыва регистрации используйте `revoke-agent --id UUID` вместо `add-agent`.
Произвольное выполнение команд на рабочих машинах не добавляется.

Том central-data содержит SQLite, токен и регистрации. `docker compose down`
сохраняет том; **не используйте `down -v` для рабочего сервера**.
Healthcheck проверяет только доступность HTTPS-страницы внутри контейнера,
а не доставку событий. Внутренний healthcheck не проверяет доверие сертификату;
агенты и проверка ниже проверяют его штатно.

## Проверка

```bash
sudo docker compose config --quiet
sudo docker compose ps
curl --cacert build/docker-tls/server.crt https://127.0.0.1:8876/ -o /dev/null
```

Для сертификата, выданного CA, передайте curl файл CA. После регистрации
тестового агента выполните файловый опыт: public разрешён, secret заблокирован;
убедитесь, что новое событие именно этого устройства появилось в панели.
Перезапустите контейнер и проверьте, что устройство, событие и токен сохранились.

В репозитории есть тест entrypoint с настоящим HTTPS, проверкой401, регистрацией,
доставкой события и повторным запуском на той же базе. Это не заменяет проверку
сборки образа и томов в Docker Engine.

## Обновление и резервная копия

Перед обновлением остановите контейнер и сохраните согласованную копию тома:

```bash
sudo docker compose stop central
mkdir -m 700 -p build/docker-backup
sudo docker compose cp central:/var/lib/dlp-central build/docker-backup/
sudo docker compose up -d --build
```

Копия содержит секреты, храните её с ограниченным доступом. Для переноса
существующего systemd-сервера сначала остановите оба его listener-а, сделайте
согласованную копию /var/lib/dlp-central, восстановите её в том с UID/GID10001,
правами каталога0700 и приватных файлов0600, настройте прежний адрес и CA.
Не запускайте независимые копии базы как один сервер: их регистрации и история
начнут расходиться. Такая миграция текущего стенда пока не выполнялась.

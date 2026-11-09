# Обслуживание

Установка: [агент](OPERATIONS.md), [сервер](DOCKER.md). Команды ниже для
администратора; остановка файловой службы кратковременно прерывает защиту.

## Правила агента

Основной способ — раздел **«Политики»** центральной панели:
выберите устройство, загрузите YAML, затем «Сохранить и применить».
«Сохранить» без применения меняет только назначение на сервере.
[Пошаговое управление и восстановление](ADMIN_CONTROL.md#политики-с-сервера-0226).
Ниже оставлен ручной способ для обслуживания администратором.

Рабочая политика — `/etc/dlp-lab/system/policy.yaml`. Сначала проверьте копию:

```bash
install -m 600 /etc/dlp-lab/system/policy.yaml "$HOME/dlp-policy-candidate.yaml"
nano "$HOME/dlp-policy-candidate.yaml"
sudo dlp-agent --policy "$HOME/dlp-policy-candidate.yaml" analyze --text 'Обычная встреча'
sudo dlp-agent --policy "$HOME/dlp-policy-candidate.yaml" analyze --text 'коммерческая тайна'
```

После проверки ожидаемых решений:

```bash
sudo cp -a /etc/dlp-lab/system/policy.yaml /etc/dlp-lab/system/policy.yaml.previous
sudo install -o root -g root -m 644 "$HOME/dlp-policy-candidate.yaml" /etc/dlp-lab/system/policy.yaml
sudo systemctl restart dlp-lab-files.service dlp-lab-session.service
sudo journalctl -u dlp-lab-files.service -n 20 --no-pager
```

Копия `.previous` хранит только предыдущее состояние. Для отката скопируйте её
обратно в `policy.yaml` и перезапустите файловую и сеансовую службы. Проверьте прикрепление.
Настройка процессов и каталогов: `sudo dlp-lab-configure --wizard`.

## Проверка применения с панели

Для первого опыта используйте копию **действующей** политики нужного устройства,
а не разработческий config/policy.yaml: так не изменятся его правила и ML-настройки.
На проверяемом устройстве:

```bash
sudo install -o "$(id -un)" -g "$(id -gn)" -m 600 \
  /etc/dlp-lab/system/policy.yaml "$HOME/dlp-policy-check.yaml"
```

Загрузите эту копию в панели для того же устройства, нажмите «Сохранить и применить».
После завершения задания выполните на устройстве:

```bash
stat -c '%U:%G %a' /etc/dlp-lab/system/policy.yaml
sha256sum /etc/dlp-lab/system/policy.yaml
systemctl is-active dlp-lab-files dlp-lab-session dlp-lab-admin-control dlp-lab-forwarder
sudo journalctl -u dlp-lab-files.service --since '5 minutes ago' -o cat --no-pager
sudo journalctl -u dlp-lab-admin-control.service --since '5 minutes ago' -o cat --no-pager
```

Ожидаются root:root0644, четыре active, новое событие policy_loaded с SHA256
текущего файла и завершённое install_policy. Сопоставляйте дату с текущим заданием,
а не с более ранним перезапуском. Проверьте разрешённое и запрещённое тестовые
вложения. Для текста отдельно проверьте доступность поля и предупреждение:
policy_loaded файловой службы не подтверждает работу AT-SPI.
После проверки удалите ненужную копию dlp-policy-check.yaml из домашнего каталога.

Бейдж «Совпадает на диске» подтверждает только содержимое файла. При аварии
между заменой и перезапуском SHA256 может совпадать, хотя новый файл ещё не загружен.
Повтор прежнего ID не перезапускает службы: после диагностики создайте **новое**
задание применения или перезапуска. При обычной ошибке перезапуска брокер
восстанавливает прежнюю политику и пытается поднять обе службы; результат failed
всё равно требует проверки. При аварии процесса автоматический откат не гарантирован.

Политика — dpkg conffile. При обновлении сохраняйте изменённую версию через
`apt -o Dpkg::Options::="--force-confold" install ...`, как в OPERATIONS.md.

## Сервер текущего стенда

Согласованная резервная копия данных и конфигурации (оба контейнера временно
останавливаются; локальная защита агентов продолжает работать):

```bash
sudo bash <<'SH'
set -eu
backup_dir=$(mktemp -d /var/backups/dlp-central-docker.XXXXXXXX)
chmod 700 "$backup_dir"
dc() { docker compose -p dlp-central-migrated -f /etc/dlp-lab/docker/compose.json "$@"; }
trap 'dc start' EXIT
dc stop
cp -a /var/lib/dlp-central "$backup_dir/state"
cp -a /etc/dlp-lab "$backup_dir/config"
printf 'Резервная копия: %s\n' "$backup_dir"
SH
```

Копия содержит токены и ключи. Для восстановления остановите оба контейнера,
сохраните текущее состояние отдельно и восстановите согласованную копию данных
и конфигурации. Для базы сохраните UID/GID 10001, каталог 0700 и файлы 0600.
Затем запустите контейнеры и проверьте устройства, историю и новое событие.
Восстановление прежней базы теряет события, принятые после её копирования.

Обновление текущего сервера после резервной копии и получения проверенных исходников:

```bash
cd /home/roman/dlp-lab
sudo python3 scripts/update-managed-agent.py
```

Сценарий предназначен для действующего стенда с двумя контейнерами и Compose
в `/etc/dlp-lab/docker/compose.json`. Он обновляет оба образа согласованно,
проверяет сервер, затем устанавливает локальный DEB. Подробности и обновление
второго агента: [административное управление](ADMIN_CONTROL.md).
Для отдельного нового сервера используйте порядок из [Docker](DOCKER.md).

## Лабораторный сертификат

Только для **нового** сервера без подготовленного сертификата. Для организации
используйте сертификат её CA. Пример ниже создаёт самоподписанный сертификат
лаборатории, который нужно явно доверить агентам. Замените IP адресом нового
сервера до запуска. Не перезаписывайте сертификаты действующей установки.

Из корня репозитория:

```bash
server_ip=192.168.17.131
mkdir -p build/docker-tls
chmod 700 build/docker-tls
openssl req -x509 -newkey rsa:3072 -nodes -days 365 \
  -subj "/CN=$server_ip" -addext "subjectAltName=IP:$server_ip" \
  -keyout build/docker-tls/server.key -out build/docker-tls/server.crt
cp build/docker-tls/server.crt build/central-ca.crt
```

Продолжите настройку прав и запуск по [Docker](DOCKER.md). Агентам передавайте
только `central-ca.crt`, не `server.key`. Следите за сроком действия сертификата.

## Остановка и удаление агента

```bash
sudo systemctl disable --now dlp-lab-files.service dlp-lab-session.service dlp-lab-forwarder.service
sudo systemctl stop dlp-lab-admin-control.service
```

Возобновление настроенного агента: `sudo dlp-setup`.
Для удаления программы: `sudo apt remove dlp-lab`. Перед полным удалением настроек
через `sudo apt purge dlp-lab` сохраните нужные конфигурации и журналы. Данные
серверного Docker-развёртывания обслуживаются отдельно.

## Если не работает

- Панель не открывается: проверьте `docker compose ... ps` и `logs`, адрес и порт.
- Агент не виден: проверьте `sudo dlp-agent doctor`, журнал forwarder, CA и адрес сервера.
- `Events acknowledged: 0` само по себе не ошибка: проверьте новое тестовое событие.
- Текст не анализируется: проверьте dlp-lab-session.service и доступность AT-SPI в карточке устройства.
- `Address already in use`: сначала найдите запущенный экземпляр; не запускайте второй.
- Файл ошибочно блокируется: проверьте причину анализа и политику, не отключайте
  защиту всей системы ради одного документа.

# Linux Endpoint DLP Lab

Актуальные требования, состояние и следующие задачи:
[контекст проекта](docs/PROJECT_CONTEXT.md). Здесь зафиксировано видение научного
руководителя: локальные данные сообщений, файлы и текстовые поля; расширяемая,
свободно распространяемая система под управлением администратора.
Ниже также сохранены инструкции и результаты отдельных этапов разработки.

Исследовательский прототип для ВКР на собственном Linux-стенде: файловый контроль
Telegram через fanotify, наблюдение одного текстового поля AT-SPI, анализ JSON-экспорта
и экспериментальное чтение локального черновика из копии tdata закрытого Telegram.
Последнее проверено на одном собственном тестовом черновике с разрешённой обработкой
локального ключа. Полная история и запрет отправки текста не реализованы.
eXpress пока не исследован. Это ещё не промышленная DLP.

Прямое чтение черновика, запуск и ограничения:
[протокол 2026-10-09](docs/research/telegram_local_reader_2026-10-09.md).

## Что работает

- TextContent/FileContent → Dictionary/Regex/Context → AnalysisResult + ALLOW/WARN/BLOCK.
- YAML-политика с порогами, весами, лимитами и стратегией ошибок.
- JSONL-аудит без содержимого сообщений; ML и messenger adapters имеют интерфейсы.
- C helper для fanotify setup со сбросом привилегий и Python worker для анализа.
- Фильтр процессов Telegram, корреляция повторных open, выбранное поле AT-SPI.
- Нормализация и аудит JSON-экспорта одного чата.
- Управление модулями через пользовательский systemd и общий журнал.
- Unit/protocol tests и отдельный opt-in kernel integration test.

**Проверка среды:** Debian 13, Python 3.13, GCC; Telegram найден, eXpress UNKNOWN.
Реальные FAN_OPEN_PERM/FAN_DENY проверены через ограниченный gateway, в том числе
при выборе файлов в Telegram. Тесты протокола не заменяют kernel integration.

## Управление агентом на текущем стенде

Из `/home/roman/dlp-lab`, без sudo перед scripts/dlp:

```bash
./scripts/dlp agent status
./scripts/dlp agent start files
./scripts/dlp agent logs --follow
./scripts/dlp agent stop
```

`logs --follow` занимает терминал; Ctrl+C прекращает просмотр, монитор продолжает
работать. `stop` выполнять после выхода из просмотра либо во втором терминале.
Для текста сначала подготовить поле с маркером, затем:

```bash
./scripts/dlp agent start text --marker DLP_TEST --seconds 120
```

Разовая проверка с сохранением результата в общем журнале:

```bash
./scripts/dlp agent export --file examples/telegram-export-synthetic.json
./scripts/dlp agent logs --lines 15
```

Status показывает только управляемые процессы. Готовность проверять по новым
событиям monitor_started/text_monitor_started. Текст наблюдается без send veto;
экспорт проверяется разово. Автозапуска нет, повторный start работающего модуля
отклоняется. Файловый start использует существующий фиксированный sudo gateway.
Права/хранение/ротация журнала определяются journald хоста; это не защищённый аудит.
Прямые CLI-команды ниже выводят результат только в терминал.
Полная последовательность: [демонстрация для ВКР](docs/demo.md).

## Установка и автономный запуск

На обычном Linux с python3-venv/pip и GCC:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m dlp.cli --policy config/policy.yaml analyze --text 'коммерческая тайна'
.venv/bin/python -m dlp.cli analyze --file examples/public.txt
make test PYTHON=.venv/bin/python
make build
```

В текущем workspace PyYAML уже установлен локально в `.deps`; работают:

```bash
make test
make demo
PYTHONPATH=src:.deps python3 -m dlp.cli analyze --file examples/secret.txt
```

Результат JSON содержит decision. Код выхода 0 означает завершённый анализ,
в том числе BLOCK; 2 — ошибку конфигурации или неполный анализ. Не трактовать
exit 0 как ALLOW. Распознаются только UTF-8 plain text; ошибки/превышение лимитов
по умолчанию BLOCK с complete=false. WARN в PoC разрешает открытие и пишет аудит.

## fanotify: ручной эксперимент на тестовом host

Нужен CAP_SYS_ADMIN (обычно запуск helper через sudo), поддержка permission events
ядром/файловой системой и доступ worker к файлам. Не запускать Python под root.
Не устанавливать setuid/capabilities на helper. Он наблюдает только непосредственных
детей отдельного каталога и не модифицирует файлы мессенджеров.

Ниже низкоуровневый опыт с отдельной сборкой helper, не обычный запуск агента.
Не запускать одновременно с agent start files. Пример cat работает в режиме all;
в текущем messengers cat пропускается. Для повседневного опыта использовать
установленный gateway и [сценарий демонстрации](docs/demo.md).
Сначала загрузить/проверить policy командой analyze. Затем, из корня проекта:

```bash
make build
mkdir -p build/watch
chmod 700 build/watch
cp examples/public.txt examples/secret.txt build/watch/
umask 077
sudo ./build/fanotify-launcher "$PWD/build/watch" "$(id -u)" "$(id -g)" \
  /usr/bin/env "PYTHONPATH=$PWD/src:$PWD/.deps" \
  /usr/bin/python3 -m dlp.cli --policy "$PWD/config/policy.yaml" monitor \
  > build/events.jsonl
```

В другой консоли того же пользователя:

```bash
cat build/watch/public.txt   # ожидается успех
cat build/watch/secret.txt   # ожидается Operation not permitted
```

Остановить Ctrl+C. После остановки защита каталога прекращается. Для установки
через venv заменить Python в команде на абсолютный путь к `.venv/bin/python`.
Лог обязательно держать за пределами watch. Метки не рекурсивны.

Полный автоматический kernel test на собственном стенде:

```bash
sudo env DLP_RUN_PRIVILEGED=1 DLP_TEST_UID="$(id -u)" DLP_TEST_GID="$(id -g)" \
  PYTHONPATH="$PWD/src:$PWD/.deps" /usr/bin/python3 -m unittest discover -s tests -p test_kernel.py -v
```

Harness запускается root исключительно для создания тестового каталога, запуска
helper и проверки его сброса привилегий. Проверяются ALLOW, WARN→ALLOW, DENY,
аудит и освобождение после завершения worker. Тест пропускается без явного флага.
Обычный `make test` не запрашивает sudo.

## Структура и ограничения

```text
src/dlp/        модели, контракты, анализ, policy, CLI, аудит, fanotify worker
native/         минимальный привилегированный setup
config/         YAML-политики
examples/       синтетические файлы
 tests/         unit/protocol и opt-in kernel test
 docs/          архитектура, модель угроз, исследование среды и клиентов
```

Событие open журналируется как file_access_attempt с send_confirmed=false.
Связь с реальной отправкой не доказана. Process filter реализован, текущий режим
— messengers: Telegram включён, eXpress отключён. Нет кеша решений, блокировки буфера обмена, TLS MITM,
перехвата клавиатуры, расшифровки профилей или чтения чужих аккаунтов.
Смерть worker приводит к fail-open; запись лога может задержать следующие события;
SIGALRM не заменяет внешний watchdog для зависшего kernel IO.

См. [архитектуру](docs/architecture.md), [модель угроз](docs/threat_model.md),
[результаты исследования среды](docs/research/environment.md).
Следующие этапы: оценка качества/задержек, расширение покрытия, тестовая среда
eXpress и защищённое администраторское управление. Границы каждого модуля
и проверенные результаты приведены в контексте проекта.

## Ограниченный sudo для дальнейшей работы

Подготовлена [одноразовая установка ограниченного доступа](docs/privileged-access.md).
Она разрешает пользователю roman только фиксированный fanotify-gateway без
аргументов. После установки `make privileged-test` проверяет реальный механизм
без запуска тестового Python-кода с root-правами.

## Проверка Telegram (этап 4)

Добавлены определение процессов и фильтр. Текущая конфигурация использует режим
`messengers`: обычный `cat` разрешён, Telegram анализируется. Команды из корня проекта:

```bash
PYTHONPATH=src:.deps python3 -m dlp.cli processes
PYTHONPATH=src:.deps python3 -m dlp.cli process-mode messengers
sudo -n /usr/local/libexec/dlp-lab/fanotify-gateway
```

В тестовом чате вручную выбрать файлы `/var/lib/dlp-lab/watch/dlp-public-demo.txt`
и `/var/lib/dlp-lab/watch/dlp-secret-demo.txt` через скрепку → Файл. Отправка не нужна.
После опыта остановить monitor Ctrl+C. Журнал должен содержать messenger=telegram
и enforcement=DENY для секретного файла; итог GUI фиксируется отдельно.
Возврат к исходному опыту с `cat`: `process-mode all` и перезапуск monitor.
`make privileged-test` теперь проверяет поведение cat согласно активному режиму.

Результат ручной проверки 2026-09-24: реальный Telegram получил DENY на четыре
попытки открытия секретного тестового файла и ALLOW на четыре открытия обычного.
Пользователь подтвердил успешное поведение в GUI. Это подтверждает контроль
доступа при выборе вложения в тестовом каталоге; отправка сообщений не проверялась.
Подробности: [протокол эксперимента](docs/research/telegram_process.md).

## Проверка текста в поле Telegram (эксперимент)

В проверенной сборке доступ к полю появился после полного выхода из Telegram
и запуска из обычного терминала:

```bash
QT_LINUX_ACCESSIBILITY_ALWAYS_ON=1 /usr/bin/telegram-desktop
```

Открыть собственный тестовый чат и ввести `DLP_TEST коммерческая тайна`, не отправляя.
Затем из корня проекта запустить без sudo:

```bash
PYTHONPATH=src:.deps python3 -m dlp.cli text-monitor --marker DLP_TEST --seconds 120
```

Агент привяжется к найденному полю и будет проверять изменения 120 секунд.
После старта маркер можно удалить и вводить обычный текст, email или секретную фразу.
Результаты — в терминале; WARN/BLOCK дополнительно вызывают desktop notification,
если notify-send и служба уведомлений доступны. `--no-notify` отключает уведомления.
Ctrl+C останавливает наблюдение. Root не требуется.

**Отправка текста не блокируется.** BLOCK в результате — решение политики,
`enforcement=observe_only` означает только наблюдение/предупреждение. Не отправляйте
реальные секреты, рассчитывая на veto. Проверка реального тестового черновика
успешна, но контроль всех полей/окон/режимов Telegram ещё не подтверждён.

## Исследование локального хранилища Telegram

```bash
python3 scripts/inspect-telegram-storage.py
```

Без root собирает агрегированные файловые метаданные собственного tdata и читает
8-байтные заголовки только settingss/maps/configs. Сообщения, ключи и кэш не читает.
Подтверждены собственные TDF-контейнеры; прямой reader переписки не реализован.
Штатный JSON-экспорт поддерживается отдельно как источник исторического аудита.
См. [результаты исследования](docs/research/telegram_storage.md).

## Проверка JSON-экспорта одного тестового чата

Демонстрация на искусственном примере, без Telegram и без root:

```bash
PYTHONPATH=src:.deps python3 -m dlp.cli analyze-export --file examples/telegram-export-synthetic.json
```

Ожидаются ALLOW, WARN, BLOCK для трёх текстов; отдельно учитываются пропущенные
служебная запись и вложение без подписи. Последняя строка — итог проверки.
BLOCK здесь означает обнаружение по правилам, отправка не блокируется.

Для своего тестового чата: Telegram → меню ⋮ → «Экспорт истории чата» → JSON,
медиа отключить. Сохранить в `private-exports/` (каталог исключён из Git), затем
передать точный путь к `result.json` через `--file`. Не экспортировать весь аккаунт.
Анализируются только тексты/подписи; содержимое вложений и другие поля не проверяются.
В журнал не выводятся сообщения и идентификаторы участников.
Проверены два реальных тестовых экспорта (2026-10-06). Во втором четыре текста
дали ALLOW, WARN, BLOCK, BLOCK, включая подпись к вложению; ошибок нет.
Секретная фраза с жирным выделением пока проверена только на синтетике.
См. [схему, ограничения и протокол](docs/research/telegram_export.md).

### Локальное хранилище через управление агентом

При полностью закрытом собственном тестовом Telegram без локального код-пароля:

```sh
scripts/dlp agent local --profile-closed --no-passcode
scripts/dlp agent logs --lines 30
```

Это разовая проверка сохранённого черновика с маркером `DLP_STORAGE_TEST`.
Дополнительный `--expected-path /absolute/path/DLP_STORAGE_ATTACHMENT_TEST.txt`
проверяет локальные сведения о тестовом файле. WARN/BLOCK вызывает предупреждение;
результат и статус доставки попадают в общий журнал. Отправка не блокируется.
Проверка уведомления без чтения профиля: `scripts/dlp agent notification-test`.
Сценарий и ограничения: [docs/demo.md](docs/demo.md).

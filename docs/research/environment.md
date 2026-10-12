# Исследование среды — 2026-09-23

Исходное состояние `/home/roman/dlp-lab`: только `installers/telegram-local/`
с двумя .deb и `td-setup-linux-x64-7.2.8.tar.xz`. Исходников, тестов и инструкций
AGENTS.md в проекте не было. `.git` — пустой read-only каталог, полноценный Git
репозиторий в данном представлении отсутствует. Установщики не изменялись.

## Наблюдения

| Параметр | Проверенный результат |
|---|---|
| ОС | /etc/os-release: Debian GNU/Linux 13.7 trixie |
| Ядро | uname: 6.12.107+deb13-amd64, x86_64 |
| Python | системный 3.13.5; pip, ensurepip и PyYAML изначально отсутствовали |
| C | GCC 14.2.0, заголовок sys/fanotify.h доступен |
| Прочее | cargo, go, pytest, rg не найдены в PATH |
| Telegram | /usr/bin/telegram-desktop → /opt/telegram-desktop/Telegram |
| Пакет Telegram | telegram-desktop-local 0+local.20260911142732 |
| Версия приложения | UNKNOWN: имя архива 7.2.8 не доказывает версию установленного бинарника |
| eXpress | executable express, пакет *express*, каталог *express* в ~/.config не обнаружены; отсутствие иных способов установки не доказано |
| GUI-сессия | XDG_SESSION_TYPE=wayland; DISPLAY=:0; WAYLAND_DISPLAY=wayland-0 |
| Telegram data | собственный ~/.local/share/TelegramDesktop/tdata существует |
| AT-SPI | libatspi2.0-0t64 2.56.2-1+deb13u2 установлен; доступ к GUI не проверен |
| Процессы | ps видит только процессы песочницы; реальные PID клиентов UNKNOWN |
| Привилегии | uid=1000; CapEff=0; CapBnd=0; Seccomp=2 |

Наличие DISPLAY не подтверждает отдельную X11-сессию или доступ к ней.
ldd Telegram показывает системные библиотеки, но не позволяет установить версию
или статическую линковку GUI-фреймворка. GUI-технология установленной сборки UNKNOWN.
Данные сообщений, ключи и содержимое профиля не читались.

## Изменения для разработки

Создан каркас проекта, локальные `.deps/` с PyYAML 6.0.3 и `build/`.
Попытка системного `python3 -m venv .venv` выявила отсутствие ensurepip;
`.venv` — неполный каталог, не использовать до установки python3-venv.
PyYAML скачан через pip вспомогательного Python 3.12 в `.deps`; Python 3.13
использует его чистую Python-реализацию. Зависимость закреплена в pyproject.toml.
Системные пакеты, настройки desktop/accessibility и клиентские профили не менялись.

## Ограничение проверки fanotify

Запуск helper на пустом `build/watch` вернул EPERM. Повторная попытка вне
песочницы через `sudo -n` остановилась: `sudo: a password is required`.
Фактические permission events и FAN_DENY в этой сессии не проверены.
Имеются непривилегированные тесты протокола и opt-in kernel integration test.

## Обновление 2026-09-24

Пользователь установил ограниченный gateway и успешно выполнил kernel test.
Результат независимо повторён агентом на хосте: ALLOW/WARN/BLOCK проходят.
Обнаружен запущенный Telegram, executable `/opt/telegram-desktop/Telegram`, UID 1000;
Python bindings Atspi доступны. Ограничения прежней песочницы не означают отсутствие
процессов/возможностей на host. Подробнее: telegram_process.md.

#!/bin/sh
# Install the official Debian Signal package. Run as the desktop user.
set -eu
if [ "$(id -u)" -eq 0 ]; then
    echo 'Запустите без sudo: bash scripts/install-signal-desktop.sh' >&2
    exit 2
fi
if [ "$(dpkg --print-architecture)" != amd64 ]; then
    echo 'Этот установщик рассчитан на Debian amd64.' >&2
    exit 2
fi
for tool in curl gpg sudo; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Нужна команда $tool. Установите её пакет через apt и повторите запуск." >&2
        exit 2
    fi
done
dlp_signal_tmp=$(mktemp -d)
trap 'rm -rf "$dlp_signal_tmp"' EXIT HUP INT TERM
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    https://updates.signal.org/desktop/apt/keys.asc -o "$dlp_signal_tmp/key.asc"
gpg --batch --yes --dearmor --output "$dlp_signal_tmp/keyring.gpg" "$dlp_signal_tmp/key.asc"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    https://updates.signal.org/static/desktop/apt/signal-desktop.sources -o "$dlp_signal_tmp/signal.sources"
printf '%s\n' 'Будет добавлен официальный репозиторий Signal и установлен signal-desktop.'
sudo install -o root -g root -m 0644 "$dlp_signal_tmp/keyring.gpg" /usr/share/keyrings/signal-desktop-keyring.gpg
sudo install -o root -g root -m 0644 "$dlp_signal_tmp/signal.sources" /etc/apt/sources.list.d/signal-desktop.sources
sudo apt-get update
sudo apt-get install signal-desktop
printf '%s\n' 'Установка завершена. Запустите signal-desktop без sudo и привяжите его к телефону.'

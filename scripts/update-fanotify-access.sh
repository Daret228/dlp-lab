#!/bin/bash
# Administrative replacement of the fixed gateway; sudoers is NOT expanded.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077
if (( EUID != 0 || $# != 0 )); then
    echo 'Run with sudo, without arguments.' >&2; exit 1
fi
[[ $(id -u roman) == 1000 && $(id -g roman) == 1000 ]] || exit 1
for dir in / /usr /usr/local /usr/local/libexec /usr/local/libexec/dlp-lab; do
    [[ -d "$dir" && ! -L "$dir" && $(stat -c %u "$dir") == 0 ]] || exit 1
    mode=$(stat -c %a "$dir")
    (( (8#$mode & 0022) == 0 )) || exit 1
done
target=/usr/local/libexec/dlp-lab/fanotify-gateway
[[ -f "$target" && ! -L "$target" && $(stat -c %u "$target") == 0 ]] || exit 1
# Never silently replace an active monitor. Stop it using the panel/agent first.
if pgrep -f '^(/usr/bin/)?python3 -m dlp.cli --policy /home/roman/dlp-lab/config/policy.yaml monitor$' >/dev/null; then
    echo 'Stop the file monitor first.' >&2; exit 1
fi
/usr/sbin/visudo -c
stage=$(mktemp -d /usr/local/libexec/dlp-lab/.upgrade.XXXXXXXX)
trap 'rm -rf -- "$stage"' EXIT
install -m 0600 /home/roman/dlp-lab/native/filesystem_launcher.c "$stage/launcher.c"
/usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/cc -std=c11 -Wall -Wextra -Werror -O2 \
    -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now \
    "$stage/launcher.c" -o "$stage/fanotify-gateway"
chown root:root "$stage/fanotify-gateway"
chmod 0755 "$stage/fanotify-gateway"
# Preserve the last installed binary for an explicit manual rollback.
cp -p -- "$target" "$stage/previous"
mv -fT -- "$stage/previous" /usr/local/libexec/dlp-lab/fanotify-gateway.previous
mv -fT -- "$stage/fanotify-gateway" "$target"
printf '%s\n' 'Gateway updated. Local filesystems present at startup are covered.' \
    'Review docs/decisions/012-filesystem-scope.md. Start files from the panel.'

#!/bin/bash
# Administrative install/update only; never grant this script NOPASSWD.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077
fail() { echo "$*" >&2; exit 1; }
(( EUID == 0 )) || fail 'Run this administrative installer with sudo.'
mode=${1:-}; shift || true
[[ $mode == install || $mode == update ]] || fail 'Expected install or update.'
source_project=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
project=$source_project
account=''
telegram=''
signal=''
exclusions=()
config_dir=/etc/dlp-lab
install_dir=/usr/local/libexec/dlp-lab
target=$install_dir/fanotify-gateway
rule=/etc/sudoers.d/dlp-lab-fanotify
trusted_dir() {
    local directory=$1 permissions
    [[ -d $directory && ! -L $directory && $(stat -c %u "$directory") == 0 ]] || fail "Untrusted directory: $directory"
    permissions=$(stat -c %a "$directory")
    (( (8#$permissions & 0022) == 0 )) || fail "Writable directory: $directory"
}
trusted_file() {
    local file=$1 permissions
    [[ -f $file && ! -L $file && $(stat -c %u "$file") == 0 && $(stat -c %h "$file") == 1 ]] || fail "Untrusted file: $file"
    permissions=$(stat -c %a "$file")
    (( (8#$permissions & 0022) == 0 )) || fail "Writable file: $file"
}
for directory in / /etc /etc/sudoers.d /usr /usr/local /var /var/lib; do trusted_dir "$directory"; done
if [[ -e /usr/local/libexec || -L /usr/local/libexec ]]; then trusted_dir /usr/local/libexec; else install -d -o root -g root -m 0755 /usr/local/libexec; fi
if [[ -e $config_dir || -L $config_dir ]]; then trusted_dir "$config_dir"; fi
had_config=false
if [[ -e $config_dir/gateway.conf || -L $config_dir/gateway.conf ]]; then
    trusted_file "$config_dir/gateway.conf"
    (( $(stat -c %s "$config_dir/gateway.conf") <= 65536 )) || fail "Configuration too large."
    had_config=true
    # Deliberately parse as data; never source an administrative configuration.
    declare -A seen=()
    while IFS='=' read -r key value; do
        [[ -z $key || $key == \#* ]] && continue
        case "$key" in uid|gid|home|project|telegram|signal|exclude) : ;; *) fail "Unknown configuration key." ;; esac
        if [[ $key != exclude ]]; then
            [[ ! ${seen[$key]+exists} ]] || fail "Duplicate key: $key"
            seen[$key]=1
        fi
        case "$key" in
            uid) account=$value ;;
            gid|home) : ;; # Re-resolved from the account database below.
            project) project=$value ;;
            telegram) telegram=$value ;;
            signal) signal=$value ;;
            exclude) exclusions+=("$value") ;;
            *) fail "Unknown configuration key: $key" ;;
        esac
    done < "$config_dir/gateway.conf"
    [[ ${seen[uid]+yes} && ${seen[gid]+yes} && ${seen[home]+yes} && ${seen[project]+yes} && ${seen[telegram]+yes} ]] || fail 'Incomplete gateway configuration.'
fi
while (( $# )); do
    (( $# >= 2 )) || fail 'Options: --user ACCOUNT --project DIRECTORY --telegram EXECUTABLE [--signal EXECUTABLE]'
    case "$1" in
        --user) account=$2 ;;
        --project) project=$2 ;;
        --telegram) telegram=$2 ;;
        --signal) signal=$2 ;;
        *) fail "Unknown option: $1" ;;
    esac
    shift 2
done
project=$(realpath -e -- "$project")
[[ -d $project/src/dlp && -f $project/config/policy.yaml ]] || fail 'Invalid project directory.'
[[ -n $account ]] || account=$(stat -c %u "$project")
record=$(getent passwd "$account") || fail 'Account not found; use --user ACCOUNT.'
IFS=: read -r username unused uid gid unused home unused <<< "$record"
[[ $uid =~ ^[0-9]+$ && $gid =~ ^[0-9]+$ ]] || fail 'Invalid UID/GID.'
(( uid > 0 && gid > 0 )) || fail 'Select a non-root account with a non-root primary group.'
if [[ -z $telegram ]]; then telegram=$(command -v telegram-desktop || true); fi
[[ -n $telegram ]] || fail 'Telegram not found; use --telegram /absolute/path.'
telegram=$(realpath -e -- "$telegram")
[[ -f $telegram && -x $telegram && $(stat -c %u "$telegram") == 0 ]] || fail 'Telegram must be an executable owned by root.'
permissions=$(stat -c %a "$telegram")
(( (8#$permissions & 0002) == 0 )) || fail 'Telegram must not be world writable.'
if (( (8#$permissions & 0020) != 0 )); then [[ $(stat -c %g "$telegram") == 0 ]] || fail 'Telegram is writable by a non-root group.'; fi
valid_path() {
    local value=$1
    [[ $value == /* && $value != *$'\n'* && $value != *$'\r'* && $value != *:* && $value != *\\* && $value != *'/../'* && $value != *'/./'* && $value != *'//'* && $value != */.. && $value != */. ]] || fail "Invalid configuration path."
    [[ ${#value} -lt 4096 && ( $value == / || $value != */ ) ]] || fail 'Invalid configuration path length or trailing slash.'
    [[ ! $value =~ [[:cntrl:]] ]] || fail 'Control characters in path.'
}
for value in "$project" "$home" "$telegram"; do valid_path "$value"; done
if [[ -n $signal ]]; then
    signal=$(realpath -e -- "$signal")
    valid_path "$signal"
    [[ $signal != "$telegram" && -x $signal ]] || fail 'Signal must be a distinct executable.'
    trusted_file "$signal"
    parent=$(dirname -- "$signal")
    while :; do
        trusted_dir "$parent"
        [[ $parent == / ]] && break
        parent=$(dirname -- "$parent")
    done
fi
if [[ $had_config == false ]]; then
    exclusions=(/usr /opt /etc /bin /sbin /lib /lib64 "$home/.cache" "$home/.config" "$home/.local/share/TelegramDesktop" "$home/.local/share/fonts" "$home/.fonts")
fi
(( ${#exclusions[@]} <= 32 )) || fail 'Too many exclusions.'
for value in "${exclusions[@]}"; do valid_path "$value"; [[ $value != / ]] || fail 'Cannot exclude the filesystem root.'; done
if [[ $mode == install ]]; then
    [[ ! -e $install_dir && ! -L $install_dir && ! -e $rule && ! -L $rule && $had_config == false ]] || fail 'Already installed; use update-fanotify-access.sh.'
else
    trusted_dir "$install_dir"; trusted_file "$target"; trusted_file "$rule"
fi
# Legacy brokers do not hold the new deployment lock. Check them explicitly.
if pgrep -f '^/usr/local/libexec/dlp-lab/fanotify-gateway$' >/dev/null; then fail 'Stop the file monitor before installation/update.'; fi
/usr/sbin/visudo -c
install -d -o root -g root -m 0755 "$config_dir"
if [[ -e $config_dir/gateway.lock || -L $config_dir/gateway.lock ]]; then trusted_file "$config_dir/gateway.lock"; else install -o root -g root -m 0600 /dev/null "$config_dir/gateway.lock"; fi
exec 9<"$config_dir/gateway.lock"
flock -n 9 || fail 'Gateway is running or another installation holds the lock.'
stage=$(mktemp -d "$config_dir/.stage.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
# Build only a snapshot, never run project code as root.
install -m 0600 "$source_project/native/filesystem_launcher.c" "$stage/launcher.c"
install -m 0600 "$source_project/native/gateway_config.h" "$stage/gateway_config.h"
/usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/cc -std=c11 -Wall -Wextra -Werror -O2 \
    -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now \
    "$stage/launcher.c" -o "$stage/fanotify-gateway"
{
    printf 'uid=%s\ngid=%s\nhome=%s\nproject=%s\ntelegram=%s\n' "$uid" "$gid" "$home" "$project" "$telegram"
    if [[ -n $signal ]]; then printf 'signal=%s\n' "$signal"; fi
    for value in "${exclusions[@]}"; do printf 'exclude=%s\n' "$value"; done
} > "$stage/gateway.conf"
(( $(stat -c %s "$stage/gateway.conf") <= 65536 )) || fail 'Configuration too large.'
printf '# Fixed broker only; no caller arguments.\n#%s ALL=(root) NOPASSWD: NOSETENV: /usr/local/libexec/dlp-lab/fanotify-gateway ""\n' "$uid" > "$stage/sudoers"
/usr/sbin/visudo -cf "$stage/sudoers"
install -d -o root -g root -m 0755 "$install_dir"
if [[ $mode == update ]]; then
    for backup in "$install_dir/fanotify-gateway.previous" "$config_dir/sudoers.previous" "$config_dir/gateway.conf.previous"; do
        if [[ -e $backup || -L $backup ]]; then trusted_file "$backup"; fi
    done
    cp -p -- "$target" "$install_dir/fanotify-gateway.previous"
    cp -p -- "$rule" "$config_dir/sudoers.previous"
    if [[ $had_config == true ]]; then cp -p -- "$config_dir/gateway.conf" "$config_dir/gateway.conf.previous"; fi
fi
# No gateway can start while FD 9 holds the deployment lock. Stage each file
# on its destination filesystem for atomic rename; install sudo authorization last.
install -o root -g root -m 0755 "$stage/fanotify-gateway" "$install_dir/.fanotify-gateway.new"
install -o root -g root -m 0644 "$stage/gateway.conf" "$config_dir/.gateway.conf.new"
install -o root -g root -m 0440 "$stage/sudoers" /etc/sudoers.d/.dlp-lab-fanotify.new
mv -fT -- "$config_dir/.gateway.conf.new" "$config_dir/gateway.conf"
mv -fT -- "$install_dir/.fanotify-gateway.new" "$target"
mv -fT -- /etc/sudoers.d/.dlp-lab-fanotify.new "$rule"
if ! /usr/sbin/visudo -c; then
    if [[ $mode == update ]]; then
        install -o root -g root -m 0440 "$config_dir/sudoers.previous" "$rule"
    else
        rm -f -- "$rule"
    fi
    fail 'Sudo validation failed; new authorization rolled back.'
fi
printf 'Gateway configured for %s (UID %s), project %s.\n' "$username" "$uid" "$project"
printf '%s\n' 'Configuration: /etc/dlp-lab/gateway.conf. Monitor remains stopped.' \
    'Ensure config/processes.yaml enables the same UID and all configured messenger executables, then start files.'

#!/bin/bash
# One-time, password-authorized installation. Never add this installer to sudoers.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077
if (( EUID != 0 )); then
    echo 'Run this installer with sudo from your Linux terminal.' >&2
    exit 1
fi
if (( $# != 0 )); then
    echo 'Installer accepts no arguments.' >&2
    exit 1
fi
if [[ $(id -u roman) != 1000 || $(id -g roman) != 1000 ]]; then
    echo 'Expected roman with UID/GID 1000. Refusing installation.' >&2
    exit 1
fi
# Refuse symlinks or writable/non-root parent directories, never repair system permissions.
trusted_dir() {
    local dir=$1 mode
    [[ -d "$dir" && ! -L "$dir" && $(stat -c %u "$dir") == 0 ]] || {
        echo "Not a root-owned real directory: $dir" >&2; exit 1;
    }
    mode=$(stat -c %a "$dir")
    (( (8#$mode & 0022) == 0 )) || {
        echo "Directory is group/world writable: $dir" >&2; exit 1;
    }
}
for dir in / /usr /usr/local /usr/local/libexec /var /var/lib /etc /etc/sudoers.d; do
    trusted_dir "$dir"
done
install_dir=/usr/local/libexec/dlp-lab
state_dir=/var/lib/dlp-lab
rule=/etc/sudoers.d/dlp-lab-fanotify
for item in "$install_dir" "$state_dir" "$rule"; do
    if [[ -e "$item" || -L "$item" ]]; then
        echo "Already exists: $item. Refusing to overwrite; see docs/privileged-access.md." >&2
        exit 1
    fi
done
/usr/sbin/visudo -c
stage=$(mktemp -d /var/lib/dlp-fanotify-install.XXXXXXXX)
trap 'rm -rf -- "$stage"' EXIT
# Build from a snapshot; nothing in the workspace will execute as root at runtime.
install -m 0600 /home/roman/dlp-lab/native/fanotify_launcher.c "$stage/launcher.c"
/usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/cc -std=c11 -Wall -Wextra -Werror -O2 \
    -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now \
    -DDLP_INSTALLED_GATEWAY "$stage/launcher.c" -o "$stage/fanotify-gateway"
cat > "$stage/sudoers" <<'RULE'
# No arguments allowed. Python and project code run only after dropping to roman.
roman ALL=(root) NOPASSWD: NOSETENV: /usr/local/libexec/dlp-lab/fanotify-gateway ""
RULE
/usr/sbin/visudo -cf "$stage/sudoers"
install -d -o root -g root -m 0755 "$install_dir" "$state_dir"
install -d -o roman -g roman -m 0700 "$state_dir/watch"
install -o root -g root -m 0755 "$stage/fanotify-gateway" "$install_dir/fanotify-gateway"
# Enable authorization last; the binary and all its parent directories are protected.
install -o root -g root -m 0440 "$stage/sudoers" "$rule"
if ! /usr/sbin/visudo -c; then
    rm -f -- "$rule"
    echo 'Sudo configuration check failed; new authorization removed.' >&2
    exit 1
fi
printf '%s\n' 'Installed: limited fanotify access for roman, only /var/lib/dlp-lab/watch.'
printf '%s\n' 'Next: cd /home/roman/dlp-lab && make privileged-test'

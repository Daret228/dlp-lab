#!/bin/bash
# Opt-in LAN TLS listener sharing the existing central database.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
[[ $EUID == 0 && $# == 2 ]] || { echo 'Usage: sudo env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin bash scripts/install-central-tls.sh IPv4 TLS_DIRECTORY' >&2; exit 2; }
bind_ip=$1
input_dir=$(realpath "$2")
python3 -I - "$bind_ip" <<'PY'
import ipaddress,sys
ip=ipaddress.IPv4Address(sys.argv[1])
if ip.is_unspecified or ip.is_multicast or ip.is_loopback:
    raise SystemExit('Use the explicit LAN IPv4 address of the server')
PY
unit=/etc/systemd/system/dlp-lab-central-tls.service
tls_dir=/etc/dlp-lab/tls
[[ ! -e $unit && ! -e $tls_dir ]] || { echo 'TLS configuration already exists; refusing to overwrite' >&2; exit 2; }
[[ -f /var/lib/dlp-central/admin.json ]] || { echo 'Initialize the existing central server first' >&2; exit 2; }
for name in ca.crt server.crt server.key; do
    [[ -f "$input_dir/$name" && ! -L "$input_dir/$name" ]] || exit 2
done
openssl verify -CAfile "$input_dir/ca.crt" -purpose sslserver -verify_ip "$bind_ip" "$input_dir/server.crt"
# Check key/certificate match without printing private material.
cert_pub=$(openssl x509 -in "$input_dir/server.crt" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum)
key_pub=$(openssl pkey -in "$input_dir/server.key" -pubout -outform DER | sha256sum)
[[ "$cert_pub" == "$key_pub" ]] || { echo 'Certificate/key mismatch' >&2; exit 2; }
install -d -o root -g dlp-central -m 0750 "$tls_dir"
install -o root -g dlp-central -m 0640 "$input_dir/server.key" "$tls_dir/server.key"
install -o root -g root -m 0644 "$input_dir/server.crt" "$tls_dir/server.crt"
install -o root -g root -m 0644 "$input_dir/ca.crt" "$tls_dir/ca.crt"
cat > "$unit" <<EOF
[Unit]
Description=DLP Lab LAN HTTPS event listener
After=network-online.target dlp-lab-central.service
Wants=network-online.target
ConditionPathExists=/var/lib/dlp-central/admin.json

[Service]
Type=exec
User=dlp-central
Group=dlp-central
StateDirectory=dlp-central
StateDirectoryMode=0700
ExecStart=/usr/bin/dlp-agent central serve --state /var/lib/dlp-central --host $bind_ip --port 8767 --cert $tls_dir/server.crt --key $tls_dir/server.key
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LimitCORE=0

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$unit"
systemctl daemon-reload
systemctl enable --now dlp-lab-central-tls.service
systemctl --no-pager status dlp-lab-central-tls.service

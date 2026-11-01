#!/bin/bash
# Install the already provisioned agent identity and scoped CA trust.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
[[ $EUID == 0 && $# == 1 ]] || { echo 'Usage: sudo bash install-central-forwarder.sh INPUT_DIRECTORY' >&2; exit 2; }
input_dir=$(realpath "$1")
[[ -f "$input_dir/central-agent.json" && ! -L "$input_dir/central-agent.json" ]]
[[ -f "$input_dir/central-ca.crt" && ! -L "$input_dir/central-ca.crt" ]]
[[ ! -e /etc/dlp-lab/central-agent.json ]] || { echo 'Agent configuration already exists; refusing to overwrite' >&2; exit 2; }
# Validate JSON and HTTPS endpoint without logging credentials.
python3 -I - "$input_dir/central-agent.json" "$input_dir/central-ca.crt" <<'PY'
import json,ssl,sys
sys.path.insert(0,'/usr/lib/dlp-lab/src')
from dlp.central import endpoint
with open(sys.argv[1]) as stream:
    config=json.load(stream)
assert endpoint(config['server']).startswith('https://')
assert isinstance(config['token'],str) and len(config['token'])>=32
assert isinstance(config['agent_id'],str) and config['agent_id']
ssl.create_default_context(cafile=sys.argv[2])
PY
install -d -o root -g root -m 0755 /etc/dlp-lab /etc/systemd/system/dlp-lab-forwarder.service.d
install -o root -g root -m 0600 "$input_dir/central-agent.json" /etc/dlp-lab/central-agent.json
install -o root -g root -m 0644 "$input_dir/central-ca.crt" /etc/dlp-lab/central-ca.crt
printf '%s\n' '[Service]' 'Environment=SSL_CERT_FILE=/etc/dlp-lab/central-ca.crt' > /etc/systemd/system/dlp-lab-forwarder.service.d/tls.conf
chmod 0644 /etc/systemd/system/dlp-lab-forwarder.service.d/tls.conf
systemctl daemon-reload
systemctl enable --now dlp-lab-forwarder.service
systemctl --no-pager status dlp-lab-forwarder.service

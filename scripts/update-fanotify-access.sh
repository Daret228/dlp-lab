#!/bin/bash
set -euo pipefail
exec /bin/bash "$(dirname -- "${BASH_SOURCE[0]}")/configure-fanotify-access.sh" update "$@"

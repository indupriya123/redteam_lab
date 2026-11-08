#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
printf '%s\n' 'Installed local reconnaissance runtime. Initialize credentials with: .venv/bin/recon-engine init'
printf '%s\n' 'Nmap/LDAP/cloud/Kubernetes tooling and credentials are not installed or authorized by this script.'

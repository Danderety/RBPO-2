#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
# Execute as a normal user; sudo is used only by pacman.
sudo pacman -Syu --needed base-devel git python python-pip nodejs npm cppcheck iputils chromium
python -m venv .venv
.venv/bin/python -m pip install -r projects/python/requirements-lock.txt
npm ci --prefix projects/javascript --no-audit --no-fund
npm install --prefix .browser-tools --no-audit --no-fund playwright@1.62.1

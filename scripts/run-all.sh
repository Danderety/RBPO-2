#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
.venv/bin/python scripts/verify.py --only all
.venv/bin/python scripts/check_additions.py
RBPO_BROWSER_PATH="${RBPO_BROWSER_PATH:-/usr/bin/chromium}" node scripts/check_xss_browser.cjs
.venv/bin/python scripts/build_dataset.py

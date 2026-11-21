#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rm -rf "${ROOT_DIR}/vibebazaar-demo/workspace"
cp -R "${ROOT_DIR}/vibebazaar-demo/template_vulnerable" "${ROOT_DIR}/vibebazaar-demo/workspace"
echo "[VibeArmor] Reset VibeBazaar India workspace to vulnerable baseline."

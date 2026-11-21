#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "[VibeArmor Bootstrap] Installing Python dependencies & editable CLI..."
pip install --quiet -r "${ROOT_DIR}/requirements.txt"
pip install --quiet --no-deps -e "${ROOT_DIR}"

# Optional CPU llama-cpp-python wheel + local Qwen2.5-Coder GGUF cache
MODEL_DIR="${HOME}/.cache/vibearmor/models"
MODEL_FILE="${MODEL_DIR}/qwen2.5-coder-0.5b-instruct-q4_k_m.gguf"
if ! python3 -c "import llama_cpp" >/dev/null 2>&1; then
  echo "[VibeArmor Bootstrap] Installing CPU llama-cpp-python wheel..."
  pip install --quiet llama-cpp-python --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu || true
fi

if [ ! -f "${MODEL_FILE}" ]; then
  mkdir -p "${MODEL_DIR}"
  echo "[VibeArmor Bootstrap] Downloading local open-weight Qwen2.5-Coder GGUF..."
  curl -sL "https://huggingface.co/Qwen/Qwen2.5-Coder-0.5B-Instruct-GGUF/resolve/main/qwen2.5-coder-0.5b-instruct-q4_k_m.gguf" \
    -o "${MODEL_FILE}" || true
fi

bash "${ROOT_DIR}/scripts/reset_demo.sh"
echo "[VibeArmor Bootstrap] Ready! Run 'vibearmor studio' or 'vibearmor fix vibebazaar-demo/workspace'."

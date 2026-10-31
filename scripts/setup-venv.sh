#!/usr/bin/env bash
# Developer entry point for the same setup script embedded in the released CLI.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$root/pkg/whisper/setup-venv.sh" "$@"

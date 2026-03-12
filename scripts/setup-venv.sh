#!/usr/bin/env bash
# setup-venv.sh — Create a dedicated Python virtual environment for m3c-tools
# Installs openai-whisper and its dependencies into ~/.m3c-tools/venv/
#
# Usage: ./scripts/setup-venv.sh [--force]
#   --force   Remove existing venv and recreate from scratch
set -euo pipefail

VENV_DIR="${HOME}/.m3c-tools/venv"
MIN_PYTHON_MAJOR=3
MIN_PYTHON_MINOR=9

# --- Color output ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info()  { echo -e "${GREEN}[setup]${NC} $*"; }
warn()  { echo -e "${YELLOW}[setup]${NC} $*"; }
error() { echo -e "${RED}[setup]${NC} $*" >&2; }

# --- Parse args ---
FORCE=false
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=true ;;
        *)       error "Unknown argument: $arg"; exit 1 ;;
    esac
done

# --- Check for existing venv ---
if [ -d "$VENV_DIR" ] && [ "$FORCE" = false ]; then
    if [ -x "$VENV_DIR/bin/whisper" ]; then
        info "Virtual environment already exists at $VENV_DIR"
        info "Whisper binary: $VENV_DIR/bin/whisper"
        "$VENV_DIR/bin/whisper" --help 2>/dev/null | head -1 || true
        info "To recreate, run: $0 --force"
        exit 0
    else
        warn "Venv exists but whisper not found — reinstalling dependencies..."
    fi
fi

# --- Find Python 3 ---
PYTHON=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        version=$("$candidate" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
        major=$(echo "$version" | cut -d. -f1)
        minor=$(echo "$version" | cut -d. -f2)
        if [ "$major" -ge "$MIN_PYTHON_MAJOR" ] && [ "$minor" -ge "$MIN_PYTHON_MINOR" ]; then
            PYTHON="$candidate"
            info "Found $candidate $version"
            break
        else
            warn "$candidate $version is too old (need >=${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR})"
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    error "Python >=${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR} not found."
    error "Install via: brew install python@3.11"
    exit 1
fi

# --- Remove old venv if --force ---
if [ "$FORCE" = true ] && [ -d "$VENV_DIR" ]; then
    warn "Removing existing venv at $VENV_DIR..."
    rm -rf "$VENV_DIR"
fi

# --- Create venv ---
info "Creating virtual environment at $VENV_DIR..."
mkdir -p "$(dirname "$VENV_DIR")"
"$PYTHON" -m venv "$VENV_DIR"

# --- Upgrade pip ---
info "Upgrading pip..."
"$VENV_DIR/bin/pip" install --upgrade pip --quiet

# --- Install whisper ---
info "Installing openai-whisper (this may take a few minutes)..."
"$VENV_DIR/bin/pip" install openai-whisper --quiet

# --- Verify ---
if [ ! -x "$VENV_DIR/bin/whisper" ]; then
    error "whisper binary not found after installation!"
    error "Check: $VENV_DIR/bin/pip show openai-whisper"
    exit 1
fi

WHISPER_VERSION=$("$VENV_DIR/bin/pip" show openai-whisper 2>/dev/null | grep '^Version:' | awk '{print $2}')
PYTHON_VERSION=$("$VENV_DIR/bin/python" --version 2>&1)

info ""
info "Setup complete!"
info "  Venv:    $VENV_DIR"
info "  Python:  $PYTHON_VERSION"
info "  Whisper: $WHISPER_VERSION"
info "  Binary:  $VENV_DIR/bin/whisper"
info ""
info "m3c-tools will automatically use this whisper installation."

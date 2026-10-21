#!/usr/bin/env bash
# Add a local Ed25519 fallback signature to verified, existing CI release assets.
# No builds, uploads, tag creation, tool installation, or catalog publication.
set -euo pipefail
exec python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/skillctl_release_fallback.py" "$@"

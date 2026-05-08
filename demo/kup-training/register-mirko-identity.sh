#!/usr/bin/env bash
# register-mirko-identity.sh — back-compat wrapper around register-identity.sh.
# See register-identity.sh for the generic implementation. Use the generic
# script directly to register the reviewer or any other identity.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/register-identity.sh" \
  id:mirko@m3c \
  "$SCRIPT_DIR/artifacts/keys/mirko.pub" \
  "Mirko (KuP demo author)"

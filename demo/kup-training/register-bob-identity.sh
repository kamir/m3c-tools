#!/usr/bin/env bash
# register-bob-identity.sh: back-compat wrapper around register-identity.sh.
# See register-identity.sh for the generic implementation. Use the generic
# script directly to register the reviewer or any other identity.
# Creating the identity needs an admin session (AIMS_ADMIN_COOKIE), not the
# shared ER1_API_KEY; confirming an existing one does not.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/register-identity.sh" \
  id:bob@m3c \
  "$SCRIPT_DIR/artifacts/keys/bob.pub" \
  "Bob (KuP demo author)"

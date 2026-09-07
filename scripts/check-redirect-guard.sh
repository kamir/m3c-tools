#!/usr/bin/env bash
# check-redirect-guard.sh: refuse credential-bearing files whose http.Client
# constructions lack a CheckRedirect policy (AUDIT-0001 Befund 1.1).
#
# Background: Go's stdlib redirect policy strips Authorization/Cookie when a
# redirect crosses to a different host, but NOT custom credential headers such
# as X-API-KEY. A client without CheckRedirect therefore forwards the key to
# any host a 30x points at. The shared fix lives in pkg/httpsafe
# (NoCredentialRedirect / NoCrossHostRedirect); this guard keeps the fixed
# state from regrowing.
#
# Scope and mechanism: every non-test .go file under cmd/ and pkg/ that names
# the X-API-KEY header or calls auth.ApplyAuth is scanned; in each such file
# the number of "http.Client{" composite literals must be matched by at least
# as many "CheckRedirect" occurrences. This is a byte-level heuristic, not a
# type check. Known limits: a client assembled field by field (c := new(http.Client))
# escapes it, as does a credential attached in a different file than the client
# construction; both are absent from this tree today. The common regression, a
# quick &http.Client{Timeout: ...} next to a credential header, is caught.
#
# Usage: ./scripts/check-redirect-guard.sh   (exit 1 on any hit; runs in make ci)
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
while IFS= read -r f; do
  clients=$(grep -c 'http\.Client{' "$f" || true)
  [ "${clients:-0}" -eq 0 ] && continue
  checks=$(grep -c 'CheckRedirect' "$f" || true)
  if [ "${checks:-0}" -lt "$clients" ]; then
    echo "ERROR: $f: $clients http.Client construction(s), only $checks CheckRedirect occurrence(s)."
    echo "       A file that sends credentials must give every http.Client a redirect policy,"
    echo "       e.g. CheckRedirect: httpsafe.NoCredentialRedirect (see pkg/httpsafe)."
    fail=1
  fi
done < <(grep -rl --include='*.go' -e 'X-API-KEY' -e 'ApplyAuth(' cmd pkg | grep -v _test.go | sort)

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "redirect-guard: OK (every credential-bearing file gives its http.Client a CheckRedirect policy)"

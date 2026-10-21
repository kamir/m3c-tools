#!/usr/bin/env bash
# A command that fails must block review, regardless of its output wording.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/repo"
git -C "$TMP/repo" init -q
printf 'APP_VERSION := test\n' > "$TMP/repo/Makefile"
printf 'package example\n' > "$TMP/repo/example.go"
cat > "$TMP/bin/go" <<'GO'
#!/usr/bin/env bash
case "$1" in
  vet) [ "${CASE:-}" != vet-quiet ] ;;
  test)
    printf 'test\n' >> "$CALLS"
    case "${CASE:-}" in
      test-quiet) exit 2 ;;
      test-mixed) printf 'ok example/one\ngo: unable to execute another package\n'; exit 1 ;;
      *) printf 'ok example/pkg\n' ;;
    esac ;;
  build)
    if [ "${CASE:-}" = build-all ] && [ "$2" = './...' ]; then exit 2; fi ;;
  mod) [ "${CASE:-}" != mod-verify ] ;;
esac
GO
cat > "$TMP/govulncheck" <<'VULN'
#!/usr/bin/env bash
case "${CASE:-}" in
  scan-quiet) exit 2 ;;
  scan-format) printf 'Found a reachable advisory\n'; exit 3 ;;
  *) printf 'No vulnerabilities found.\n' ;;
esac
VULN
chmod +x "$TMP/bin/go" "$TMP/govulncheck"
for scenario in clean vet-quiet test-quiet test-mixed build-all mod-verify scan-quiet scan-format scan-missing; do
    cp "$TMP/govulncheck" "$TMP/bin/govulncheck"
    if [ "$scenario" = scan-missing ]; then rm "$TMP/bin/govulncheck"; fi
    : > "$TMP/calls"
    status=0
    (cd "$TMP/repo" && PATH="$TMP/bin:/usr/bin:/bin" CASE="$scenario" CALLS="$TMP/calls" bash "$ROOT/scripts/code-review.sh") > "$TMP/output" 2>&1 || status=$?
    if { [ "$scenario" = clean ] && [ "$status" -ne 0 ]; } || { [ "$scenario" != clean ] && [ "$status" -eq 0 ]; }; then
        cat "$TMP/output" >&2
        echo "FAIL: $scenario returned $status" >&2
        exit 1
    fi
    [ "$(wc -l < "$TMP/calls" | tr -d ' ')" = 1 ] || { echo "FAIL: tests reran in $scenario" >&2; exit 1; }
    echo "ok: $scenario"
done

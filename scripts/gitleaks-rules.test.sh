#!/usr/bin/env bash
# Negative self-test for the ER1 key rules in .gitleaks.toml.
#
# A scanner rule that was never shown a real violation reports green because it
# sees nothing, not because nothing is there. This test plants freshly generated
# fake keys in a temporary tree, runs gitleaks with the repository config over
# it, and requires each planted key to be reported under the expected rule. It
# also requires the one fixture exception to stay limited to its exact path and
# value, and that nothing else in the tree is reported.
#
# gitleaks never scans a file whose path matches gitleaks\.toml (a default
# allowlist entry, inherited through useDefault), so a key copied into the
# config is invisible to it. The last check therefore reads .gitleaks.toml
# directly and fails on any UUID literal, after showing that the same check
# finds a planted one.
#
# Needs gitleaks on PATH or in $GITLEAKS; a missing scanner fails the test.
# Output names rules, paths and line numbers only, never a value.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
config="$root/.gitleaks.toml"
gitleaks=${GITLEAKS:-gitleaks}
command -v "$gitleaks" >/dev/null 2>&1 || {
  echo "FAIL: gitleaks not found; set GITLEAKS or install the version pinned in .github/workflows/ci.yml" >&2
  exit 1
}
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
export HOME="$fixture/home" USERPROFILE="$fixture/home"
mkdir -p "$HOME" "$fixture/tree"

# A random version 4 UUID, built from 16 bytes of /dev/urandom.
uuid4() {
  local h
  h=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')
  printf '%s-%s-4%s-%x%s-%s\n' "${h:0:8}" "${h:8:4}" "${h:13:3}" \
    $(((0x${h:16:1} & 3) | 8)) "${h:17:3}" "${h:20:12}"
}
# The prefixed form: "m3cer1_" and 32 random bytes, base64url without padding.
prefixed() {
  printf 'm3cer1_%s\n' "$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n')"
}
plant() { # plant <path> <line>
  mkdir -p "$fixture/tree/$(dirname -- "$1")"
  printf '%s\n' "$2" >"$fixture/tree/$1"
}
dummy=00000000-0000-4000-8000-000000000000

plant env/prod.env "ER1_API_KEY=$(uuid4)"
plant pkg/leak/leak_test.go "	\"ER1_API_KEY\":    \"$(uuid4)\","
plant pkg/client/upload.go "	req.Header.Set(\"X-API-KEY\", \"$(uuid4)\")"
plant deploy/values.yaml "api_key: $(uuid4)"
plant docs/rotation.md "The new value is $(prefixed) and nothing else."
plant pkg/config/doctor_test.go "	\"ER1_API_KEY\":    \"$dummy\","
plant pkg/other/doctor_test.go "	\"ER1_API_KEY\":    \"$dummy\","
plant pkg/config/elsewhere_test.go "	\"ER1_API_KEY\":    \"$(uuid4)\","
plant logs/request.log "request_id=$(uuid4) status=200"
plant pkg/config/real/doctor_test.go "	\"ER1_API_KEY\":    \"$(uuid4)\","

printf '{{ range . }}{{ .RuleID }} {{ .File }}:{{ .StartLine }}\n{{ end }}' >"$fixture/report.tmpl"
rc=0
(cd -- "$fixture/tree" && "$gitleaks" detect --no-git --redact --no-banner --log-level error \
  --source . --config "$config" --exit-code 3 --report-format template \
  --report-template "$fixture/report.tmpl" --report-path "$fixture/report.txt") \
  >"$fixture/gitleaks.log" 2>&1 || rc=$?
if [ "$rc" -ne 3 ] || [ ! -f "$fixture/report.txt" ]; then
  echo "FAIL: gitleaks did not complete a scan with findings (exit $rc, want 3)" >&2
  exit 1
fi

failures=0
want() { # want <label> <rule> <path>: exactly one finding of <rule> in <path>
  local n
  n=$(grep -c -x -F "$2 $3:1" "$fixture/report.txt" || true)
  if [ "$n" -eq 1 ]; then echo "ok: $1"; else
    echo "FAIL: $1 (want 1 finding of $2 in $3, got $n)" >&2
    failures=$((failures + 1))
  fi
}
none() { # none <label> <path>: no finding at all in <path>
  local n
  n=$(grep -c -F " $2:" "$fixture/report.txt" || true)
  if [ "$n" -eq 0 ]; then echo "ok: $1"; else
    echo "FAIL: $1 (want no finding in $2, got $n)" >&2
    failures=$((failures + 1))
  fi
}
want 'legacy key in an env file' er1-api-key-legacy env/prod.env
want 'legacy key in a Go map' er1-api-key-legacy pkg/leak/leak_test.go
want 'legacy key in an X-API-KEY header' er1-api-key-legacy pkg/client/upload.go
want 'legacy key under api_key in YAML' er1-api-key-legacy deploy/values.yaml
want 'prefixed key without a key name' er1-api-key-prefixed docs/rotation.md
none 'dummy at its exact allowlisted path' pkg/config/doctor_test.go
want 'same dummy at another path' er1-api-key-legacy pkg/other/doctor_test.go
want 'random key next to the allowlisted file' er1-api-key-legacy pkg/config/elsewhere_test.go
want 'random key in a file of the same name below it' er1-api-key-legacy pkg/config/real/doctor_test.go
none 'UUID without a key name on its line' logs/request.log
total=$(wc -l <"$fixture/report.txt" | tr -d ' ')
if [ "$total" -eq 8 ]; then echo "ok: no finding beyond the 8 expected"; else
  echo "FAIL: want 8 findings in total, got $total" >&2
  sed 's/^/  found: /' "$fixture/report.txt" >&2
  failures=$((failures + 1))
fi

# The config file itself: line numbers of UUID literals, never the values.
uuid_lines() {
  grep -n -E '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}' "$1" |
    cut -d: -f1 | paste -sd ',' - || true
}
printf '[[rules.allowlists]]\n    regexes = [\n      "^%s$",\n    ]\n' "$(uuid4)" >"$fixture/planted.toml"
if [ "$(uuid_lines "$fixture/planted.toml")" = 3 ]; then echo "ok: config check finds a planted UUID"; else
  echo "FAIL: config check missed a planted UUID" >&2
  failures=$((failures + 1))
fi
lines=$(uuid_lines "$config")
if [ -z "$lines" ]; then echo "ok: no UUID literal in .gitleaks.toml"; else
  echo "FAIL: UUID literal in .gitleaks.toml on line(s) $lines; gitleaks never scans this file" >&2
  failures=$((failures + 1))
fi

[ "$failures" -eq 0 ] || { echo "$failures check(s) failed" >&2; exit 1; }

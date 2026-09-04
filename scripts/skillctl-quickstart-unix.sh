#!/usr/bin/env bash
#
# skillctl-quickstart-unix.sh: offline lifecycle SMOKE TEST for skillctl on
# macOS and Linux. The POSIX twin of scripts/skillctl-quickstart-windows.ps1:
# same seven steps, same PASS/FAIL/SKIP vocabulary, same fail-closed assertion
# at the end, so a Windows run and a Unix run can be compared line by line.
#
# Each lifecycle step is EXECUTED and ASSERTED (exit code plus the load-bearing
# artifact it must have written). Exit 0 iff every required step passed, so it
# is safe to wire into a gate.
#
#   1. version     prints a non-empty version string
#   2. keygen      writes <work>/author.priv + author.pub
#   3. pack        packs a throwaway skill dir into <work>/demo.skb
#   4. sign        writes the detached <bundle>.<digest>.author.sig
#   5. verify-sig  accepts the genuine bundle (exit 0)
#   6. trust add   pins the author pubkey in the SANDBOXED trust-roots.yaml
#   7. tamper      flips a byte in a COPY, re-points the signature at the new
#                  digest, and asserts verify-sig REFUSES it (ideal exit 11,
#                  author signature invalid; any non-zero is fail-closed)
#
# Why it cannot touch your real trust roots: `skillctl trust add` writes
# $HOME/.claude/skill-trust-roots.yaml, and skillctl resolves that home from
# $HOME (pkg/skillctl/verify/home.go), so the run happens with $HOME pointed at
# a fresh temp dir. (The Windows twin needs a binary built with
# `-tags allow_home_override_test` for the same sandbox, because a shipping
# Windows build deliberately ignores the attacker-settable $HOME. On Unix a
# plain `go build` is enough.)
#
# Everything is OFFLINE. The registry URL pinned in step 6 is a `.invalid`
# host that is never contacted: `trust add` only writes local YAML.
#
# It never prints a private key or signature bytes. Only paths, digests and
# exit codes.
#
# Usage:
#   ./scripts/skillctl-quickstart-unix.sh [--bin PATH] [--keep-work]
#   SKILLCTL=/path/to/skillctl ./scripts/skillctl-quickstart-unix.sh
#
# Binary resolution, in order: --bin, $SKILLCTL, ./build/skillctl, PATH.
#
# Exit: 0 every required step passed - 1 a step failed - 2 no binary found.
#
set -uo pipefail

BIN="${SKILLCTL:-}"
KEEP_WORK=0

while [ $# -gt 0 ]; do
  case "$1" in
    --bin)       BIN="${2:?--bin needs a path}"; shift 2 ;;
    --keep-work) KEEP_WORK=1; shift ;;
    -h|--help)   sed -n '3,40p' "$0" | sed 's/^#\{1,\} \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; NC=$'\033[0m'
[ -t 1 ] || { RED=""; GREEN=""; YELLOW=""; NC=""; }

PASS_N=0; FAIL_N=0; SKIP_N=0
_pass() { printf '  %s[PASS]%s %s\n' "$GREEN" "$NC" "$1"; PASS_N=$((PASS_N + 1)); }
_fail() { printf '  %s[FAIL]%s %s\n' "$RED" "$NC" "$1"; [ $# -gt 1 ] && printf '         hint: %s\n' "$2"; FAIL_N=$((FAIL_N + 1)); return 0; }
_skip() { printf '  %s[SKIP]%s %s (%s)\n' "$YELLOW" "$NC" "$1" "${2:-}"; SKIP_N=$((SKIP_N + 1)); }
_stage() { printf '\n%s\n' "$1"; }

# --- locate the binary ------------------------------------------------------
if [ -z "$BIN" ]; then
  REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  if [ -x "$REPO_ROOT/build/skillctl" ]; then BIN="$REPO_ROOT/build/skillctl"
  elif command -v skillctl >/dev/null 2>&1; then BIN="$(command -v skillctl)"
  fi
fi
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
  echo "ERROR: no skillctl binary. Build one (go build -o build/skillctl ./cmd/skillctl)," >&2
  echo "       pass --bin PATH, or set \$SKILLCTL." >&2
  exit 2
fi

# --- sandbox ----------------------------------------------------------------
WORK="$(mktemp -d "${TMPDIR:-/tmp}/skillctl-quickstart.XXXXXX")" || exit 2
ORIG_HOME="$HOME"
cleanup() {
  HOME="$ORIG_HOME"
  if [ "$KEEP_WORK" -eq 1 ]; then echo ""; echo "work dir kept: $WORK"
  else rm -rf "$WORK"; fi
}
trap cleanup EXIT
export HOME="$WORK"     # sandboxes every trust-roots write for this run only

echo ""
echo "========================================"
echo " skillctl lifecycle smoke ($(uname -s))"
echo "========================================"
echo "  binary : $BIN"
echo "  work   : $WORK"

# --- 1. version -------------------------------------------------------------
_stage "Step 1: version"
VER="$("$BIN" version 2>/dev/null | head -1)"
if [ -n "$VER" ]; then _pass "version prints '$VER'"
else _fail "version printed nothing" "wrong or broken binary"; fi

# --- 2. keygen --------------------------------------------------------------
_stage "Step 2: keygen"
STEM="$WORK/author"; PRIV="$STEM.priv"; PUB="$STEM.pub"
KEYGEN_OK=0
if "$BIN" keygen --out "$STEM" >/dev/null 2>&1 && [ -f "$PRIV" ] && [ -f "$PUB" ]; then
  _pass "keygen wrote author.priv + author.pub"      # contents deliberately not echoed
  KEYGEN_OK=1
else
  _fail "keygen did not produce both key files" "skillctl keygen --out <stem> writes <stem>.priv and <stem>.pub"
fi

# --- 3. pack ----------------------------------------------------------------
_stage "Step 3: pack"
SKILL_DIR="$WORK/skill"; BUNDLE="$WORK/demo.skb"; PACK_OK=0
mkdir -p "$SKILL_DIR"
cat > "$SKILL_DIR/SKILL.md" <<'SKILLMD'
---
name: skillctl-quickstart-smoke
version: 0.0.1
governance_level: green
---

# skillctl-quickstart-smoke

Throwaway skill packed by scripts/skillctl-quickstart-unix.sh to prove the
author, sign, verify, trust lifecycle runs here. Not for install.
SKILLMD
if [ "$KEYGEN_OK" -eq 1 ]; then
  if "$BIN" pack --skill "$SKILL_DIR" -o "$BUNDLE" --name skillctl-quickstart-smoke --version 0.0.1 >/dev/null 2>&1 \
     && [ -f "$BUNDLE" ] && [ "$(wc -c < "$BUNDLE" | tr -d ' ')" -ge 128 ]; then
    _pass "pack wrote demo.skb ($(wc -c < "$BUNDLE" | tr -d ' ') bytes)"
    PACK_OK=1
  else
    _fail "pack did not produce a non-trivial demo.skb" "pack needs --skill, -o, --name, --version and a SKILL.md"
  fi
else
  _skip "pack" "keygen failed, nothing to sign afterwards"
fi

# --- 4. sign ----------------------------------------------------------------
_stage "Step 4: sign"
SIGN_OK=0; SIG=""
if [ "$PACK_OK" -eq 1 ]; then
  # Flags BEFORE the positional bundle: Go's flag package stops at the first non-flag.
  if "$BIN" sign --key "$PRIV" "$BUNDLE" >/dev/null 2>&1; then
    SIG="$(find "$WORK" -maxdepth 1 -name 'demo.skb.*.author.sig' | head -1)"
  fi
  if [ -n "$SIG" ]; then
    _pass "sign wrote detached signature ($(basename "$SIG"))"
    SIGN_OK=1
  else
    _fail "sign did not produce a signature" "skillctl sign --key <priv> <bundle>, flag before the bundle"
  fi
else
  _skip "sign" "pack did not produce a bundle"
fi

# --- 5. verify-sig ----------------------------------------------------------
_stage "Step 5: verify-sig"
VERIFY_OK=0
if [ "$SIGN_OK" -eq 1 ]; then
  if "$BIN" verify-sig --pubkey "$PUB" "$BUNDLE" >/dev/null 2>&1; then
    _pass "verify-sig accepts the genuine bundle (exit 0)"
    VERIFY_OK=1
  else
    _fail "verify-sig rejected a genuine bundle" "sign/verify key mismatch, or sidecar signature name drift"
  fi
else
  _skip "verify-sig" "no signature to verify"
fi

# --- 6. trust add -----------------------------------------------------------
_stage "Step 6: trust add"
if [ "$KEYGEN_OK" -eq 1 ]; then
  # `--registry self` is invalid (the URL validator requires https:// or a
  # loopback http://). This host is never contacted: trust add writes YAML.
  REGISTRY="https://skillctl-quickstart.invalid/api/skills"
  TRUST_FILE="$WORK/.claude/skill-trust-roots.yaml"
  if "$BIN" trust add --registry "$REGISTRY" --pubkey "$PUB" >/dev/null 2>&1 \
     && [ -f "$TRUST_FILE" ] && grep -qF "$REGISTRY" "$TRUST_FILE"; then
    _pass "trust add pinned the author pubkey (sandboxed trust-roots.yaml)"
  else
    _fail "trust add did not pin the registry" "skillctl trust add --registry <https-url> --pubkey <pub>"
  fi
else
  _skip "trust add" "no pubkey to pin"
fi

# --- 7. tamper check (fail-closed) ------------------------------------------
_stage "Step 7: tamper check (fail-closed)"
if [ "$VERIFY_OK" -eq 1 ]; then
  TDIR="$WORK/tamper"; mkdir -p "$TDIR"
  TAMPERED="$TDIR/tampered.skb"
  cp "$BUNDLE" "$TAMPERED"

  # Flip one byte in the COPY. dd writes a single byte at the midpoint; the
  # replacement is chosen to differ from whatever was there.
  SIZE=$(wc -c < "$TAMPERED" | tr -d ' ')
  OFF=$((SIZE / 2))
  ORIG_BYTE="$(dd if="$TAMPERED" bs=1 skip="$OFF" count=1 2>/dev/null | od -An -tu1 | tr -d ' ')"
  NEW_BYTE=$(( (ORIG_BYTE + 1) % 256 ))
  printf "$(printf '\\%03o' "$NEW_BYTE")" | dd of="$TAMPERED" bs=1 seek="$OFF" count=1 conv=notrunc 2>/dev/null

  # verify-sig recomputes the digest and looks for <bundle>.<newdigest>.author.sig.
  # Re-point the ORIGINAL signature at the tampered digest, so the refusal comes
  # from the crypto path (exit 11) and not from a missing sidecar file (exit 1).
  # Both are fail-closed; 11 is the real proof.
  if command -v shasum >/dev/null 2>&1; then
    NEW_HASH="$(shasum -a 256 "$TAMPERED" | cut -d' ' -f1)"
  else
    NEW_HASH="$(sha256sum "$TAMPERED" | cut -d' ' -f1)"
  fi
  [ -n "$SIG" ] && cp "$SIG" "$TDIR/tampered.skb.$NEW_HASH.author.sig"

  "$BIN" verify-sig --pubkey "$PUB" "$TAMPERED" >/dev/null 2>&1
  CODE=$?
  if [ "$CODE" -eq 11 ]; then
    _pass "tamper REFUSED with exit 11 (author signature invalid), fail-closed proven"
  elif [ "$CODE" -ne 0 ]; then
    _pass "tamper REFUSED with exit $CODE (non-zero, fail-closed; ideal is 11)"
  else
    _fail "CRITICAL: verify-sig ACCEPTED a tampered bundle (fail-OPEN)" "a modified .skb must never verify, this is a trust-chain breach"
  fi
else
  _skip "tamper check" "the genuine verify-sig did not pass, so a tamper delta proves nothing"
fi

# --- summary ----------------------------------------------------------------
echo ""
echo "========================================"
if [ "$FAIL_N" -eq 0 ]; then
  printf ' %sPASS%s  %d checks, %d skipped\n' "$GREEN" "$NC" "$PASS_N" "$SKIP_N"
else
  printf ' %sFAIL%s  %d passed, %d failed, %d skipped\n' "$RED" "$NC" "$PASS_N" "$FAIL_N" "$SKIP_N"
fi
echo "========================================"
echo ""
[ "$FAIL_N" -eq 0 ] || exit 1
exit 0

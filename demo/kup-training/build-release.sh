#!/usr/bin/env bash
# build-release — Build cross-platform skillctl binaries, checksums,
# install.sh, and draft GitHub release notes.
#
# Output: $ARTIFACTS_DIR/release/
#   skillctl-darwin-arm64
#   skillctl-darwin-amd64
#   skillctl-linux-amd64
#   skillctl-linux-arm64
#   skillctl-windows-amd64.exe
#   SHA256SUMS
#   install.sh             (curl|sh installer)
#   RELEASE_NOTES.md       (draft notes for `gh release create`)
#   release-tag.txt        (suggested tag, e.g. skillctl/v0.1.0-kup)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

header "G2 — Cross-platform release of skillctl"

# Locate source
SOURCE_DIR=""
for cand in /Users/kamir/wt/spec-0189/s2-integration /Users/kamir/GITHUB.kamir/m3c-tools; do
  if [[ -d "$cand/cmd/skillctl" ]]; then SOURCE_DIR="$cand"; break; fi
done
test -n "$SOURCE_DIR" || { fail "skillctl source not found"; exit 2; }
ok "source: $SOURCE_DIR"

REL="$ARTIFACTS_DIR/release"
rm -rf "$REL"
mkdir -p "$REL"

# Tag and version
TAG="${RELEASE_TAG:-skillctl/v0.1.0-kup}"
echo "$TAG" > "$REL/release-tag.txt"

# Cross-build matrix
declare -a TARGETS=(
  "darwin/arm64"
  "darwin/amd64"
  "linux/amd64"
  "linux/arm64"
  "windows/amd64"
)

for t in "${TARGETS[@]}"; do
  os="${t%/*}"; arch="${t#*/}"
  ext=""; [[ "$os" == "windows" ]] && ext=".exe"
  out="skillctl-${os}-${arch}${ext}"
  log "building $out"
  ( cd "$SOURCE_DIR" && \
    GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w -X main.version=$TAG" \
      -o "$REL/$out" ./cmd/skillctl ) || { fail "build failed for $t"; exit 1; }
  ok "$out  ($(du -h "$REL/$out" | awk '{print $1}'))"
done

# Checksums
log "computing SHA-256"
( cd "$REL" && shasum -a 256 skillctl-* > SHA256SUMS )
ok "SHA256SUMS:"
sed 's/^/      /' "$REL/SHA256SUMS"

# Installer (curl|sh)
log "writing installer: install.sh"
cat > "$REL/install.sh" <<'INSTALLER'
#!/usr/bin/env bash
# skillctl installer — fetch the right binary for this host from a GitHub
# release, verify SHA-256, install to a user-writable bin directory.
#
# Usage:
#   curl -L https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.1.0-kup/install.sh | bash
#   curl -L .../install.sh | INSTALL_DIR=$HOME/.local/bin bash
#
# Required env (or args): RELEASE_BASE — GitHub raw release URL prefix.
set -euo pipefail

RELEASE_BASE="${RELEASE_BASE:-https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.1.0-kup}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

uname_s=$(uname -s | tr '[:upper:]' '[:lower:]')
uname_m=$(uname -m)
case "$uname_s" in
  darwin) os="darwin" ;;
  linux)  os="linux" ;;
  msys*|cygwin*|mingw*) os="windows" ;;
  *) echo "unsupported OS: $uname_s" >&2; exit 1 ;;
esac
case "$uname_m" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *) echo "unsupported arch: $uname_m" >&2; exit 1 ;;
esac
ext=""; [[ "$os" == "windows" ]] && ext=".exe"
asset="skillctl-${os}-${arch}${ext}"

mkdir -p "$INSTALL_DIR"
tmp=$(mktemp -d)
trap "rm -rf $tmp" EXIT

echo "Fetching $asset from $RELEASE_BASE"
curl -fsSL -o "$tmp/$asset"     "$RELEASE_BASE/$asset"
curl -fsSL -o "$tmp/SHA256SUMS" "$RELEASE_BASE/SHA256SUMS"

echo "Verifying SHA-256"
expected=$(grep " $asset\$" "$tmp/SHA256SUMS" | awk '{print $1}')
[[ -n "$expected" ]] || { echo "$asset not in SHA256SUMS" >&2; exit 1; }
actual=$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')
if [[ "$expected" != "$actual" ]]; then
  echo "checksum mismatch: expected $expected, got $actual" >&2
  exit 1
fi
echo "OK: $expected"

chmod +x "$tmp/$asset"
mv "$tmp/$asset" "$INSTALL_DIR/skillctl${ext}"
echo "Installed: $INSTALL_DIR/skillctl${ext}"
echo
echo "Next steps:"
echo "  $INSTALL_DIR/skillctl${ext} --help"
echo "  $INSTALL_DIR/skillctl${ext} keygen --out ~/.claude/skillctl-keys/author"
INSTALLER
chmod +x "$REL/install.sh"
ok "installer: $REL/install.sh"

# Release notes
log "writing release notes"
cat > "$REL/RELEASE_NOTES.md" <<EOF
# skillctl ${TAG#skillctl/} — KuP Berlin training cut

Released: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Source:   $SOURCE_DIR ($(cd "$SOURCE_DIR" && git rev-parse --short HEAD 2>/dev/null || echo "<no git>"))

## What's in the box

This is the **first end-user-facing cut** of \`skillctl\` for the KuP Berlin
Skill-Manager training cohort. It ships:

- The full SPEC-0188 trust-chain CLI: \`pack\`, \`keygen\`, \`sign\`, \`verify-sig\`,
  \`trust\`, \`install\`, \`verify\`, \`attest\`.
- The SPEC-0189 inventory CLI: \`scan\`, \`report\`, \`diff\`, \`seal\`, \`audit\`,
  \`review\`, \`browse\`, \`consolidate\`, \`sync-usage\`, \`import\`.
- The SPEC-0195 awareness bridge: \`awareness sync\`, \`awareness verify\`,
  \`awareness reset\`.
- The SPEC-0196 intent declaration: \`intent declare\`.

## Install

\`\`\`bash
curl -fsSL https://github.com/kamir/m3c-tools/releases/download/${TAG}/install.sh | bash
\`\`\`

The installer auto-detects OS/arch (darwin · linux · windows × amd64 · arm64),
verifies SHA-256, drops the binary into \`\$HOME/.local/bin/skillctl\`.

## Manual download

| OS / Arch | Asset |
|---|---|
| macOS (Apple Silicon) | \`skillctl-darwin-arm64\` |
| macOS (Intel) | \`skillctl-darwin-amd64\` |
| Linux (amd64) | \`skillctl-linux-amd64\` |
| Linux (arm64) | \`skillctl-linux-arm64\` |
| Windows (amd64) | \`skillctl-windows-amd64.exe\` |

Verify checksums against \`SHA256SUMS\` before running.

## Documentation

- **User manual**: USER-MANUAL.pdf (in the release assets)
- **CLI reference**: SKILLCTL-MANUAL.pdf (in the release assets)
- **Combined handbook**: KuP-skill-manager-handbook.pdf
- **Source docs**: \`PROJECTS/Skill-Manager/USER-MANUAL.md\` in [m3c-tools-maintenance](https://github.com/kamir/m3c-tools-maintenance)

## Known gaps (read before training)

- Author-side \`propose\` (SPEC-0194) is drafted, not in the dispatcher yet — use \`pack\` + \`sign\` + the registry HTTP endpoint manually until it lands.
- \`audit\` Phase 2 (full verdict UX with cleanup) is in flight — Phase 1 surface (scan + per-skill verdict) is what's wired today.
- SPEC-0201 \`import-public\`/\`-list\`/\`-policy lint\` and SPEC-0202 \`run\`/\`invoke-replay\` are documented but not in this binary cut.

## Verifying the release

The KuP demo \`demo/kup-training/run-all.sh\` walks every claim in the user manual
end-to-end and asserts a valid skill installs, an invalid skill fails, and a
post-install edit is detected. Re-run on any host to verify the binary behaves
as documented.

EOF
ok "release notes: $REL/RELEASE_NOTES.md"

# Recommended `gh release create` command (do NOT run automatically — that's
# a destructive ship action and stays user-driven).
log "writing gh-release recipe (NOT executed)"
cat > "$REL/gh-release-create.sh" <<EOF
#!/usr/bin/env bash
# Run this manually to publish the release. NOT auto-run by build-release.sh.
set -euo pipefail
cd "$REL"
gh release create "$TAG" \\
    --title "skillctl ${TAG#skillctl/} — KuP Berlin training cut" \\
    --notes-file RELEASE_NOTES.md \\
    --draft \\
    skillctl-darwin-arm64 skillctl-darwin-amd64 \\
    skillctl-linux-amd64  skillctl-linux-arm64 \\
    skillctl-windows-amd64.exe \\
    SHA256SUMS install.sh \\
    RELEASE_NOTES.md \\
    \$( [[ -f "$ARTIFACTS_DIR/USER-MANUAL.pdf" ]]                  && echo "$ARTIFACTS_DIR/USER-MANUAL.pdf" ) \\
    \$( [[ -f "$ARTIFACTS_DIR/SKILLCTL-MANUAL.pdf" ]]              && echo "$ARTIFACTS_DIR/SKILLCTL-MANUAL.pdf" ) \\
    \$( [[ -f "$ARTIFACTS_DIR/KuP-skill-manager-handbook.pdf" ]]   && echo "$ARTIFACTS_DIR/KuP-skill-manager-handbook.pdf" )
EOF
chmod +x "$REL/gh-release-create.sh"
ok "release recipe: $REL/gh-release-create.sh  (run manually to publish — DRAFT by default)"

header "G2 — done"
note "Release dir: $REL"
note "Tag:         $TAG"
note "Assets:      $(ls -1 "$REL" | wc -l | tr -d ' ') files"

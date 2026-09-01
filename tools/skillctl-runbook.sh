#!/usr/bin/env bash
# Generate the skillctl publisher onboarding runbook (a self-contained, CSP-safe
# HTML worksheet) for a given release tag, by stamping the version into the
# template. This is a STANDARD step of skillctl release prep — invoked by
# tools/skillctl-release.sh so every release ships a version-matched runbook.
#
# Usage:
#   tools/skillctl-runbook.sh <tag> [out.html]
#   tools/skillctl-runbook.sh skillctl/v0.2.11-rc1
#   tools/skillctl-runbook.sh skillctl/v0.2.11-rc1 ../m3c-tools-maintenance/ONBOARDING/skillctl-publisher-runbook.html
#
# Default output: release/<tag>/skillctl-publisher-runbook.html
set -euo pipefail

TAG="${1:?usage: skillctl-runbook.sh <tag> [out.html]  e.g. skillctl/v0.2.11-rc1}"
VERSION="${TAG##*/}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TPL="${ROOT}/tools/release-templates/skillctl-publisher-runbook.template.html"
OUT="${2:-${ROOT}/release/${TAG}/skillctl-publisher-runbook.html}"

[ -f "${TPL}" ] || { echo "runbook template not found: ${TPL}" >&2; exit 1; }
mkdir -p "$(dirname "${OUT}")"

# Stamp the release version into the template (install URL, version check, prose).
sed "s/__SKILLCTL_VERSION__/${VERSION}/g" "${TPL}" > "${OUT}"

# Gate: no unresolved placeholders, no stray external resources (CSP-safe).
if grep -q '__SKILLCTL_VERSION__' "${OUT}"; then
  echo "ERROR: unresolved __SKILLCTL_VERSION__ placeholder in ${OUT}" >&2
  exit 1
fi
if grep -qiE 'src="http|href="http|@import|cdn|googleapis|unpkg|jsdelivr' "${OUT}"; then
  echo "ERROR: runbook references an external resource (must be self-contained/CSP-safe): ${OUT}" >&2
  exit 1
fi

echo "==> runbook generated: ${OUT} (version ${VERSION})"

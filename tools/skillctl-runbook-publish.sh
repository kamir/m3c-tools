#!/usr/bin/env bash
# Publish a generated onboarding runbook to the THOH catalog (SPEC-0272 P0).
#
# This is the "release → aims-core catalog" bridge: after the runbook HTML is
# generated (tools/skillctl-runbook.sh), POST its descriptor + cached HTML to
# the thoh_manager catalog so a manager can find and assign it.
#
# Auth: device token (FR-0043). Reads $ER1_DEVICE_TOKEN, else the persisted
# token (same as skillctl). Endpoint: POST <ER1_BASE>/api/thoh/runbooks.
#
# NOTE: not wired into skillctl-release.sh yet — activate that one-liner once
# thoh_manager is deployed (the endpoint must exist). Until then, run manually.
#
# Usage:
#   tools/skillctl-runbook-publish.sh <tag> <runbook.html> [ER1_BASE]
#   tools/skillctl-runbook-publish.sh skillctl/v0.2.11 release/skillctl/v0.2.11/skillctl-publisher-runbook.html https://onboarding.guide
set -euo pipefail

TAG="${1:?usage: skillctl-runbook-publish.sh <tag> <runbook.html> [ER1_BASE]}"
HTML="${2:?path to the generated runbook HTML}"
ER1_BASE="${3:-${ER1_API_BASE:-https://onboarding.guide}}"
VERSION="${TAG##*/}"
[ -f "$HTML" ] || { echo "runbook html not found: $HTML" >&2; exit 1; }

TOKEN="${ER1_DEVICE_TOKEN:-}"
if [ -z "$TOKEN" ] && command -v security >/dev/null 2>&1; then
  TOKEN=$(security find-generic-password -s m3c-tools -a device-token -w 2>/dev/null \
    | python3 -c 'import sys,json;print(json.load(sys.stdin).get("token",""))' 2>/dev/null || true)
fi
[ -n "$TOKEN" ] || { echo "no device token (export ER1_DEVICE_TOKEN or 'skillctl login')" >&2; exit 1; }

# The skillctl publisher runbook descriptor (SPEC-0272 §4). The dogfood case.
# Other runbooks pass their own descriptor; this bakes skillctl's for P0.
PAYLOAD=$(python3 - "$VERSION" "$HTML" "$TAG" "$ER1_BASE" <<'PY'
import json, sys
version, html_path, tag, base = sys.argv[1:5]
html = open(html_path, encoding="utf-8").read()
descriptor = {
    "runbook_id": "rb-skillctl-publisher",
    "version": version,
    "title": "skillctl — sign & publish a skill",
    "purpose": "Turn a person into a verified skill publisher",
    "goal": "A signed, green-attested skill published to the room",
    "tags": ["skillctl", "onboarding", "publisher", "trust"],
    "audience_roles": ["user", "learner", "coach"],
    "governance_level": "green",
    "source": {"repo": "m3c-tools",
               "path": "tools/release-templates/skillctl-publisher-runbook.template.html",
               "release": tag},
    "html_url": f"{base.rstrip('/')}/../m3c-tools/releases/download/{tag}/skillctl-publisher-runbook.html",
}
print(json.dumps({"descriptor": descriptor, "html": html}))
PY
)

echo "==> POST ${ER1_BASE}/api/thoh/runbooks  (rb-skillctl-publisher@${VERSION})"
code=$(curl -s -o /tmp/thoh-publish.out -w '%{http_code}' \
  -X POST "${ER1_BASE%/}/api/thoh/runbooks" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  --data-binary "$PAYLOAD")
echo "HTTP $code"
cat /tmp/thoh-publish.out 2>/dev/null; echo
[ "$code" = "201" ] || { echo "publish failed" >&2; exit 1; }
echo "==> runbook in catalog — assign it from the THOH board."

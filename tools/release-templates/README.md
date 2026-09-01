# skillctl release templates

## Onboarding runbook generator (release-prep standard)

Every skillctl release ships a **version-matched onboarding runbook** — a
self-contained, CSP-safe HTML worksheet that walks a new publisher through
install → keygen → login → package → publish → upgrade for *that exact version*.

- **Template:** `skillctl-publisher-runbook.template.html` — single source of
  truth. Versioned tokens use the `__SKILLCTL_VERSION__` placeholder.
- **Generator:** `tools/skillctl-runbook.sh <tag> [out.html]` — stamps the
  version, then gates on (a) no unresolved placeholder and (b) no external
  resource (CSP-safe / offline).
- **Wired into release prep:** `tools/skillctl-release.sh <tag>` calls the
  generator automatically, dropping `skillctl-publisher-runbook.html` into
  `release/<tag>/` alongside the binaries. So cutting a release always produces
  the matching runbook — no manual step.

### Manual use
```sh
# into the release dir (default)
tools/skillctl-runbook.sh skillctl/v0.2.11-rc1

# into the living onboarding copy (sibling maintenance repo)
tools/skillctl-runbook.sh skillctl/v0.2.11-rc1 \
  ../m3c-tools-maintenance/ONBOARDING/skillctl-publisher-runbook.html
```

### Editing the runbook
Edit the **template**, never a generated copy. Keep it self-contained (inline
CSS/JS, no external fetches) so the CSP-safety gate passes. The worksheet engine
(progress, per-step CLI-output + feedback, copy icons, session-input templating)
lives in the template's inline `<script>`.

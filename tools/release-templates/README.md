# skillctl release templates

## Onboarding runbook generator (release-prep standard)

Every skillctl release ships a **version-matched onboarding runbook**: a
self-contained, CSP-safe HTML worksheet that walks a new publisher through
install → keygen → login → package → publish → upgrade for *that exact version*.

- **Template:** `skillctl-publisher-runbook.template.html`: single source of
  truth. Versioned tokens use the `__SKILLCTL_VERSION__` placeholder.
- **Generator:** `tools/skillctl-runbook.sh <tag> [out.html]`: stamps the
  version, then gates on (a) no unresolved placeholder and (b) no external
  resource (CSP-safe / offline).
- **Wired into release prep:** `tools/skillctl-release.sh <tag>` calls the
  generator automatically, dropping `skillctl-publisher-runbook.html` into
  `release/<tag>/` alongside the binaries. So cutting a release always produces
  the matching runbook: no manual step.

## The descriptor: `runbook.meta.json` (BUG-0224)

The HTML is what a human works through; `runbook.meta.json` is what the THOH catalog
stores so the work can be **assigned and tracked**. It is the SPEC-0275 sidecar for
`rb-skillctl-publisher`, and it lives here because its `steps[]` are read off the
template next to it.

- **`steps[].id` must match the template's `data-step` attributes** (`s1` to `s14`
  today). The worksheet books progress per `data-step`, and the server counts
  completion per `steps[].id`. Ids that drift produce progress that lands nowhere.
- **Add a step to the template, add it here in the same commit.** `s11`
  (re-validate) is the one optional step: `"required": false`.
- Publishers read it: `tools/skillctl-runbook-publish.sh` (automatically) and
  `skillctl runbook publish --meta <path>`. Without it, both fall back to a baked
  descriptor that has no steps, and the catalog entry can never reach `complete`.
  That was BUG-0224.
- `version`, `source` and `html_url` are **not** in the file. They are stamped at
  publish time (SPEC-0275 section 4).

### Manual use
```sh
# into the release dir (default)
tools/skillctl-runbook.sh skillctl/v0.2.11-rc1

# into the living onboarding copy (sibling private maintenance plane)
tools/skillctl-runbook.sh skillctl/v0.2.11-rc1 \
  "${M3C_MAINTENANCE_DIR}"/ONBOARDING/skillctl-publisher-runbook.html
```

### Editing the runbook
Edit the **template**, never a generated copy. Keep it self-contained (inline
CSS/JS, no external fetches) so the CSP-safety gate passes. The worksheet engine
(progress, per-step CLI-output + feedback, copy icons, session-input templating)
lives in the template's inline `<script>`.

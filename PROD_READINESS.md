# Production Readiness Checklist (Pre-Release 1.5)

## Security

- [ ] `ER1_ENV=prod` enforces `ER1_VERIFY_SSL=true` (hard fail if not).
- [ ] TLS-disabled mode (`ER1_VERIFY_SSL=false`) is used only for `ER1_ENV=dev`.
- [ ] No sensitive data (full URLs, tokens, API keys) is logged.
- [ ] Local sensitive artifacts use restrictive permissions (`0700` dirs, `0600` files).
- [ ] Retry payloads preserve original transcript/audio/image artifacts.

## Data Integrity

- [ ] Retry uploads re-send the original payload files, not placeholders.
- [ ] Import pipeline records deterministic status transitions (`new -> imported -> uploaded/failed`).
- [ ] Queue entries include enough metadata to retry uploads safely (`content_type`, file paths).

## Feature Completeness

- [ ] `import-audio --dry-run` scans and reports statuses only.
- [ ] `import-audio --apply` imports and tracks files.
- [ ] `import-audio --upload` imports and uploads to ER1.
- [ ] Audio import works without source image and uses app logo placeholder.
- [ ] Auto-tagging from filename is present in imported and uploaded payloads.

## UX

- [ ] Permission setup communicates required vs optional permissions clearly.
- [ ] Error messages provide actionable remediation.
- [ ] Menubar/browser tab detection avoids leaking full URLs.

## Release Pipeline

- [ ] macOS app bundle signing is configured.
- [ ] Notarization and stapling are configured for production artifacts.
- [ ] Release process does not auto-commit unrelated working-tree changes.
- [ ] CI gate includes unit + integration checks for import/retry/upload.

## Verification

- [ ] `go test ./pkg/er1 ./pkg/importer ./pkg/menubar ./cmd/m3c-tools` passes.
- [ ] Manual smoke test: import audio -> upload -> open ER1 item -> audio playable.
- [ ] Manual smoke test: force upload failure -> queued -> retry success with original artifacts.

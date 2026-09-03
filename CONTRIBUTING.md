# Contributing

Thanks for helping improve **m3c-tools** and **skillctl**. This guide covers the local setup,
the checks CI enforces, and the conventions that keep the two tools releasable at all times.

## Prerequisites

- **Go 1.25+**.
- For the macOS menu-bar GUI only: `portaudio` + `ffmpeg` (cgo). The CLIs and `skillctl` need
  neither.

```bash
git clone https://github.com/kamir/m3c-tools.git && cd m3c-tools
make build                                  # → ./build/m3c-tools
go build -o build/skillctl ./cmd/skillctl   # skillctl
```

## Before you open a PR — run the gates CI runs

```bash
make ci            # vet · golangci-lint · unit tests · build (the gate CI enforces)
make code-review   # build, vet, tests, secret scan, dead code, deps
make check-docs    # documentation ↔ implementation consistency
```

- **Formatting is not negotiable.** Run `gofumpt -w .` and keep imports grouped with `gci`
  (std / external / `github.com/kamir/m3c-tools`). `.golangci.yml` is the enforced config.
- **Tests bite.** Add tests with your change; the suite runs with `-race`. Offline tests live
  under `make test-unit`; networked / ER1 / whisper suites are opt-in (`make test-*`).
- **Document CLI flags.** Every CLI flag must be described in its manual
  (`docs/manual-m3c-tools.md` / `docs/manual-skillctl.md`) — and only real flags may be
  documented. Undocumented or phantom flags are treated as a defect.

## Commit messages — Conventional Commits

The release version bump is **derived from your commits**, so the prefix matters
([`scripts/derive-bump.sh`](scripts/derive-bump.sh)):

| Prefix | Meaning | Release effect |
|--------|---------|----------------|
| `feat:` | a new capability | **minor** |
| `fix:` | a bug fix | **patch** |
| `feat!:` / `fix!:` / `BREAKING CHANGE:` trailer | a breaking change to callers | **major** (never automatic) |
| `chore:` / `docs:` / `refactor:` / `test:` | no user-facing behaviour change | **patch** |

Line count is not a signal: a one-line feature is a `feat:`; a large behaviour-preserving
refactor is not.

## Branching & PRs

- Branch off `master`; open a PR against `master`.
- Keep PRs focused; a green `make ci` is the baseline for review.
- Pushing changes under `.github/workflows/**` requires an **SSH** remote (the HTTPS OAuth token
  lacks the `workflow` scope).

## Where things live

- **Code** lives in this repository.
- **Plans, SPECs and design docs** live in the sibling private maintenance repository, not in
  this tree — the boundary is enforced by [`tools/boundary-gate.sh`](tools/boundary-gate.sh).
  Contributor/release tooling resolves it via `M3C_MAINTENANCE_DIR` (see the README).

## Releasing

Releases are tag-driven and signed in CI. The full runbook is in
**[docs/releasing.md](docs/releasing.md)**.

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the project's
**Apache-2.0** license (see [LICENSE](LICENSE)).

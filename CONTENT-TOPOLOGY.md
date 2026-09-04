# Content topology: `m3c-tools` (public plane)

`m3c-tools` is the **PUBLIC / open-source plane**: it is meant to be given away. Its
private sibling, the **maintenance plane**, holds the *reasoning* behind the code.
This split implements **SPEC-0358** ("ship the code, keep the reasoning"). The
`tools/boundary-gate.sh` check (run in CI by `.github/workflows/boundary-gate.yml`)
enforces it on every push and pull request.

## What lives here (public)

- **README**: orientation and quick start.
- **User manual & API docs**: everything under `docs/` that documents how to run and
  call the tool (including the ER1 client endpoints and default context: these are the
  shipped client's own public operation).
- **The code**: `cmd/`, `pkg/`, `internal/`, `mcp-skill-server/`, `rag-mcp-server/`,
  tests, `installer/`, `scripts/`, `demo/`.
- **LICENSE**.
- **CHANGELOG**: the public release history.

## What lives on the private (maintenance) plane

The private maintenance plane (a separate repo, plus PLM and ER1) holds the reasoning
and governance artefacts:

- **SPECs, ARCH docs, ADRs**: requirements, architecture, decision records.
- **OPS / CISO**: operational runbooks, compliance mappings, infra device registry.
- **FR / Bug / CR**: feature requests, bug reports, change requests.
- **Onboarding-Guide material**: publisher runbooks and customer onboarding manuals.

These never ship in this repo.

## The cross-reference rule (ID-ONLY)

A public-plane file may reference the private plane **only by identifier**:

- Good:  `implements SPEC-1234`, `see ADR-0007`, `fixes BUG-0124`
- Bad:   any path or URL into the private repo, an internal endpoint, a secret header,
         or a raw ER1 context-id.

An identifier is a durable, plane-independent handle; a path leaks the private plane's
layout (and often a personal machine path) into a giveable artefact. When the full
detail is needed, keep it on the private maintenance plane and cite the identifier
here.

## What the boundary-gate enforces

`tools/boundary-gate.sh` scans every tracked, non-binary file (minus a small,
documented allowlist) and fails on:

| Reason                     | Pattern                       | Scope |
|----------------------------|-------------------------------|-------|
| private-repo path reference| a path into the private repo  | all files |
| internal endpoint          | `127.0.0.1:8081`              | narrative surface* |
| ER1 context-id             | `<digits>___<slug>`           | narrative surface* |
| secret header              | `X-API-KEY`                   | narrative surface* |
| internal API path          | `/upload_2`, `/api/plm/`      | narrative surface* |

\* The operational patterns are **not** checked on the tool's own operational surface
(its source, tests, config, API/user docs, demo, templates), per "ship the code", the
ER1 client legitimately carries those there. They guard the narrative surface (README,
agent instructions, root files) against an accidental paste. A **path into the private
repo is always a leak, in any file**, and is checked everywhere.

Bare `SPEC-1234` / `ADR-1234` identifiers match no pattern and are always allowed.

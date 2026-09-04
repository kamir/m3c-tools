# Compatibility policy

What we promise not to break, and how far back a release reaches. `skillctl` is a
trust tool: the artifacts it produces, signed `.skb` bundles and the events that
attest to them, outlive any single CLI version and are verified on machines we do
not control. So for `skillctl`, **format compatibility outranks API compatibility.**
A caller can adapt to a renamed flag on the next upgrade; a bundle signed last year
must still verify today. When the two are in tension, the wire/bundle format wins.

These are committed guarantees (decision H8d), not aspirations. Where a guarantee is
mechanically checked, the [how we verify](#how-we-verify-these) section says by what.

## Supported versions

Only the **latest** released version of each line is supported:

- **product**: `vX.Y.Z` (`m3c-tools` and the bundled binaries);
- **skillctl**: `skillctl/vX.Y.Z` (the signed trust CLI, its own version series).

The two lines version independently (see [docs/releasing.md](docs/releasing.md): a
release cuts them from the same commit under two separate tags). Older tags are not
maintained; **security fixes land on the latest release** of each line. This mirrors
[SECURITY.md](SECURITY.md#supported-versions): the supported set is exactly what
receives fixes.

## Security-fix SLA

| Severity | Target |
|----------|--------|
| HIGH / CRITICAL | fix on the latest line **within 7 days** of a confirmed report |
| everything else | best-effort, next scheduled release |

Report privately: see [SECURITY.md](SECURITY.md#reporting-a-vulnerability). The clock
starts when a report is confirmed, and a fix ships as a new latest release (there is no
backport to older tags).

## Breaking changes

A change that breaks callers ships **only with a MAJOR version bump**, and **always
with a migration note** in the release. "Breaking" is a statement about callers, so it
is never derived automatically from a diff, the MAJOR bump is a deliberate act
(`make release-major`; the derive-bump rule never issues MAJOR on its own, see
[docs/releasing.md](docs/releasing.md#choosing-the-version-bump)).

## `.skb` bundle format

The bundle format is the load-bearing compatibility surface. A `.skb` archive carries a
`bundle.json` manifest whose `schema` field is the **format version**: currently
`m3c-skill-bundle/v1` (the `skillbundle.Schema` constant in
[`pkg/skillbundle/manifest.go`](pkg/skillbundle/manifest.go)). The manifest also carries
the skill's own semver `version`, and a content-address `bundle_digest` (the SHA-256 of
the canonical archive) that *is* the bundle's identity.

- A reader accepts bundles produced by the **current and the previous MINOR (N−1)** of
  its line. Upgrading one MINOR never orphans the bundles you already trust.
- A **format break**: anything that changes how existing bytes are interpreted:
  **requires a MAJOR bump** and bumps the `schema` version field
  (`m3c-skill-bundle/v1` → `.../v2`). Readers gate on that field, so an
  incompatible bundle is refused explicitly rather than silently mis-parsed. The
  registry carrier formats gate the same way and **fail closed**: a store whose
  wire-format version is newer than the running build is rejected with "upgrade
  skillctl", never best-effort parsed.

Additive fields within a MAJOR (new optional `bundle.json` keys) are **not** a break: old
readers ignore unknown keys and the signed `bundle_digest` still verifies.

## CLI flags

A removed or renamed flag is **deprecated for at least one MINOR before removal**. During
that window the old flag keeps working (and the manual documents the deprecation), so a
script pinned to one MINOR keeps running across the next. Removal itself, if it breaks
callers, follows the [breaking-changes](#breaking-changes) rule.

## Policy / config schemas

Trust-root and policy configuration is **additive-only within a MAJOR**: new optional
keys may appear, but an existing config keeps its meaning across every MINOR and PATCH of
a line. A change that would reinterpret or drop an existing key is a format break and
takes a MAJOR bump.

## How we verify these

These guarantees are not honour-system where a check exists:

- **CLI flags**: the `docaudit` code↔manual gate ([`cmd/docaudit`](cmd/docaudit), run by
  `make check-docs`) fails the build on any flag that is real-but-undocumented or
  documented-but-phantom, in both directions and per CLI. A deprecation is therefore
  visible in the manual for as long as the flag is real, and a removed flag cannot leave
  a dangling doc entry.
- **Version bumps**: the single loose-semver comparator
  ([`pkg/skillctl/semver`](pkg/skillctl/semver)) gates version monotonicity at propose
  time and is covered by comparator + monotonicity tests, so the "highest non-revoked
  version" decision is one implementation, not four divergent ones.
- **`.skb` format**: the `schema` version field is stamped into every bundle at pack
  time and is the explicit gate point for a format break; the registry/carrier
  wire-format versions add a fail-closed "newer than this build" refusal.

See [docs/releasing.md](docs/releasing.md) for how a version is chosen and cut, and
[SECURITY.md](SECURITY.md) for the supported-version and reporting policy this document
tracks.

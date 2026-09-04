# Threat model: the `skillctl` trust layer

`skillctl` is the *capability plane* of m3c-tools: it signs, admits, verifies, installs and
revokes the agent skills that read your memory and act on your behalf. Because it is a trust
tool, this document holds its own threat model to the same evidence standard it asks of others
: every claim below either points at a mitigation **and the test(s) that exercise it**, or is
marked honestly as a **GAP** with a filed follow-up.

This is a living document. The threat IDs (`R01`–`R12`) are meant to be cited from the tests
themselves (see [§6](#6-keeping-the-model-live)), so the map between "what we say we defend"
and "what the suite actually proves" stays connected as the code moves.

**Companion documents:** [SECURITY.md](SECURITY.md) (reporting + supply-chain guarantees),
[CONTRIBUTING.md](CONTRIBUTING.md) (the CI gates), [README.md](README.md#security--supply-chain)
(the release/provenance posture). This document covers the *runtime trust chain*, what happens
between an author signing a skill and a consumer running it, not the release supply chain, which
those pages already cover.

**Scope note.** This model covers `skillctl` and the trust artefacts it produces and consumes. It
does **not** cover the `m3c-tools` capture pipeline (YouTube/audio/screenshot → ER1), which is a
data-capture tool with a different risk profile. Where the two meet, a skill acting on ER1 memory
, the boundary is the skill's declared `data_dependencies`, addressed in R11.

---

## 1. Scope & assets

The assets below are what an attacker wants to forge, replace, suppress, or leak. They are
ordered from the artefact that crosses the most hands (a `.skb`) to the roots that anchor trust.

| # | Asset | What it is | Why it matters |
|---|-------|------------|----------------|
| A1 | **Skill bundles (`.skb`)** | The packaged, signed unit of a skill: content + manifest, addressed by its digest. | This is the executable payload. If a forged or tampered bundle is admitted, arbitrary skill code runs. Identity **is** the digest: the whole chain hangs off it. |
| A2 | **The ed25519 trust chain** | Author signature + registry signature over each bundle, plus the identity records the signatures verify against. | The offline proof that a bundle is who it says it is. A break here means impersonation or silent modification. |
| A3 | **Signing keys** | ed25519 private keys used by authors (skill signatures) and the registry (admission signatures); the agent-identity owner keys behind `agentid`. | Custody of a private key is custody of an identity. Leakage = the attacker signs as you; the mitigation is revocation (A4). |
| A4 | **Revocation lists / revocation HEAD** | The signed, epoch-stamped statement of "these identities/bundles are no longer trusted", with a monotonic floor. | The only way to withdraw trust after a key or a skill goes bad. Must be **fail-closed** (absence ≠ permission) and **unforgeable** from unsigned carrier data. |
| A5 | **Trust roots** | `~/.claude/skill-trust-roots.yaml`: the pinned registry public keys, the `governance_minimum`, and policy such as `require_independent_review`. | The root of the whole offline decision. Whatever this file trusts, the verifier trusts. Its integrity and its ACLs are load-bearing. |
| A6 | **The install target directory** | The on-disk location a verified bundle is extracted into (e.g. under `~/.claude/…`). | The extraction step turns a byte stream from an untrusted carrier into files on your disk: the classic path-traversal / symlink-escape / archive-bomb surface. |
| A7 | **The transparency log (`translog`) and audit trail** | The local, append-oriented record of trust decisions (gate verdicts, install/revoke events, invocation receipts). | The after-the-fact evidence. It must resist replay and tamper, and, because it records security events, it must not itself become a place credentials leak. |

Two crosscutting properties are assets in their own right:

- **Offline verifiability**: the trust-chain check must reach a verdict with *no network and no
  hosted CA in the path* (README §"Offline verification"). Any dependency on a live authority is a
  new attack surface and a new outage mode.
- **Fail-closed default**: on ambiguity, panic, missing data, or a policy the verifier can't
  evaluate, the answer is *deny*, never *allow*.

---

## 2. Trust boundaries

A skill travels from an author's machine, through a carrier nobody trusts, to a consumer who runs
it, with CI in the middle for first-party skills. Each arrow is a boundary where data changes
hands and trust must be re-established, never assumed.

```
   ┌────────────┐   sign (ed25519, A3)   ┌──────────────────────┐   admit + sign      ┌────────────┐
   │  AUTHOR    │ ─────────────────────▶ │  REGISTRY / CARRIER  │ ──────────────────▶ │  CONSUMER  │
   │ (trusted   │      .skb + author sig │  ER1 · Git · OCI     │  registry sig, meta │ (installs, │
   │  key held) │                        │  ── UNTRUSTED ──     │                     │  runs)     │
   └────────────┘                        └──────────────────────┘                     └────────────┘
         │                                          │                                        │
         │ CI/build (first-party): keyless          │  carries bytes + UNSIGNED metadata     │  offline verifier +
         │ cosign/OIDC, SLSA L3: see SECURITY.md    │  (annotations, filenames, status)      │  local install root (A6)
         ▼                                          ▼                                        ▼
   provenance over releases            *projection ≠ proof*: R05              trust roots (A5) + translog (A7)
```

**B1: Author ↔ registry.** The author signs; the registry stores and re-serves. The registry is
an **untrusted carrier**: it moves bytes and adds convenience metadata (OCI annotations, Git
filenames/dir names, an advertised `status` field), but none of that carrier-added metadata is
authenticated. Trust decisions must read identity and revocation state from the **signed
envelope**, never from the carrier's projection of it (this is the R05 class, and the reason for
the "git event signed-identity" rule the code already carries).

**B2: Registry ↔ consumer.** The consumer pulls a bundle plus registry metadata over a network it
does not control. Everything received here is attacker-influenceable until the ed25519 chain and
the revocation floor have been checked. The pull is gated in stages ("gate 5" is the revocation
gate); a stale or replayed view of the registry is a first-class threat (R03/R04).

**B3: CI / build.** For first-party releases, the build boundary is covered by the supply-chain
guarantees in SECURITY.md (keyless cosign over checksums, SLSA L3 for the `skillctl/v*` line,
ed25519 fallback on `SHA256SUMS`, pinned bootstrap). This model does not re-derive those; it
assumes them and focuses on what the *verifier* does with the artefacts they produce.

**B4: The offline verifier.** The single most important boundary. Given a bundle, the trust roots,
and whatever local revocation state exists, it must decide *admit / deny* with no network and no
hosted CA. Its inputs are the trust roots (A5) and the signed artefacts; its guarantee is
fail-closed. `verify-hook` is the Claude Code trust gate that runs this decision inline before a
skill is allowed to act.

**B5: The local install root.** Crossing from "verified bundle" to "files on disk" (A6). Even a
correctly-signed bundle from a correctly-trusted author is hostile *input to an extractor*: paths,
symlinks, and compression ratios are all attacker-chosen within the bundle. This boundary is
defended by the extraction hardening (R02, R07).

---

## 3. Attackers & assumptions

We reason about the following adversaries. Each row states what we assume they can do and, as
importantly, what we assume they **cannot** do, because an honest threat model is precise about
its own limits.

| Adversary | Can | Cannot (assumed) |
|-----------|-----|------------------|
| **Compromised / malicious registry** | Serve any bytes, any metadata, any `status`; withhold or replay; relabel OCI annotations; rename Git objects; present a stale revocation HEAD. | Forge an author's or the registry's ed25519 signature without the private key; produce a signed revocation that lowers the monotonic epoch floor. |
| **Compromised author account (no key)** | Publish under the author's registry account; push metadata. | Sign as the author without A3. (If the *key* is also stolen, see below.) |
| **Author with a stolen signing key (A3)** | Sign arbitrary bundles as that identity until revoked. | Evade a **signed, fail-closed revocation** once it is issued and reaches the consumer (R01). This is the containment mechanism for key theft. |
| **Compromised CI** | Influence a first-party build. | Out of scope for the runtime chain: covered by B3 / SECURITY.md (keyless, in-job self-verification, SLSA L3). Called out as a residual in §5. |
| **Malicious skill author (fully legitimate identity)** | Ship a signed skill that *does* something harmful within its declared capabilities; declare broad `data_dependencies`. | Escape the extractor sandbox (R02/R07); be admitted from an untrusted registry (R11); act after tenant/data-source denial or revocation (R11/R01). Note: a signed-but-malicious skill's *behaviour* is a governance/attestation problem (independent review, `governance_minimum`), not something signature-checking alone solves. |
| **Malicious reference data** | Supply hostile inputs a skill later consumes (crafted archives, oversized payloads, traversal paths inside a bundle). | Cause writes outside the install root or unbounded resource use: bounded by R02/R07. Content-level trust of *reference data a skill fetches at runtime* is the skill's responsibility, not skillctl's; noted in §5. |
| **Network / passive carrier** | Drop, delay, replay, or reorder. | Downgrade the offline verdict: the check does not depend on reachability, and staleness is caught by the epoch floor (R03/R04/R12). |

**Custody assumption (A3).** Private signing keys are held by their owners outside this repo
(keygen writes `*.priv`/`*.pub`; the private half never enters a bundle or the registry). We assume
standard OS-level key custody. The system's answer to *custody failure* is revocation, not
prevention, which is why R01/R04/R05 (revocation must be fail-closed, monotonic, and unforgeable
from unsigned data) carry so much of the model's weight.

**No-hosted-CA assumption.** The verification path contains no mandatory online authority. This is
a deliberate design property (sovereignty + availability), and it shapes the threat model: there is
no revocation *server* to phone, so revocation must travel as **signed, offline, monotonic** state
that the consumer already holds or pulls and re-verifies (R03/R04/R05/R12).

---

## 4. Threat register (R01–R12)

Each row: the threat, the mitigation in the code, and the **covering test(s)**, function name and
file, that exercise it, or an explicit **GAP**. The mapping was inventoried against the tree and
spot-checked by grep; every test named below was confirmed present at authoring time.

### R01: Revocation must be fail-closed

**Threat.** A key or a skill goes bad; an attacker (or the registry) tries to keep a revoked bundle
or author installable: by withholding the revocation, by serving a bundle whose digest is on the
revocation list, or by presenting a revoked author identity as still valid. Absence of a revocation
must **not** be read as permission.

**Mitigation.** Revocation is checked at every trust decision and fails closed: a revoked digest is
refused by the verifier; the Claude Code gate denies a revoked bundle; the pull rejects a revoked
bundle at the revocation gate ("gate 5"); an install against a revoked author identity exits `17`
(`RevokeIdentityRevoked`) and names the revocation in stderr for audit correlation.

**Covering tests.**
- `TestVerifyBundle_RevokedDigest`: `cmd/skillctl/verify_bundle_test.go`
- `TestVerifyHook_RevokedBundle_Denied`: `cmd/skillctl/revoked_cache_test.go`
- `TestPullBundles_Revoked_RejectsAtGate5`: `pkg/skillctl/registry/er1_pull_test.go`
- `TestInstall_RevokedAuthor_Exit17`: `cmd/skillctl/install_e2e_test.go`

### R02: Path traversal / symlink escape on install

**Threat.** A bundle (or a Git-backed registry tree) contains entries that, when extracted, write
outside the install target directory (A6), via `../` traversal, absolute paths, or symlinks that
redirect a later write onto an attacker-chosen location.

**Mitigation.** Extraction refuses traversal and absolute paths, refuses symlink entries, and
canonicalises paths (resolving symlinks) before any write, so a resolved path that escapes the
root is rejected. The Git backend applies the same rejection to object paths.

**Covering tests.**
- `TestInstall_TarPathTraversal_Refused`: `pkg/skillctl/install/install_test.go`
- `TestExtractSkb_SymlinkRefused`: `pkg/skillctl/registry/install_trust_mode_test.go`
- `TestGitPathTraversalRejected`: `pkg/skillctl/backend/git/git_test.go`
- `TestCanonicalPath_ResolvesSymlink`: `pkg/skillctl/install/canonical_path_test.go`

### R03: Replay of a stale trusted view

**Threat.** The carrier re-serves a previously-valid, now-stale artefact (an old registry HEAD, an
old attestation, a replayed invocation-trail entry) to roll the consumer back to a moment before a
revocation or a governance downgrade.

**Mitigation.** Pull rejects a replayed/stale revocation HEAD via an epoch floor; the invocation
trail detects replay on read; governance verification refuses a replayed attestation.

**Covering tests.**
- `TestPullBundles_ReplayedStaleHead_RejectedByEpochFloor`: `pkg/skillctl/registry/er1_pull_revoke_head_test.go`
- `TestReadAndVerifyTrail_DetectsReplay`: `cmd/skillctl/invocation_trail_test.go`
- `TestGovernance_ReplayedAttestationRefused`: `pkg/skillctl/verify/governance_signed_test.go`

### R04: Rollback / epoch non-monotonicity

**Threat.** An attacker presents *older* signed state (a lower revocation epoch, an earlier
version) as current: a downgrade that un-revokes or reintroduces a vulnerable version. Distinct
from R03 (a verbatim replay) in that the values may be genuinely-signed-but-old.

**Mitigation.** The revocation epoch is enforced monotonic (a lower epoch is refused); emergency
rollback to a lower epoch is refused; install refuses a version downgrade; and version ordering
itself is proven monotonic in the semver layer.

**Covering tests.**
- `TestEmergency_RollbackEpochRefused`: `pkg/skillctl/verify/emergency_test.go`
- `TestCheckEpochMonotonic`: `pkg/skillctl/registry/revocation_head_test.go`
- `TestInstall_RefusesDowngrade`: `pkg/skillctl/registry/install_trust_mode_test.go`
- `TestMonotonicity`: `pkg/skillctl/semver/semver_test.go`

### R05: Revocation bypass via unsigned carrier projection / relabel

**Threat.** The carrier's *unsigned* metadata (an OCI annotation, a Git filename/dir name, a raw
JSON `status`) is trusted as if it were signed, letting an attacker relabel or suppress a revoked
bundle: a signed revoke gets hidden behind a friendly annotation, or an unsigned "revoked list"
forges the floor. This is the systemic "projection ≠ proof" class.

**Mitigation.** Trust identity (Kind/Digest, revoked-by, bundle-digest) is read from the **signed
envelope**, not from the carrier's projection: an OCI annotation relabel is defeated; the revoked
floor cannot be forged via unsigned JSON; an unsigned revoke does not suppress installation.

**Covering tests.**
- `TestOCIAnnotationRelabelDefeated`: `pkg/skillctl/backend/oci/oci_test.go`
- `TestRevokedFloor_UnforgeableViaUnsignedJson`: `cmd/skillctl/kill_switch_hardening_test.go`
- `TestPullBundles_UnsignedRevoke_DoesNotSuppress`: `pkg/skillctl/registry/er1_pull_test.go`

### R06, TOCTOU (verify-then-use race), **covered**

**Threat.** A time-of-check-to-time-of-use gap: the bytes that are *verified* differ from the bytes
that are *used* because the artefact is swapped on disk between the digest check and the read, or
the extracted tree is mutated after verification but before execution.

**Status: covered.** `TestVerifyThenUse_MutatedAfterVerify_RechecksAndFailsClosed`
(`pkg/skillctl/install/offline_verify_test.go`) closes the window: verify PASSES on a pristine
extraction (time-of-check), then the on-disk tree is mutated three ways: edit-a-byte, swap the
whole file (atomic `rename` over the verified inode), and **repoint a verified regular file to a
symlink pointing outside the tree** (a vector no earlier test covered), and each *subsequent* call
(time-of-use) re-reads + re-hashes and fails closed with `ErrDigestMismatch`. The seam
`verifyExtractedMatchesBlob`, on the hot per-invocation gate path (`verify_hook_cmds.go` →
`VerifyInstalledOffline`/`VerifyInstalledSidecar`), is **stateless**: it caches no verdict and
reuses no check-time handle between check and use, so the verified bytes ARE the used bytes. A
negative control (drop the mutation → the subtest fails) confirms the test bites. The complementary
verdict-cache reuse path is covered by `TestVerdict_TamperedFile_MissesCache`.

### R07: Archive bomb (size / count exhaustion)

**Threat.** A signed-but-hostile bundle expands to exhaust disk or memory (a gzip/decompression
bomb, or an archive with pathologically many entries) turning install into a denial of service.

**Mitigation.** Extraction enforces a decompression-size ceiling and a file-count ceiling and aborts
when either is exceeded, before the bytes are committed.

**Covering tests.**
- `TestInstall_GzipBomb_Refused`: `pkg/skillctl/install/install_test.go`
- `TestExtractSkb_OversizedAborts`: `pkg/skillctl/registry/install_trust_mode_test.go`
- `TestExtractSkb_TooManyFilesAborts`: `pkg/skillctl/registry/install_trust_mode_test.go`

### R08: Signature tamper

**Threat.** A bundle, a revocation HEAD, or a signed event envelope is modified after signing and
served in the hope the modification slips past verification.

**Mitigation.** ed25519 verification rejects any post-signing modification: a tampered signed
envelope fails `EnvelopeVerify`; a detached-signed bundle whose bytes changed fails verification;
a tampered revocation HEAD is detected.

**Covering tests.**
- `TestEnvelopeVerify_TamperedAfterSign`: `pkg/skillctl/registry/event_test.go`
- `TestVerifyDetached_TamperedBundle`: `pkg/skillctl/signing/verify_test.go`
- `TestRevocationHead_TamperDetected`: `pkg/skillctl/registry/revocation_head_test.go`

### R09: Wrong-key / impersonation (exit 11)

**Threat.** An artefact is signed by a key that is *not* the claimed identity's key: an
impersonation attempt, or a bundle signed with the wrong key served as if authentic.

**Mitigation.** A signature that does not verify against the identity's pinned public key is refused
with exit `11` (`ExitAuthorSigInvalid`), distinct from the revocation exit (`17`) and the
digest-mismatch exit (`10`) so callers can branch precisely. `agentid` mandates enforce the same
rule for agent identities.

**Covering tests.**
- `TestAgentID_WrongKeyExit11`: `cmd/skillctl/agentid_cmds_test.go`
- `TestInstall_BadAuthorSig_Exit11`: `cmd/skillctl/install_e2e_test.go`
- signing **AC5** (sign with key A → verify with key B → exit 11), inside `TestEndToEnd`: `cmd/skillctl/signing_cmds_test.go`

### R10, Credential leakage, **covered**

**Threat.** A signing key, a Git credential, or another secret is exposed: most dangerously through
an error message, a log line, or persisted state that a later reader can harvest.

**Mitigation (what is proven).** Signing does not leak the private key in its error output; the Git
backend does not leak credentials in its output.

**Status, covered.** `TestNoSecretAtRest_PersistedArtifacts` (`cmd/skillctl/threat_r10_test.go`)
drives a full secret-handling cycle producing the three durable artefacts A7 names, the
device-signed invocation trail, the HMAC-signed verdict cache, and the ed25519-signed
transparency-log head/STH, then sweeps EVERY file skillctl wrote for the three secrets (the device
signing-key seed, the verdict HMAC key, the translog signing key) in 7 encodings (raw, hex, base64
variants), asserting none appears: only the secrets' own `0600` key files are excused. A positive
control (a key IS found in its own key file) plus a negative control (a planted seed is detected)
prove non-vacuity. The artefacts carry only public identifiers (KeyID) + detached signatures.

**Covering tests.**
- `TestNoSecretAtRest_PersistedArtifacts`: `cmd/skillctl/threat_r10_test.go` (no secret at rest)
- `TestSignBundle_DoesNotLeakKeyInError`: `pkg/skillctl/signing/sign_test.go` (error-path)
- `TestGitCredNoLeak`: `pkg/skillctl/backend/git/git_test.go` (error-path)

### R11: Malicious / unsigned admission rejected

**Threat.** A skill from an untrusted registry, or one that a policy gate should block, is admitted
anyway, including the failure mode where the *gate itself* errors or panics and "fails open".

**Mitigation.** An install from a registry not in the trust roots exits `12`
(`ExitRegistryNotTrusted`); the Claude Code gate blocks an unmanaged-policy deny; and a **panic
inside a gate fails closed to deny**, not open: the single most important property of a trust gate.

**Covering tests.**
- `TestInstall_UntrustedRegistry_Exit12`: `cmd/skillctl/install_e2e_test.go`
- `TestVerifyHook_UnmanagedPolicyDeny_Blocks`: `cmd/skillctl/verify_hook_cmds_test.go`
- `TestVerifyHook_PanicInGate_FailsClosedDeny`: `cmd/skillctl/verify_hook_cmds_test.go`

### R12: Offline verification (no network / no hosted CA)

**Threat.** The verifier is coerced into needing an online authority, so an attacker who controls
the network (or simply takes the authority offline) can force a "can't check → allow" downgrade, or
just deny availability.

**Mitigation.** The trust-chain check reaches a verdict with no network and no hosted CA in the
path: `agentid` issues and verifies mandates offline; the Claude Code gate is offline-first and
still **denies** a bad signature with no network; translog receipts round-trip verify offline.

**Covering tests.**
- `TestAgentID_IssueVerifyOffline`: `cmd/skillctl/agentid_cmds_test.go`
- `TestVerifyHook_OfflineFirst_DeniesBadSig`: `cmd/skillctl/verify_hook_cmds_test.go`
- `TestReceipt_VerifyOfflineRoundTrip`: `pkg/skillctl/translog/receipt_test.go`

---

## 5. Residual risks & gaps

The register lists a few risks that are structurally out of `skillctl`'s reach; we call them out so
nobody reads a covered row and assumes the whole surface is covered.

**Recently closed**: the model's two former test gaps are now covered (see the register above):
- **R06** (verify-then-use race) → `TestVerifyThenUse_MutatedAfterVerify_RechecksAndFailsClosed`
  (mutate-after-verify: edit / file-swap / symlink-repoint, each re-checked + fail-closed).
- **R10** (secret at rest) → `TestNoSecretAtRest_PersistedArtifacts` (sweeps trail + verdict cache +
  translog/STH for the device / verdict-HMAC / translog keys in 7 encodings).

**Structural residuals (defended elsewhere or by design, not by this register):**

- **Signed-but-malicious skill behaviour.** A legitimately-signed skill can still do harm *within*
  its declared capabilities. Signature-checking proves *who* and *unmodified*, not *safe*. The
  brakes here are governance, independent review (`require_independent_review`),
  `governance_minimum`, tenant/data-source denial (exits 16/17), not the signature chain. Treat
  the trust chain as authenticity, and governance as safety.

- **Runtime reference data a skill fetches itself.** Content trust of data a skill pulls *at run
  time* (beyond the bundle's own contents, which R02/R07 bound) is the skill's responsibility, not
  skillctl's. `data_dependencies` declare the surface; they do not sanitise it.

- **CI / build compromise (B3).** Covered by the release supply chain (keyless cosign + in-job
  self-verification + SLSA L3 + pinned bootstrap) in [SECURITY.md](SECURITY.md), not re-proven
  here. A compromise of the first-party build is a supply-chain event, addressed on that plane.

- **Trust-root & local-state ACLs (A5/A7 at rest).** The verifier trusts whatever
  `skill-trust-roots.yaml` says; if an attacker can *write* that file (or the local caches), they
  move the root of trust. Filesystem ACLs on those paths are an OS-level control this model assumes
  and does not itself enforce; platform-specific hardening (e.g. Windows ACLs on trust-root/cache
  paths) is tracked in the security reviews, not here.

- **Key custody (A3).** Prevention of private-key theft is out of scope; the system's response to
  it is revocation (R01/R04/R05). The strength of that response is what the register measures.

---

## 6. Keeping the model live

These threat IDs are only useful if they stay wired to the code. The intended convention is a
one-line comment at the covering test, so a reader (or a future audit script) can walk from a
threat to its proof and back:

```go
// THREAT-R05: an unsigned OCI annotation relabel must not suppress a signed revoke.
func TestOCIAnnotationRelabelDefeated(t *testing.T) { ... }
```

Guidance:

- When you add or move a covering test, update its `THREAT-Rxx` comment and this register together
. The map is only as good as its last edit.
- When you **close a gap** (R06 or R10), replace the GAP/THIN note here with the new test's
  name + file, and add the matching `THREAT-Rxx` comment at the test.
- When you add a *new* threat class, extend the register (`R13`, …) rather than overloading an
  existing row: the IDs are stable references.
- The mapping in §4 was inventoried against the tree and spot-checked by grep at authoring time; a
  periodic `grep -rn 'THREAT-R' ` sweep against this register is the cheapest way to catch drift.

A threat model that isn't cited from the tests rots into fiction. Cite it.

# Trust Freeze release evidence

What a platform may claim about Trust Freeze, and what backs the claim. The levels are separate statements
and never collapse into one word such as "supported" (SPEC-0471, TF06-R6 and TF06-R7):

| Level | Meaning |
|---|---|
| `implemented` | the code path exists for that platform |
| `fixture-tested` | its parsers and decisions are covered by table tests and fixtures, runnable on any host |
| `cross-compiled` | `go vet` is clean and the test binaries link for that target, nothing was executed there |
| `real-platform-tested` | the test binaries and the acceptance path really ran on that platform, tied to a commit |

Cross-compilation is not a platform test. A run against an earlier commit does not prove a later one.

`release-matrix.json` records, per ROUND and per platform, what actually ran for a given commit: the unit-test
totals, the acceptance script result, the cross-machine verifications, and for a round with real captures the
probe outcomes and what the runs found. It carries no host names, addresses or user names: a bundle does record
the host it describes, but this evidence file does not.

A round also lists `defects_found_by_these_runs`. That list is the argument for running on real hosts at all: the
T-03 round found six defects that 49 fixtures and three review passes had not, among them a redaction marker that
broke colon separated records and dropped the root account from the bundle.

Scope of the two rounds recorded today: T-01 is the walking skeleton (the `common.identity` probe plus the
bundle lifecycle). T-03 adds the nine Linux probes and the `ubuntu-bastion` profile, executed on two real Ubuntu
hosts, one of them a bastion. TF06-AC1 (a real Linux run of the required probes) is therefore claimed for the
Linux round; TF06-AC2 (Windows and WSL) and TF06-AC3 (macOS probe families) are NOT, because those probe
families do not exist. TF06-AC4 (cross-machine verification) is claimed for both rounds.

T-03b adds the three probes the T-03 rounds did not have: `linux.network.routes`, `linux.dns` and
`linux.executables`, and raises `ubuntu-bastion` to version `3`, whose required list is now the full list of
SPEC-0471 TF06-R3. Two consequences, and neither of them is a claim about a run:

- What this file says about a real run of the three new probes is decided by the round entry in
  `release-matrix.json`, not by this paragraph. Until such an entry exists for them, their evidence levels are
  `implemented`, `fixture-tested` and `cross-compiled`, and nothing more. The fixtures they were measured
  against were read on two real Ubuntu hosts, which is provenance for the fixtures and not a platform test of
  the probes. The `scope` text of the T-03 round in `release-matrix.json` still says that routes, DNS and
  executable hashes are not implemented. That is left as it stands on purpose: a round entry names its commit
  (`744d015`) and is a record of what was true there, so it is superseded by a later round, never edited.
- A host whose last capture was `complete` against `ubuntu-bastion` version `2` is `incomplete` against version
  `3` until the three new probes have run there. That is not a regression in the host and not one in the tool: a
  wider question cannot make an older answer more complete. The remedy is a new capture and a new approval, and
  the completeness gap names each probe that has not run.

Regenerate by running, on each platform, `go test -count=1 ./pkg/skillctl/trustfreeze/... ./cmd/skillctl/` and
`./scripts/trustfreeze-acceptance.sh` against a clean checkout of the commit, then update the entry by hand.

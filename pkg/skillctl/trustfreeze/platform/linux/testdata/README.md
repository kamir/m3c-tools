# Linux probe fixtures (SPEC-0471 TF06-R3)

## Source class

Every file under this directory is **transcribed from a real host and sanitized**, with one named
exception below. Nothing here was invented, and nothing here is a live capture.

Most of it came off one trial host on 2026-09-23 through read-only commands, and then went through
the substitutions listed below. Three files came off a **second real host on the same day**, an
Ubuntu 22.04 bastion where `docker` is installed as a **snap** (it answers only at
`/snap/bin/docker`) and where the daemon **socket refuses an unprivileged caller** because the
account is not in the group `docker`. Those three are
`containers/docker-version-snap.txt`, `containers/docker-ps-socket-denied.stderr.txt` and
`containers/docker-info-socket-denied.stderr.txt`; they carry `"host": "ubuntu-22.04-bastion"` in
`commands.json` and are byte for byte what the host printed, with nothing to substitute (no account
name, no host name and no address occurs in them). They are the two shapes the trial host could not
produce, and the first of them is why the runner search path now includes `/snap/bin`.

Two further files came off a **third real host**, an Ubuntu 22.04 bastion read during an **elevated**
run on the same day: `systemd/systemctl-show-template.stderr.txt` and
`systemd/systemctl-show-batch-aborted.txt`. They carry `"host": "ubuntu-22.04-bastion-elevated"` in
`commands.json`. The first is that host's stderr line, byte for byte. The second is the **one
composed file in this tree**: its SHAPE was measured on that host (a `systemctl show` call for
several units answers for the units before a name the manager refuses, prints nothing for the names
after it, and exits 1), its BYTES are two measured property blocks of the trial host, because the
bastion's property values were never transcribed and the probe asks for a different property set
than the reproduction did. Its `commands.json` entry says which half is which, and it is the only
file here whose bytes are not a host's.

That host carries 180 unit files, 33 of them templates, and it is where the batch abort cost one
capture the runtime state of 47 units.

The two hosts of the first two paragraphs were read as an ordinary, unprivileged user. No command elevated, wrote, installed,
started or stopped anything (playbook L2). That is why several fixtures are refusals rather than
data, and that is the point: the refusals are the shapes the probes have to survive.

Host class, so a parser author knows what the fixtures are valid for:

| Property | Trial host (all fixtures but three) | Bastion (the three named above) |
|---|---|---|
| Distribution | Ubuntu 24.04.1 LTS | Ubuntu 22.04 LTS |
| Kernel release | 6.17.0-35-generic | not recorded |
| Architecture | amd64 | amd64 |
| Privilege of the capture | unprivileged account, member of the groups `sudo` and `docker` | unprivileged account, NOT in the group `docker` |
| Container runtime | docker from the distribution package | docker from a snap, at `/snap/bin/docker` |
| Scale | 1879 dpkg packages, 516 unit files, 51 listeners, 113 mount points, 20 running containers | not measured: the socket refused every listing |

## Tool versions

A parser is only valid for the versions it was measured against (playbook L7). These are the
versions that produced the fixtures:

| Tool | Version | Fixture |
|---|---|---|
| `dpkg-query` | 1.22.6 (amd64) | `packages/dpkg-query-version.txt` |
| `apt-mark` | apt 2.7.14 (amd64) | `packages/apt-mark-version.txt` |
| `snap` / `snapd` | 2.76.3 | `packages/snap-version.txt` |
| `getent` | Ubuntu GLIBC 2.39-0ubuntu8.9 | `users/getent-version.txt` |
| `id` | GNU coreutils 9.4 | `users/id-version.txt` |
| `sshd` | OpenSSH_9.6p1 Ubuntu-3ubuntu13.19, OpenSSL 3.0.13 | `ssh/sshd-version.stderr.txt` |
| `systemctl` | systemd 255 (255.4-1ubuntu8.17) | `systemd/systemctl-version.txt` |
| `ss` | iproute2-6.1.0 | `network.listeners/ss-version.txt` |
| `ufw` | 0.36.2 | `firewall/ufw-version.txt` |
| `nft` | nftables v1.0.9 | `firewall/nft-version.txt` |
| `findmnt` | util-linux 2.39.3 | `mounts/findmnt-version.txt` |
| `docker` (trial host, deb) | 27.5.1, build 9f9e405 | `containers/docker-version.txt` |
| `docker` (bastion, snap) | 29.8.0, build 88096ef | `containers/docker-version-snap.txt` |
| `podman` | not installed | `honest-status/tool-missing-command-v-podman.txt` |
| `flatpak` | not installed | not fixtured, `command -v` behaves like podman |

## Environment of every capture

`LC_ALL=C`, with `LANG` and `LANGUAGE` removed. That is the environment `probe.ExecRunner` builds
(the variable allowlist plus `LC_ALL=C` and `TZ=UTC0`), so the fixtures show what a probe actually
receives. One fixture deliberately breaks the rule and says so in its entry:
`packages/snap-list-localized.txt` was taken with `LANG=de_DE.UTF-8` inherited, because `snap list`
translates its header words and re-computes its column widths. Two fixtures of the same command at
the same moment, different bytes. A parser that keys on header text or on fixed column offsets is
wrong, and this pair is how a test proves it.

## commands.json

`commands.json` is the machine readable index. One entry per fixture:

```
path                   fixture path relative to this directory
probe                  probe id the fixture belongs to (null for the cross cutting ones)
command                argv exactly as it was run, executable first, no shell
probe_command          argv the probe issues, where it differs from the one above; absent when they are the same
stream                 stdout or stderr: which stream the file holds
exit_code              the exit code of that run
expected_probe_status  the honest status the probe should report for this input
transcribed_lines      lines in the fixture
source_lines           lines in the untouched host output (differs where a subset was kept)
note                   what the fixture is for, and the trap it carries
```

`command` stays what was run on the host: it is a record of a measurement and is never edited to
match the code. Three fixtures were taken with an argv the probes do not issue (`findmnt --json`
without the column selection, and `sshd` through its absolute path), and those entries carry
`probe_command` beside it. The tests script the fake runner under `probe_command` where it exists
and under `command` otherwise, so a probe that changes its call fails a test instead of passing
quietly.

The fixtures themselves carry no header: a parser has to read them byte for byte as the tool
produced them, so provenance lives here and in `commands.json` instead of in the files. Five
fixtures are zero bytes long on purpose; they are the genuinely empty results, and their exit codes
(0, 1 and 2, all three occur) are in `commands.json`.

## Sanitization rules

Applied to every file. The rule is: change identity, keep shape. Column counts, field separators,
record order, padding widths, exit codes, streams and message wording are untouched.

| Real value | Replacement |
|---|---|
| the interactive account (uid 1000, gid 1000) | `alice`, home `/home/alice` |
| its GECOS full name | `Alice Example` |
| the service account (uid 1001, gid 1001) | `deploy`, home `/home/deploy` |
| a locally built daemon seen in the `ss` process column | `svc-app-exporte` (15 characters, so the comm truncation stays visible) |
| the host name | `host-a`, in FQDN position `host-a.example` |
| the one routable IPv4 in the material (a container registry) | `203.0.113.10` |
| container ids (64 hex) | synthetic 64 hex, one per row, equal values stay equal |
| an image digest (`sha256:` plus 64 hex) | one synthetic 64 hex, shared by the two rows that shared it |
| overlay2 layer ids and their `l/` short link names | synthetic, same lengths, one per distinct original |
| docker network namespace ids (12 hex) | synthetic 12 hex |
| registry organisation and product names in image references | `example/` plus a generic component name |
| container names built from product names | `app-*` and `svc-app-*` |
| a self-hosted runner unit name | `actions.runner.alice-m3c-tools.host-a.service`, padded back to the original column width |

IPv6: the rule is `2001:db8::`, but no routable IPv6 address appears anywhere in this material, so
no IPv6 substitution was needed.

Never collected, and therefore absent by construction: private key material, public key bodies and
fingerprints, `authorized_keys` content, password hashes, tokens, and the contents of any file the
account was not allowed to read. `/etc/shadow` was not touched at all (playbook L4).

Two fixtures are shortened rather than substituted: `users/getent-version.txt` and
`users/id-version.txt` keep only the first line. The dropped lines are GPL boilerplate that names
the upstream authors, and a real person's name has no business in a fixture. The first line is the
line a version parser reads.

### What was deliberately NOT changed

- `127.0.0.1`, `127.0.0.53`, `127.0.0.54`, `0.0.0.0`, `::`, `::1`, `*`. These are the substance of
  the listener probe: a listener on `0.0.0.0` or `::` is exposure, one on loopback is not. Rewriting
  them would destroy the only fact the fixture carries.
- Port numbers. Same reason, and they identify no one.
- Uid and gid 1000 and 1001, group ids, file modes, sizes and timestamps.
- Volatile values: `pid=2698` in the `ss` line, `Up 2 weeks (healthy)` in `docker ps`, the
  `start_time`, `stop_time`, `pid`, `code` and `status` fields inside a systemd `ExecStart`, and
  nsfs inode numbers. They stay so that the normalization rule set (playbook L8) has something real
  to prove itself against.
- Public image names (`grafana/grafana`, `moby/buildkit`, `kindest/node`, `gitlab/gitlab-ce`,
  `confluentinc/cp-kafka`) and public package names. They name software, not a person or a site.

### Verification

After writing, the tree was searched for the real account name, the real full name, the real host
name and the one routable address that appeared in the material. No hit. `bash tools/boundary-gate.sh`
and `./scripts/check-no-real-names.sh` are green. The originals are not repeated here, because
writing them down would undo the substitution; whoever repeats the check fills them in from the
trial host:

```bash
grep -rniE "$REAL_ACCOUNT|$REAL_HOSTNAME|$REAL_IPV4" \
  pkg/skillctl/trustfreeze/platform/linux/testdata/
```

## Fixtures per probe

### linux.packages

| Fixture | What it shows |
|---|---|
| `packages/dpkg-query-w.txt` | 51 of 1879 packages in the host's order, both architectures (`all`, `amd64`), both status abbreviations (`ii `, `rc `), epoch versions, multiarch names such as `zlib1g:amd64`. The trailing space of the three character status field is real. |
| `packages/dpkg-query-w-unknown.stderr.txt` | named package absent: stderr diagnostic, exit 1 |
| `packages/apt-mark-showmanual.txt` | all 82 manually installed packages, one per line |
| `packages/snap-list.txt` | 24 snaps under `LC_ALL=C` |
| `packages/snap-list-localized.txt` | the same call with `LANG` inherited: other header words, other column widths |
| `packages/dpkg-query-version.txt`, `apt-mark-version.txt`, `snap-version.txt` | tool versions |

### linux.users

| Fixture | What it shows |
|---|---|
| `users/getent-passwd.txt` | all 53 accounts, colon separated, including empty GECOS fields, GECOS fields with trailing commas, and `nologin` or `false` shells |
| `users/getent-group.txt` | all 81 groups, including empty member lists and multi member lists |
| `users/getent-group-sudo-docker.txt` | two keys in one call, the privilege relevant pair |
| `users/id.txt` | the capturing account: `sudo` and `docker` membership, two privilege capabilities from one line |
| `users/id-service-account.txt` | an account with no supplementary groups |
| `honest-status/empty-result-getent-unknown-user.txt` | unknown key: empty stdout, exit 2 |
| `users/getent-version.txt`, `users/id-version.txt` | tool versions, first line |

### linux.sudo

| Fixture | What it shows |
|---|---|
| `sudo/ls-la-etc-sudoers-d.txt` | the drop-in directory is 0755, so names, modes, owners and sizes are observable, and one drop-in is called `alice-nopasswd` |
| `sudo/stat-sudoers.txt` | modes and owners of `/etc/sudoers`, the directory and both drop-ins |
| `sudo/cat-etc-sudoers.stderr.txt` | 0440 root:root: `permission_denied`, exit 1, stdout empty |
| `sudo/cat-etc-sudoers-d-entry.stderr.txt` | same for the drop-in whose name announces a NOPASSWD rule |

The honest result for this probe on this host is a `permission_denied` with the structure still
recorded: two rule files exist, one of them is named after a user and is 29 bytes long, and the rule
text is not observable. A silent empty rule list would be a lie.

### linux.ssh

| Fixture | What it shows |
|---|---|
| `ssh/sshd_config.txt` | the declared state, 3257 bytes, byte for byte, leading and trailing empty lines included. Carries `PasswordAuthentication yes` and `PermitEmptyPasswords yes`, an `Include /etc/ssh/sshd_config.d/*.conf`, a tab separated `AuthorizedKeysFile` comment and a commented `Match User` block |
| `ssh/ls-la-etc-ssh.txt` | nine `sshd_config.backup-*` files and one `.ucf-dist` beside the active file, plus the host key files whose contents were never read |
| `ssh/ls-la-sshd-config-d.txt` | the include directory is genuinely empty: `captured` with an empty list |
| `ssh/sshd-T-unprivileged.stderr.txt` | the effective state is not observable unprivileged: `sshd: no hostkeys available -- exiting.`, exit 1, stdout empty |
| `ssh/sshd-version.stderr.txt` | `sshd -V` writes to STDERR and exits 0 |

Declared stays declared (playbook L3). This host cannot produce an `observed` SSH state at all.

### linux.systemd

| Fixture | What it shows |
|---|---|
| `systemd/systemctl-list-unit-files.txt` | 55 of 516 unit files in the host's order, all nine state values that occur here, and every unit type. Column two begins at byte 79 |
| `systemd/systemctl-show-enabled-running.txt` | enabled and running |
| `systemd/systemctl-show-disabled.txt` | disabled and dead, `ConditionResult=no` |
| `systemd/systemctl-show-local-unit.txt` | a locally added unit under `/etc/systemd/system` running as a human account |
| `systemd/systemctl-show-unknown-unit.txt` | a unit that does not exist: exit 0, all properties present and empty, `LoadState=not-found` |
| `honest-status/empty-result-systemctl-no-match.txt` | pattern matches nothing: empty stdout, exit 1 |
| `systemd/systemctl-show-template.stderr.txt` | a TEMPLATE unit name refused, from the elevated Ubuntu 22.04 bastion: one stderr line, exit 1 |
| `systemd/systemctl-show-batch-aborted.txt` | the stdout half of that abort: the blocks that arrived before the refused name, nothing after it. Composed, see above |
| `systemd/systemctl-version.txt` | version plus the feature flag line |

Four traps live here. `systemctl show` returns the properties in systemd's order, not in the order
asked for, and it answers a question about a nonexistent unit with exit 0. A TEMPLATE unit
(`getty@.service`, an empty instance part) is not a nonexistent unit and not an unknown one: the
call is refused outright. And that refusal is not local to the bad name; the call STOPS there, so
every name after it in the same argument vector goes unanswered. Batching a hundred units into
calls of forty therefore loses a whole batch per template. `linux.systemd` reads the template from
the name grammar and never asks about one, and asks again, one name at a time, for whatever an
aborted call left unanswered.

### linux.network.listeners

| Fixture | What it shows |
|---|---|
| `network.listeners/ss-H-lntup.txt` | all 51 listeners, UDP and TCP, `0.0.0.0`, `127.0.0.1`, `127.0.0.53%lo`, `[::]`, `[::1]` and `*`, with variable column count |
| `honest-status/empty-result-ss-no-match.txt` | filter matches nothing: empty, exit 0 |
| `network.listeners/ss-version.txt` | tool version |

The decisive property: unprivileged, `ss -p` fills the `users:((...))` column only for the caller's
own processes. Exactly one of the 51 rows has seven fields, the other 50 have six. The honest status
is `partial` with a diagnostic naming the missing owner information, never `captured`.

### linux.firewall

| Fixture | What it shows |
|---|---|
| `firewall/ufw-status.stderr.txt` | `ERROR: You need to be root to run this script`, exit 1 |
| `firewall/nft-list-ruleset.stderr.txt` | two stderr lines, cause first, exit 1 |
| `firewall/nft-json-list-ruleset.stderr.txt` | the `--json` form fails identically and emits no JSON, so the exit code has to be checked before decoding |
| `firewall/ufw-version.txt`, `firewall/nft-version.txt` | tool versions |

Both tools are installed. `unavailable` would be false here; the truthful status is
`permission_denied`, and the firewall state of this host is simply not knowable from an
unprivileged capture.

### linux.mounts

| Fixture | What it shows |
|---|---|
| `mounts/findmnt-json.json` | 25 of 113 mount points as a pruned subtree, with `findmnt`'s own formatting: three space indentation, the `},{` sibling form, key order `target, source, fstype, options, children` |
| `mounts/findmnt-version.txt` | tool version |

The pruning tool round-tripped the untouched host file byte for byte before it removed anything, so
the formatting in the fixture is the tool's, not a re-serialization. Kept on purpose: an `autofs`
mount and the `binfmt_misc` mount nested under it at the same target path, `nsfs` sources of the
shape `nsfs[net:[4026531833]]`, a `tmpfs` at `/run/user/1000` with `uid=` and `gid=` options, a
`fuse.portal` and a `fuse.gvfsd-fuse` mount, squashfs snap mounts on loop devices, a second block
device at `/home`, and two `overlay` mounts whose `options` carry a twelve element and a four
element `lowerdir` chain.

### linux.containers

| Fixture | What it shows |
|---|---|
| `containers/docker-ps.txt` | 20 running containers, six tab separated fields, including an empty `Ports` field, port ranges, `0.0.0.0` and `[::]` and `:::` publishings, loopback-only publishings, and an image reference pinned by digest |
| `containers/docker-info.txt` | one line, ten tab separated fields, daemon version, storage driver, counts and root directory |
| `containers/docker-ps-empty.txt` | runtime present, no matching container: empty, exit 0 |
| `containers/docker-daemon-unreachable.stderr.txt` | client present, daemon unreachable, exit 1 |
| `containers/docker-version.txt` | client version of the deb package on the trial host |
| `containers/docker-version-snap.txt` | client version of a docker installed as a snap: the binary lives at `/snap/bin/docker`, which the four classic system directories do not contain |
| `containers/docker-ps-socket-denied.stderr.txt` | binary present, socket refused: `permission denied while trying to connect to the docker API at unix:///var/run/docker.sock`, exit 1, stdout empty |
| `containers/docker-info-socket-denied.stderr.txt` | the same refusal from the info call, with an empty line in front of it, so a first-line reader sees nothing and the classification has to read the whole stream |

A format string trap that cost a round of collection: `docker ps --format` expands a literal
backslash-t into a tab, and `docker info --format` does not. The info fixture was therefore taken
with `{{"\t"}}`, a Go template string literal, and `commands.json` records both argv forms exactly.

## Honest status classes

Each class the parsers must be tested against, and the fixture that carries it:

| Class | Fixture | Shape |
|---|---|---|
| tool missing | `honest-status/tool-missing-command-v-podman.txt` | `command -v podman`: empty output, exit 1 |
| tool missing, shell variant | `honest-status/tool-missing-shell-127.stderr.txt` | `bash: line 1: ...: command not found`, exit 127 |
| permission refusal, config file | `sudo/cat-etc-sudoers.stderr.txt` | one stderr line, exit 1 |
| permission refusal, effective state | `ssh/sshd-T-unprivileged.stderr.txt` | one stderr line, exit 1 |
| permission refusal, firewall | `firewall/ufw-status.stderr.txt`, `firewall/nft-list-ruleset.stderr.txt` | one and two stderr lines, exit 1 |
| permission refusal, container socket | `containers/docker-ps-socket-denied.stderr.txt`, `containers/docker-info-socket-denied.stderr.txt` | one stderr line, exit 1; the info variant leads with an empty line |
| partial, privilege dependent column | `network.listeners/ss-H-lntup.txt` | 1 of 51 rows carries the owner column |
| empty result, exit 0 | `containers/docker-ps-empty.txt`, `honest-status/empty-result-ss-no-match.txt` | zero bytes |
| empty result, exit 1 | `honest-status/empty-result-systemctl-no-match.txt` | zero bytes |
| empty result, exit 2 | `honest-status/empty-result-getent-unknown-user.txt` | zero bytes |
| object absent, exit 0 | `systemd/systemctl-show-unknown-unit.txt` | full property set, `LoadState=not-found` |
| object absent, exit 1 | `packages/dpkg-query-w-unknown.stderr.txt` | stderr diagnostic |

The shell variant is recorded to be dismissed, not to be parsed: `probe.ExecRunner` resolves the
executable through `LookPath` and returns `tool_missing` before any process starts, so it never sees
exit 127. A real 127 from a child process means something else and must not be read as absence.

## What this host could not show

Honest gaps in the fixture set, so nobody builds a test on a shape that was never measured:

- **A docker socket the caller may not open.** No longer a gap, and kept here to say where it was
  closed. The trial host cannot produce it (its account is in the group `docker`); the bastion can,
  and `containers/docker-ps-socket-denied.stderr.txt` plus
  `containers/docker-info-socket-denied.stderr.txt` are that host's two refusals. The
  unreachable-daemon shape in `containers/docker-daemon-unreachable.stderr.txt` stays a different
  message, forced with `DOCKER_HOST` pointing at a path that does not exist.
- **podman.** Not installed, so only its absence is fixtured, never its output.
- **An active firewall ruleset.** Both backends refuse unprivileged; no `nft --json` document and no
  `ufw status` table exist in this set.
- **The effective sshd state.** `sshd -T` never succeeded, so there is no `observed` SSH fixture.
- **Sudoers rule text.** Only the structure around the files, never a rule.
- **The `docker inspect` answer.** The container probe asks `docker inspect --format ...` for the
  restart policy and the privileged flag, and that call was never transcribed from the trial host.
  `containers_test.go` builds the answer by hand from the ids of `containers/docker-ps.txt` and says
  so in the test. Until a run on a Linux host records it, the parser of that call is fixture-tested
  against a constructed input, not against a measured one.
- **A snap-less or docker-less host.** Neither measured machine is one, so the "tool not found
  anywhere we looked" path of `linux.packages` and `linux.containers` is covered by the absence of
  podman and flatpak only. That path reports `unavailable` and names the searched directories; it
  never reports `not_applicable`, because a failed lookup cannot tell a host without a runtime from
  a runtime this build did not look in the right place for.
- **A container runtime that is neither docker nor podman.** `containerd` and `crio` are not read at
  all by this build. A host that runs only one of them gets the same `unavailable` with the
  directories named, which is the honest answer and not the complete one.

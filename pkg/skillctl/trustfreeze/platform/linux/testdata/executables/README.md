# Fixtures of `linux.executables` and of the systemd dependency edges

Read with `../README.md`, whose source class, host class, environment and sanitization rules apply
here unchanged. This file adds what is specific to these fixtures, and it is written so that the
entries can be folded into `../README.md` and `../commands.json` without a second measurement.

## Source class

Every file is **transcribed from a real host and sanitized**. Nothing here was invented. The two
hosts, read **read only** on 2026-09-24 as an ordinary account, with no elevation, nothing written,
nothing started or stopped:

| Host class | What it is | Fixture suffix |
|---|---|---|
| Trial host | Ubuntu 24.04.1 LTS, amd64, unprivileged account in the groups `sudo` and `docker` | no suffix |
| Bastion | Ubuntu 22.04.5 LTS, amd64, unprivileged account, `ngrok` and a MinIO client present, snaps mounted under `/snap` | `-2204` |

The bastion is the host the profile is for, and it is the only one that carries the two cases this
probe exists for: a program under `/usr/local/bin` that **is** owned by a package (`mcli`, installed
from a `.deb`), and one that **no package owns** (`ngrok`). Both were measured, neither was staged.

## Tool versions

A parser is only valid for the versions it was measured against (playbook L7).

| Tool | Trial host | Bastion | Fixture |
|---|---|---|---|
| `dpkg` | 1.22.6 (amd64) | 1.21.1 (amd64) | `dpkg-version.txt`, `dpkg-version-2204.txt` |
| `stat` (GNU coreutils) | 9.4 | 8.32 | `stat-version.txt`, `stat-version-2204.txt` |
| `systemctl` | systemd 255 (255.4-1ubuntu8.17) | systemd 249 (249.11-0ubuntu3.22) | `../systemd/systemctl-version.txt` (trial host) |
| `ss` | iproute2-6.1.0 | iproute2-5.15.0 | `../network.listeners/ss-version.txt` (trial host) |

## The argv each fixture came from

| Fixture | argv (no shell, `LC_ALL=C`, `LANG` and `LANGUAGE` removed) | Stream | Exit |
|---|---|---|---|
| `dpkg-version.txt` | `dpkg --version`, first line kept | stdout | 0 |
| `dpkg-version-2204.txt` | same on the bastion, first line kept | stdout | 0 |
| `stat-version.txt` | `stat --version`, first line kept | stdout | 0 |
| `stat-version-2204.txt` | same on the bastion, first line kept | stdout | 0 |
| `dpkg-search.txt` | `dpkg -S /usr/sbin/sshd /usr/bin/ls /usr/local/bin/mcli /usr/bin/snap` | stdout | 1 |
| `dpkg-search.stderr.txt` | the same call | stderr | 1 |
| `dpkg-search-2204.txt` | `dpkg -S /usr/local/bin/ngrok /usr/local/bin/mcli /snap/core22/1122/usr/bin/env /usr/lib/snapd/snapd` | stdout | 1 |
| `dpkg-search-2204.stderr.txt` | the same call | stderr | 1 |
| `dpkg-search-multi-owner.txt` | `dpkg -S /etc/init.d` | stdout | 0 |
| `dpkg-search-diversion.txt` | `dpkg -S /usr/share/dict/words` | stdout | 0 |
| `stat-executables.txt` | `stat -L -c %n %a %U %G %s /usr/sbin/sshd /usr/bin/ls /usr/local/bin/mcli /usr/bin/snap` | stdout | 0 |
| `stat-executables-2204.txt` | the same call on the bastion, over its four paths | stdout | 0 |
| `stat-missing.stderr.txt` | `stat -L -c %n %a %U %G %s /usr/bin/ls /usr/local/bin/nosuch-trustfreeze` | stderr | 1 |
| `systemctl-show-execstart.txt` | `systemctl show --no-pager -p Id,ExecStart ssh.service snap.cups.cupsd.service cron.service man-db.timer` | stdout | 0 |
| `systemctl-show-execstart-2204.txt` | `systemctl show --no-pager -p Id,ExecStart ngrok-host-a.service ssh.socket` | stdout | 0 |
| `../systemd/systemctl-show-dependencies.txt` | `systemctl show --no-pager -p <the full property list of systemdShowProperties> ngrok-host-a.service ssh.socket` on the bastion | stdout | 0 |
| `../systemd/systemctl-show-required-by.txt` | `systemctl show --no-pager -p Id,BindsTo,RequiredBy dbus.socket docker.socket` on the trial host | stdout | 0 |

The last two files live in `../systemd/` because they belong to `linux.systemd`, whose show property
list now carries the five dependency properties.

## What each fixture is for, and the trap it carries

- **`dpkg-search.txt` plus its stderr.** The ordinary answer shape `package: path`, and the one trap
  of this tool: `/bin/ls` answers **no path found**, because the dpkg database holds `/usr/bin/ls`
  and `/bin` is a symlink to `/usr/bin` on a merged-`/usr` Ubuntu. A probe that asks dpkg before it
  resolves symlinks reports half its programs as unowned. The fixture asks for `/usr/bin/ls`, the
  resolved form, which answers `coreutils`.
- **`dpkg-search.stderr.txt`.** A path no package owns goes to stderr and the call exits 1 while the
  other lines are still printed on stdout. The wording was identical on both releases, so the parser
  keys on the ABSENCE of a stdout answer and not on this message.
- **`dpkg-search-2204.txt` plus its stderr.** The bastion: `mcli` under `/usr/local/bin` is owned by
  a package of the same name, `ngrok` beside it is owned by nobody, and the file of a mounted snap is
  not in the database at all. Three different answers for three paths in one call.
- **`dpkg-search-multi-owner.txt`.** One path, 31 package names in one comma separated line, several
  with an architecture qualifier after a colon (`libc6-dev:amd64`). It is a directory path, because
  no executable file on either host had more than one owner; the parser cannot tell the difference,
  it reads `packages: path`. On the same host `dpkg -S /usr/lib/x86_64-linux-gnu` answered with 757
  names in a single line of about 25 kB, which is why the probe caps the recorded package list.
- **`dpkg-search-diversion.txt`.** Two diversion records and an ownership answer for the same path.
  A parser that splits every line at `": "` reads the package name as `diversion by
  dictionaries-common from`. This is the fixture that fails such a parser.
- **`stat-executables.txt`, `stat-executables-2204.txt`.** Mode, owner, group and size of real
  programs, including a 31 MB and a 32 MB one. The sizes are real, so a test that sets a small size
  cap has real numbers to refuse.
- **`stat-missing.stderr.txt`.** A path that does not exist: stat prints the other lines on stdout,
  this line on stderr, and exits 1. The probe parses stdout whatever the exit code says.
- **`systemctl-show-execstart.txt`.** The two property call the probe makes. Four units, and the last
  one is the case a reader forgets: a timer answers with `Id` only, because it starts no program. It
  also shows that the manager answers in ITS property order (ExecStart before Id) and separates
  units with a blank line.
- **`systemctl-show-execstart-2204.txt`.** The same call on the bastion: the ngrok unit names a
  program under `/usr/local/bin`, and the socket unit names none.
- **`../systemd/systemctl-show-dependencies.txt`.** The full property list. `Requires` of the ngrok
  unit names `system.slice`, `-.mount` and `sysinit.target`, none of which is in any unit file: the
  manager adds them. That is why the dependency edges are recorded on the OBSERVED artifact of the
  unit and not on the declared one (playbook L3). It also shows the empty form `BindsTo=`, which is
  how the manager says there is no such edge, and the root mount unit `-.mount`, whose name starts
  with a hyphen.
- **`../systemd/systemctl-show-required-by.txt`.** A non-empty `RequiredBy`: 17 units in one line of
  343 bytes, the longest dependency line of all 372 units the selection rule picked on that host.
  `RequiredBy` is in no unit file at all; the manager computes it from every other loaded unit.

`BindsTo` was **empty on every unit measured on both hosts** (every unit of the selection on the
trial host, the first 60 units on the bastion). The property is asked for and recorded through the
same code path as its four siblings, and the non-empty case is covered by the parser test with the
shape the siblings measured: a space separated list of unit names. No file here carries an invented
non-empty `BindsTo`.

## Sanitization applied here

Change identity, keep shape. Column counts, field separators, record order, padding, exit codes,
streams and message wording are untouched.

| Real value | Replacement |
|---|---|
| the bastion's ngrok unit name | `ngrok-host-a.service` (same length class, same suffix) |
| the site name inside its `ExecStart` argv | `host-a-ssh` |
| its `Description`, which named the site and the role | `ngrok TCP endpoint for host-a` |
| its `FragmentPath` | `/etc/systemd/system/ngrok-host-a.service` |

The argv column of the table above carries the SANITIZED unit name, the same substitution the
fixture bytes carry. An earlier version of this file kept the real name there, with the argument that
an argv is the record of a measurement and is never edited. The argument cut both ways and lost: the
same string was then hidden in one file of this repository and published in another, which makes the
substitution pointless and leaves a reader guessing which of the two is the rule. The record is
therefore complete up to that one named substitution, which is the most a public fixture can record
(playbook L5, SPEC-0358), and whoever repeats the call substitutes the name back once, from the host.
Nothing else in any argv of this table is substituted; a value that is not in the sanitization table
above is the host's own.

### What was deliberately NOT changed

- Program paths (`/usr/local/bin/ngrok`, `/usr/local/bin/mcli`, `/snap/core22/1122/usr/bin/env`,
  `/usr/lib/snapd/snapd`), package names, snap names and the snap revision `1122`. They name
  software, not a person or a site, and they are the substance of these fixtures: the whole point is
  that one of them is owned by a package and the next one is not.
- File modes, owners (`root`), groups and sizes. Real numbers, so a cap test refuses a real size.
- The service account `ngrok` in the `User` and `Group` properties: it is named after the software
  it runs, not after a person.
- The volatile fields inside an `ExecStart` record (`start_time`, `stop_time`, `pid`, `code`,
  `status`) and the environment references `$SSHD_OPTS` and `$EXTRA_OPTS`. They stay so that
  `ParseExecStartPath` keeps proving that it returns the path and nothing else.
- Unit names of the distribution (`ssh.service`, `ssh.socket`, `dbus.socket`, `docker.socket`,
  `man-db.timer`, `snap.cups.cupsd.service`, `-.mount`) and the 17 unit names of the `RequiredBy`
  line. They are the same on every Ubuntu of that release.

No account name of a person, no host name, no address and no key material appears in any file of
this directory. There was none to substitute in the dpkg and stat output.

#!/usr/bin/env bash
#
# scripts/bugtracker.sh, keep a bug's two planes in step (SPEC-0358,
# "ship the code, keep the reasoning").
#
# It tracks the two kinds of item that live in bug-reports/:
#   BUG-NNNN  a defect, closed as `fixed`
#   FR-NNNN   a feature request: closed as `implemented`
#
#   1. the REPORT: ${M3C_MAINTENANCE_DIR}/bug-reports/<KIND>-NNNN-<slug>.md
#      The source of truth. PRIVATE plane: root cause or rationale, file:line,
#      customer context, SPEC references, whatever the analysis needs.
#
#   2. the ISSUE: a GitHub issue in this (PUBLIC) repository.
#      The tracker view other people can see. It is a REDACTED restatement,
#      never a copy: observed behaviour, expected behaviour, reproduction,
#      version. It refers to the private plane ID-ONLY ("BUG-0213"): never a
#      path, an internal endpoint, an ER1 context-id or a secret header.
#
# The issue is fail-closed on purpose. `open` refuses unless the report declares
# `- **Public:** yes` and a separate redacted body exists that passes the same
# leak patterns tools/boundary-gate.sh enforces in CI. bug-reports/ also holds
# bugs for systems that are NOT this OSS artifact; those get `Public: no` and
# never leave the private plane. A public issue cannot be un-published.
#
# Configuration:
#   M3C_MAINTENANCE_DIR   required, the private maintenance repo's root
#   M3C_BUG_REPO          optional, owner/repo fallback for an item that does
#                         not declare `- **Repo:**` and has no issue yet. The
#                         target is NEVER inferred from the working directory.
#
# An item is named BUG-0213 / FR-0096, or fr-96, or a filename. A BARE NUMBER
# means a BUG. The FR kind must be spelled out, so "96" can never silently
# resolve to the wrong item.
#
# Commands:
#   next-id [BUG|FR] [--no-fetch] next free id of that kind (default BUG)
#   claim  <ID>                   establish the id on the slot table's branch
#   path   <ID>                   resolve the report file
#   status <ID> [STATUS]          read, or set, the canonical status
#   issue  <ID>                   print the linked issue reference
#   spec   <ID>                   print the SPEC the item answers to
#   redact-check [FILE|-]         SPEC-0358 leak patterns over text; 1 = a hit
#   open   <ID>                   create the public issue and link it back
#   close  <ID> [--status S] [--comment TEXT]
#   sync   [<ID>]                 read-only: report/issue drift
#
# Closing an item as done requires a `- **Spec:**` line. Solving an issue means
# serving the contract it belongs to, so the value may be `none: <reason>`, but
# the question has to have been ANSWERED rather than skipped.
#
# ALLOCATION IS A WRITE, NOT A READ. `next-id` only READS: it takes the ceiling
# from every claim it can see, which still lets two sessions asking at the same
# moment receive the same number; that is how FR-0096 was handed out twice.
# `claim` is the write, and the write is a commit on the branch that holds the
# shared slot table, pushed. `claim` exits 0 only when that push was accepted,
# or when the branch already carries the same number for the same file. A row
# in a working copy is not an allocation, and `claim` does not write one.
#
# What serialises two claims is the push: it moves the branch from the commit
# this claim read to the commit it wrote, or it is refused. After a refusal
# `claim` reads the branch again from scratch; it never forces and never merges.
#
# What a failed `claim` says depends on whether it had pushed. Before its first
# push nothing can have reached the remote, and it says "Nothing was claimed".
# After a push it says only what it can see, as one of three states (see
# claim_stop): ESTABLISHED, exit 0; NOT_ESTABLISHED, exit 1, when the branch can
# be read, does not carry the row, and every push was answered with a refusal;
# OUTCOME_UNKNOWN, exit 3, otherwise. A push that got no answer, a lost
# connection, or a pre-push hook of your own that refused leaves the outcome
# unknown from here. Then run the same `claim` again: it reads the branch and
# either finds its own row (exit 0) or tries again or names who holds the
# number. If `claim` itself is killed, its exit status says nothing; the same
# rerun applies.
#
#   M3C_SLOT_TABLE   the slot table, a tracked file in a checkout of its repo
#   M3C_SLOT_REF     optional, <remote>/<branch> that is canonical for it;
#                    default: the upstream of that checkout
# `claim` refuses, before it commits or pushes anything, when git configuration
# comes from the environment (GIT_CONFIG_PARAMETERS, GIT_CONFIG_COUNT,
# GIT_CONFIG), when the remote is not plainly one repository (a pushurl, several
# urls, a url rewrite rule from git's config files that applies, a url without
# '/' or ':', a url that is a remote's name, an old-style remote file for the
# url), when the table does not have exactly one ANKER row
# or does not end with a newline, and when the report's filename is not a plain
# identifier. It also refuses to push a commit that is not the one row on top
# of what it read; that check is against accidents of the table repository's
# hooks, not against a hook written to defeat it.
#
# Why `claim` is a separate verb and not part of `next-id`: a slot row carries the
# FILENAME, which does not exist until the report is written. Claiming at next-id
# time could only reserve a placeholder, and the checker would need a special case
# for it. So the order is: next-id -> write the file -> claim.
#
# Exit: 0 ok · 1 a check failed (drift, leak, refusal) · 2 usage/config error
#       · 3 claim only: outcome unknown, run the same claim again.
set -euo pipefail

# The states that mean "done": closing an issue as completed, and the states
# that require a Spec answer.
DONE_STATES="fixed implemented"

die()  { printf 'bugtracker: %s\n' "$1" >&2; exit "${2:-2}"; }
note() { printf '%s\n' "$1" >&2; }

# ---------------------------------------------------------------- config ----

bug_dir() {
  [ -n "${M3C_MAINTENANCE_DIR:-}" ] || die "M3C_MAINTENANCE_DIR is not set.
  Point it at the private maintenance repo root, e.g.
      export M3C_MAINTENANCE_DIR=\"\$HOME/path/to/your-maintenance-repo\""
  [ -d "$M3C_MAINTENANCE_DIR/bug-reports" ] || die "no bug-reports/ under \$M3C_MAINTENANCE_DIR ($M3C_MAINTENANCE_DIR)"
  printf '%s\n' "$M3C_MAINTENANCE_DIR/bug-reports"
}

# repo_for FILE: which GitHub repository this item's issue lives in.
#
# The target is a property of the ITEM, never of the working directory. Deriving
# it from `git remote origin` was wrong in both directions: run from the private
# maintenance checkout it resolved to the private repo (so `close` would address
# a DIFFERENT issue of the same number), and run from some other public checkout
# it would have published into that repo instead. bug-reports/ holds items for
# several systems, so there is no single correct default to infer.
#
# Resolution order, most authoritative first:
#   1. the recorded `- **Issue:** owner/repo#N`: after creation this IS the fact
#   2. the declared `- **Repo:** owner/repo`: before creation, reviewed in-file
#   3. $M3C_BUG_REPO: a stated override for one-offs
#   4. refuse
#
# The file outranks the environment on purpose: an item that has declared its
# target must not be redirected somewhere else by a stray variable.
repo_for() {
  local file=$1 r
  # NB: `s///p` prints the whole line, so the pattern must consume the "#N" too.
  r=$(read_field "$file" Issue | sed -n 's|^\([A-Za-z0-9_.-]\{1,\}/[A-Za-z0-9_.-]\{1,\}\)#.*$|\1|p' | head -1)
  [ -n "$r" ] || r=$(read_field "$file" Repo)
  [ -n "$r" ] || r=${M3C_BUG_REPO:-}
  [ -n "$r" ] || die "$(basename "$file"): no target repository.
  Declare it in the report as
      - **Repo:** owner/repo
  or set M3C_BUG_REPO for a one-off. It is NOT inferred from the working
  directory: bug-reports/ holds items for several systems, and guessing from
  wherever you happen to stand is how an issue lands in the wrong repository." 1
  printf '%s\n' "$r" | grep -qE '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' \
    || die "$(basename "$file"): '$r' is not a valid owner/repo" 1
  printf '%s\n' "$r"
}

need_gh() { command -v gh >/dev/null 2>&1 || die "the GitHub CLI (gh) is required for issue commands"; }

# ------------------------------------------------------------- resolving ----

# normalise "213" / "bug-0213" / "FR-96" / "BUG-0213-slug.md" -> BUG-0213 / FR-0096
item_id() {
  local up kind n
  up=$(printf '%s\n' "$1" | tr '[:lower:]' '[:upper:]')
  kind=$(printf '%s\n' "$up" | sed -E -n 's/^(BUG|FR)[-_]?[0-9].*$/\1/p')
  [ -n "$kind" ] || kind=BUG
  n=$(printf '%s\n' "$up" | sed -E -n 's/^(BUG|FR)?[-_]?0*([0-9]+).*$/\2/p')
  [ -n "$n" ] || die "not an item id: $1 (expected BUG-NNNN, FR-NNNN or a bare number)"
  printf '%s-%04d\n' "$kind" "$n"
}

kind_of() { printf '%s\n' "${1%%-*}"; }

# The vocabulary differs by kind on one word only: a defect is FIXED, a feature
# request is IMPLEMENTED. Sharing the rest keeps sync and close uniform.
statuses_for() {
  case "$1" in
    BUG) printf 'open in-progress fixed wontfix duplicate\n' ;;
    FR)  printf 'open in-progress implemented wontfix duplicate\n' ;;
    *)   die "unknown item kind: $1" ;;
  esac
}

label_for() {
  case "$1" in
    BUG) printf 'bug\n' ;;
    FR)  printf 'enhancement\n' ;;
  esac
}

report_path() {
  local id dir hits
  id=$(item_id "$1"); dir=$(bug_dir)
  hits=$(find "$dir" -maxdepth 1 -name "$id-*.md" ! -name '*.public.md' | sort)
  [ -n "$hits" ] || die "no report file for $id in $dir" 1
  [ "$(printf '%s\n' "$hits" | wc -l)" -eq 1 ] || die "several files match $id:
$hits"
  printf '%s\n' "$hits"
}

public_body_path() { printf '%s\n' "${1%.md}.public.md"; }

# claims KIND: every number of that kind anyone has already taken, as
# "<number><TAB><where>" lines. The point is the SOURCES: reading max+1 out of
# one working tree is why two sessions can be handed the same id. A claim is
# real if it exists ANYWHERE another checkout could later push:
#
#   1. a file in the local bug-reports/          (what the old code saw)
#   2. a file on ANY local or remote branch      (someone else's unmerged work)
#   3. a BRANCH NAME like docs/fr-0096-…         (claimed before the file exists)
#
# Source 3 matters more than it looks: a branch is usually named before the file
# is written, so it is the earliest visible claim there is.
claims() {
  local kind=$1 dir lower ref
  dir=$(bug_dir)
  lower=$(printf '%s\n' "$kind" | tr '[:upper:]' '[:lower:]')

  find "$dir" -maxdepth 1 -name "$kind-*.md" 2>/dev/null \
    | sed -E -n "s#.*/$kind-0*([0-9]+)-.*#\\1\\tlocal file#p"

  git -C "$dir" rev-parse --git-dir >/dev/null 2>&1 || return 0

  for ref in $(git -C "$dir" for-each-ref --format='%(refname:short)' refs/heads refs/remotes 2>/dev/null); do
    # BUG-0227: zwei Fehler in einer Zeile, und jeder allein macht diese
    # Quelle still tot. $dir IST bereits bug-reports/, der Pfad loeste sich
    # also zu bug-reports/bug-reports/ auf; und `ls-tree` gibt aus einem
    # Unterverzeichnis RELATIVE Namen aus, denen der Schraegstrich fehlt, den
    # das Muster unten verlangt. Gemessen am 2026-09-25 auf origin/master:
    # heute 0 Nummern, mit --full-name und Pfad "." 274; ueber alle 115 Refs
    # 28995 statt 0. Damit war Quelle 2 tot, also genau der refuebergreifende
    # Abgleich, den der Kopfkommentar als Schutz gegen Nummern-Rennen fuehrt.
    git -C "$dir" ls-tree --full-name --name-only "$ref" . 2>/dev/null \
      | sed -E -n "s#.*/$kind-0*([0-9]+)-.*#\\1\\t$ref#p"
    printf '%s\n' "$ref" \
      | sed -E -n "s#.*[^a-z]$lower-?0*([0-9]+).*#\\1\\tbranch $ref#p"
  done
}

# The fourth source, and the one that was missing until 2026-09-15: the shared
# slot table. A reservation lives there BEFORE any file or branch exists, which
# is the whole point of reserving. Without it `next-id` hands out numbers that
# were claimed days ago: measured on that date it answered BUG-0268 while the
# table had held 0268 since 2026-09-14 and was unbroken up to 0281.
#
# Kept separate from claims() so a missing table cannot be mistaken for "no
# claims": next-id says out loud that it read an incomplete set.
#
# slot_rows is the ONE reading of a slot row; next-id and claim both go through
# it, so they cannot disagree about what a row says. A row counts when its
# first cell is a number and its second cell is a backticked name that starts
# with the kind, a number and a dash. The number is printed without leading
# zeros: 300 and 0300 are one slot. A row written any other way, without
# backticks or with a path before the name, is not a slot row for either of them.
slot_rows() {  # slot_rows KIND FILE -> "<number>\t<filename>" per row
  sed -E -n "s/^\\|[[:space:]]*0*([0-9]+)[[:space:]]*\\|[[:space:]]*\`($1-[0-9]+-[^\`]*)\`.*/\\1\\t\\2/p" "$2"
}

slot_claims() {
  local kind=$1 t=${M3C_SLOT_TABLE:-}
  [ -n "$t" ] && [ -f "$t" ] || return 1
  slot_rows "$kind" "$t" | sed -E 's/\t.*/\tslot table/'
  return 0
}

cmd_next_id() {
  local kind=${1:-BUG} fetch=1 dir n where max=0 top="" all
  while [ $# -gt 0 ]; do
    case "$1" in
      --no-fetch) fetch=0 ;;
      -*) die "next-id: unknown flag '$1'" ;;
      *) kind=$1 ;;
    esac
    shift
  done
  kind=$(printf '%s\n' "$kind" | tr '[:lower:]' '[:upper:]')
  statuses_for "$kind" >/dev/null      # rejects an unknown kind
  dir=$(bug_dir)

  # Without a fetch the answer is only as fresh as your last pull, which is
  # exactly how a number that someone else already pushed still looks free.
  if [ "$fetch" -eq 1 ] && git -C "$dir" rev-parse --git-dir >/dev/null 2>&1; then
    git -C "$dir" fetch --quiet origin 2>/dev/null \
      || note "next-id: could not fetch: the answer may be stale (use --no-fetch to silence)"
  fi

  if [ -n "${M3C_SLOT_TABLE:-}" ] && [ -f "${M3C_SLOT_TABLE}" ]; then
    all=$( { claims "$kind"; slot_claims "$kind"; } | sort -u )
  else
    all=$(claims "$kind" | sort -u)
    note "next-id: M3C_SLOT_TABLE is not set or not readable.
  The answer ignores every reservation that has no file and no branch yet, which
  is exactly what a reservation IS. Point M3C_SLOT_TABLE at the shared table."
  fi
  while IFS=$'\t' read -r n where; do
    [ -n "$n" ] || continue
    if [ "$n" -gt "$max" ]; then max=$n; top=$where; fi
  done <<EOF
$all
EOF

  # Say where the ceiling came from when it is NOT something in your own tree:
  # that is the claim you would otherwise have walked straight into.
  case "$top" in
    ""|"local file") ;;
    *) note "next-id: highest $kind claim is $(printf '%s-%04d' "$kind" "$max") in $top: not in your working tree" ;;
  esac

  local next; next=$(printf '%s-%04d' "$kind" "$((max + 1))")
  note "next-id: $next is NOT yet allocated: reading a ceiling is not a claim.
  Write the report, then: $(basename "$0") claim $next"
  printf '%s\n' "$next"
}

# ---------------------------------------------------------------- fields ----
#
# The script owns three canonical lines in the report:
#     - **Status:** open
#     - **Public:** yes
#     - **Issue:**  owner/repo#42
# Reading tolerates the older loose spellings ("**Status:** Fixed (2026-03-21)");
# writing always produces the canonical form, so `sync` has something to parse.

# BULLET_* match an optional markdown list marker ("- ", "* ", "+ ") and nothing
# more: deliberately NOT a [-* ] character class, which would also swallow the
# "**" that opens the bold field name.
BULLET_BRE='[[:space:]]*\([-*+][[:space:]]\{1,\}\)\{0,1\}'
BULLET_ERE='^[ \t]*([-*+][ \t]+)?'

read_field() {
  sed -n "s/^$BULLET_BRE\*\*$2:\*\*[[:space:]]*//p" "$1" | head -1 | sed 's/[[:space:]]*$//'
}

canon_status() {
  local raw
  raw=$(printf '%s\n' "$1" | tr '[:upper:]' '[:lower:]' | sed 's/\*//g; s/[[:space:]]*(.*//; s/[[:space:]]*·.*//; s/^[[:space:]]*//; s/[[:space:]]*$//')
  case "$raw" in
    ""|unknown)                 printf 'unknown\n' ;;
    open|new|reported)          printf 'open\n' ;;
    in-progress|wip|doing)      printf 'in-progress\n' ;;
    fixed|resolved|closed)      printf 'fixed\n' ;;
    implemented|shipped|delivered|done) printf 'implemented\n' ;;
    wontfix|declined)           printf 'wontfix\n' ;;
    duplicate|dup)              printf 'duplicate\n' ;;
    *)                          printf '%s\n' "$raw" ;;
  esac
}

set_field() {
  local file=$1 name=$2 value=$3 tmp
  tmp=$(mktemp)
  if grep -q "^$BULLET_BRE\*\*$name:\*\*" "$file"; then
    awk -v n="$name" -v v="$value" -v b="$BULLET_ERE" '
      !seen && $0 ~ b "\\*\\*" n ":\\*\\*" {
        match($0, b); print substr($0, 1, RLENGTH) "**" n ":** " v; seen=1; next
      } { print }
    ' "$file" > "$tmp"
  else
    # Insert into the metadata block that follows the H1 title.
    awk -v n="$name" -v v="$value" '
      NR==1 { print; next }
      !seen && /^$/ { print; print "- **" n ":** " v; seen=1; next }
      { print }
      END { if (!seen) print "- **" n ":** " v }
    ' "$file" > "$tmp"
  fi
  mv "$tmp" "$file"
}

cmd_status() {
  local id file kind allowed want
  id=$(item_id "$1"); file=$(report_path "$1"); kind=$(kind_of "$id")
  if [ $# -lt 2 ]; then canon_status "$(read_field "$file" Status)"; return 0; fi
  allowed=$(statuses_for "$kind"); want=$(canon_status "$2")
  case " $allowed " in *" $want "*) ;; *) die "status '$2' is not valid for a $kind (use: $allowed)";; esac
  set_field "$file" Status "$want"
  printf '%s\n' "$want"
}

issue_ref()  { read_field "$1" Issue | sed -n 's/.*#\([0-9]\{1,\}\).*/\1/p' | head -1; }
cmd_issue()  { local f; f=$(report_path "$1"); printf '%s\n' "$(read_field "$f" Issue)"; }
cmd_spec()   { local f; f=$(report_path "$1"); printf '%s\n' "$(read_field "$f" Spec)"; }

# ----------------------------------------------------------- redact-check ---
#
# The leak rules live in tools/leak-patterns.txt and are shared with
# tools/boundary-gate.sh, the CI commit gate. They are applied here because an
# issue body is a public-plane artefact that NO CI job ever sees: the commit gate
# cannot catch what is posted through the API. Every pattern applies, including
# the ops-exempt ones: those are exempt for the tool's own SOURCE, never for
# text we publish about it.

leak_patterns_file() {
  local f
  f="$(cd "$(dirname "$0")/.." && pwd)/tools/leak-patterns.txt"
  [ -f "$f" ] || die "missing the shared leak-pattern table: $f"
  printf '%s\n' "$f"
}

# redact_scan TEXT -> 0 = clean, 1 = at least one pattern matched (reported on stderr)
redact_scan() {
  local text=$1 file scope reason re out clean=0
  file=$(leak_patterns_file)
  while IFS=$'\t' read -r scope reason re; do
    case "$scope" in ''|\#*) continue ;; esac
    [ -n "$re" ] || continue
    out=$(grep -nE "$re" <<<"$text" || true)
    [ -n "$out" ] && { note "  $reason: $out"; clean=1; }
  done < "$file"
  return $clean
}

cmd_redact_check() {
  local src=${1:--} text
  if [ "$src" = "-" ]; then text=$(cat); else text=$(cat "$src"); fi
  if redact_scan "$text"; then
    echo "redact-check: clean"
  else
    note "redact-check: FAIL: this text carries private-plane content (SPEC-0358); it must not be posted publicly"
    exit 1
  fi
}

# ------------------------------------------------------------------ open ----

cmd_open() {
  local id file pub_file title body num url
  id=$(item_id "$1"); file=$(report_path "$1")

  if [ -n "$(issue_ref "$file")" ]; then
    note "$id already links $(read_field "$file" Issue): nothing to do"
    return 0
  fi

  [ "$(canon_status "$(read_field "$file" Public)")" = "yes" ] && : || \
    die "refusing to publish $id: the report does not declare '- **Public:** yes'.
  Publishing is per-bug and deliberate. Declare it only for a bug in THIS
  shipped artifact, never a security issue, a customer-specific detail, or a
  bug in a system this repository does not ship." 1

  pub_file=$(public_body_path "$file")
  [ -f "$pub_file" ] || die "refusing to publish $id: no redacted body at
  $(basename "$pub_file")
  Write the public-safe restatement there first (observed behaviour, expected
  behaviour, reproduction, affected version) referring to the analysis ID-ONLY
  as '$id'." 1

  title=$(sed -n '1s/^#[[:space:]]*//p' "$pub_file")
  [ -n "$title" ] || die "the redacted body needs a '# <title>' on line 1" 1
  body=$(sed '1d' "$pub_file")

  if ! redact_scan "$body$title"; then
    die "refusing to publish $id: the redacted body still carries private-plane content (SPEC-0358)" 1
  fi

  local repo; repo=$(repo_for "$file")

  need_gh
  url=$(gh issue create --repo "$repo" --title "$title" --label "$(label_for "$(kind_of "$id")")" \
        --body "$body"$'\n\n---\n_Tracked privately as '"$id"'._')
  num=$(printf '%s\n' "$url" | sed -n 's#.*/issues/\([0-9]\{1,\}\).*#\1#p' | head -1)
  [ -n "$num" ] || die "could not read the created issue number from: $url" 1

  set_field "$file" Issue "$repo#$num"
  echo "$repo#$num  $url"
}

# ----------------------------------------------------------------- claim ----

slot_table() {
  local t=${M3C_SLOT_TABLE:-}
  [ -n "$t" ] || die "M3C_SLOT_TABLE is not set. There is nowhere to record the claim.
  Point it at the shared slot table, the same file the slot checker reads.
  Until a number is pushed on its branch it is NOT allocated: a number that
  exists only in your working copy, or in a conversation, is one someone else
  can be handed a moment later." 1
  [ -f "$t" ] || die "the slot table does not exist: $t" 1
  printf '%s\n' "$t"
}

# Where the table is canonical. A claim is a row on a BRANCH OF A REMOTE; the
# file $M3C_SLOT_TABLE only tells us which repository and which path. The branch
# is $M3C_SLOT_REF (remote/branch) or, without it, the upstream of the checkout
# that holds the table. No remote means there is nowhere to establish a claim.
LEDGER_REPO=""; LEDGER_REL=""; LEDGER_REF=""; LEDGER_BRANCH=""; LEDGER_URL=""

slot_ledger() {
  local table=$1 dir remote pushes fetches raw r cands d p
  dir=$(cd "$(dirname "$table")" && pwd -P)
  LEDGER_REPO=$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null) \
    || die "the slot table is not inside a git repository: $table
  A claim is established by a commit on the shared branch. A row in a loose
  file is a note to yourself, and this command does not write one." 1
  LEDGER_REL=$(git -C "$dir" ls-files --full-name -- "$(basename "$table")")
  [ -n "$LEDGER_REL" ] || die "the slot table is not tracked in its repository: $table" 1

  LEDGER_REF=${M3C_SLOT_REF:-}
  if [ -z "$LEDGER_REF" ]; then
    LEDGER_REF=$(git -C "$LEDGER_REPO" rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null) \
      || die "cannot tell which branch holds the slot table: the checkout at
  $LEDGER_REPO has no upstream. Name it: M3C_SLOT_REF=<remote>/<branch>" 1
  fi
  # Which remote the ref names is read from the list of remotes, not guessed
  # from the first slash: exactly one remote name may be a prefix of it.
  remote=""; cands=0
  while IFS= read -r r; do
    case $LEDGER_REF in "$r"/?*) remote=$r; cands=$((cands + 1)) ;; esac
  done <<EOF
$(git -C "$LEDGER_REPO" remote)
EOF
  [ "$cands" = 1 ] || die "cannot tell which remote '$LEDGER_REF' names: $cands remotes of
  $LEDGER_REPO match it. M3C_SLOT_REF must be <remote>/<branch>. Nothing was claimed." 1
  LEDGER_BRANCH=${LEDGER_REF#"$remote"/}

  # One repository is read and written, and it has to be plain which one. The
  # URL below is handed to git as a URL. These are the ways known here in which
  # git would read it as something else, and each is refused before anything
  # is written:
  #   - more than one url, or any pushurl, on the remote;
  #   - a url.*.insteadOf or url.*.pushInsteadOf rule in git's config files
  #     that changes where the remote fetches from or pushes to (configuration
  #     from the environment is refused in cmd_claim);
  #   - a url without '/' or ':', which git may take for a remote's name;
  #   - an old-style remote file under .git/remotes or .git/branches for it;
  #   - a url that is also the name of a configured remote.
  # This is not a model of git's URL handling, and it does not claim to cover
  # every way git can resolve a url. Within these cases it errs towards
  # refusing, also where the configuration would have been harmless.
  raw=$(git -C "$LEDGER_REPO" config --get-all "remote.$remote.url" 2>/dev/null || true)
  [ -n "$raw" ] && [ "$(printf '%s\n' "$raw" | wc -l | tr -d ' ')" = 1 ] \
    || die "remote '$remote' has no url, or more than one. Nothing was claimed." 1
  # A bare name, without '/' or ':', is not supported as a url: git may read it
  # as the name of a remote, from the config or from the old files under
  # .git/remotes and .git/branches, and then the name decides where claim
  # writes. Those old files are refused for any url.
  case $raw in
    */* | *:*) ;;
    *) die "the url of remote '$remote' is the bare name '$raw'. git may read a
  bare name as a remote, so claim does not use one. Write the url as a path
  (./$raw) or a URL. Nothing was claimed." 1 ;;
  esac
  for d in remotes branches; do
    p=$(git -C "$LEDGER_REPO" rev-parse --git-path "$d/$raw")
    case $p in /*) ;; *) p="$LEDGER_REPO/$p" ;; esac
    [ ! -e "$p" ] || die "there is an old-style remote file for '$raw': $p
  git would read the url through it. Nothing was claimed." 1
  done
  [ -z "$(git -C "$LEDGER_REPO" config --get-all "remote.$remote.pushurl" 2>/dev/null || true)" ] \
    || die "remote '$remote' has a pushurl. A claim reads and writes ONE repository,
  named by the remote's url alone. Nothing was claimed." 1
  fetches=$(git -C "$LEDGER_REPO" remote get-url --all "$remote")
  pushes=$(git -C "$LEDGER_REPO" remote get-url --push --all "$remote")
  [ "$fetches" = "$raw" ] && [ "$pushes" = "$raw" ] \
    || die "a url.*.insteadOf or url.*.pushInsteadOf rule rewrites remote '$remote':
  configured: $raw
  fetches:    $fetches
  pushes:     $pushes
  A claim reads and writes ONE repository and does not follow rewrites.
  Nothing was claimed." 1
  if git -C "$LEDGER_REPO" remote | grep -q -x -F -- "$raw"; then
    die "the url of remote '$remote' is '$raw', which is also the name of a
  remote; git would read it as that remote. Nothing was claimed." 1
  fi
  LEDGER_URL=$raw
}

# Everything a claim writes outside git's own storage sits in one directory
# that mktemp made for this process, and its ref carries that directory's name.
# No path here is fixed, so a second claim cannot be handed the same one.
CLAIM_DIR=""; CLAIM_WT=""; CLAIM_PRIV=""

claim_cleanup() {
  if [ -n "$CLAIM_WT" ] && [ -d "$CLAIM_WT" ]; then
    git -C "$LEDGER_REPO" worktree remove --force "$CLAIM_WT" >/dev/null 2>&1 || true
  fi
  [ -z "$CLAIM_DIR" ] || rm -rf "$CLAIM_DIR"
  [ -z "$CLAIM_PRIV" ] || git -C "$LEDGER_REPO" update-ref -d "$CLAIM_PRIV" >/dev/null 2>&1 || true
  return 0
}

# claim_stop MSG: end a claim that did not get its row on the branch. It runs in
# cmd_claim's scope and reads its variables.
#
# Before any push nothing can have reached the remote, and that is said. After
# a push only what can be observed is said, as one of three states:
#   ESTABLISHED       the branch carries this number for this file and no other
#                     (an earlier push landed after all): exit 0;
#   NOT_ESTABLISHED   the branch can be read and does not carry it, and every
#                     push of this claim was answered with a refusal: exit 1;
#   OUTCOME_UNKNOWN   anything else: a push got no answer, or the branch cannot
#                     be read now. Exit 3, and the claim must be run again.
claim_stop() {
  local msg=$1 seen
  [ "$pushes" != 0 ] || die "$msg
  Nothing was claimed." 1
  if git -C "$LEDGER_REPO" fetch -q --no-tags "$LEDGER_URL" \
       "+refs/heads/$LEDGER_BRANCH:$CLAIM_PRIV" >/dev/null 2>&1 \
     && git -C "$LEDGER_REPO" show "$CLAIM_PRIV:$LEDGER_REL" > "$CLAIM_DIR/seen" 2>/dev/null; then
    seen=$(slot_rows "$kind" "$CLAIM_DIR/seen" | awk -F'\t' -v n="$want" '$1 == n { print $2 }')
    if [ "$seen" = "$base" ]; then
      claim_cleanup
      echo "$id claimed for $base on $LEDGER_REF (ESTABLISHED: an earlier push of this claim landed)"
      exit 0
    fi
    [ "$unknown" != 0 ] || die "$msg
  NOT_ESTABLISHED: $LEDGER_REF does not carry $id for $base, and every push of
  this claim was refused by an answer from the remote. Nothing was claimed." 1
  fi
  die "$msg
  OUTCOME_UNKNOWN: a push of this claim got no answer, or $LEDGER_REF cannot be
  read now. Whether it carries $id for $base cannot be told from here, so the
  number is neither free nor yours yet. Run the same claim again: it reads the
  branch and either finishes or names who holds the number." 3
}

# How often a claim starts over because the branch moved under it. Every round
# reads the table again, so a retry never carries an old answer forward.
CLAIM_ROUNDS=5

cmd_claim() {
  local id file table num kind base row want holders other name tip new out out_push="" round last=""
  local mode blob want_blob expect got back re pushes=0 unknown=0 status="" rc tab
  tab=$(printf '\t')
  id=$(item_id "$1"); file=$(report_path "$1"); table=$(slot_table)
  kind=$(kind_of "$id"); num=${id#*-}; base=$(basename "$file"); want=$((10#$num))

  # The filename goes into a table cell between backticks and is read back by
  # slot_rows. It is an identifier, not free text: letters, digits, dot,
  # underscore and dash after the id, ending in .md. That leaves out everything
  # that could end the cell or the line early (backtick, pipe, backslash, CR,
  # LF) along with the rest that no existing row uses.
  # Matched as one string, in the C locale so that A-Z means the 26 letters.
  re="^$kind-[0-9]+-[A-Za-z0-9._-]+[.]md\$"
  ( LC_ALL=C; [[ $base =~ $re ]] ) \
    || die "the report filename cannot be a slot row: $base
  Allowed after '$kind-<number>-' are letters, digits, dot, underscore and
  dash, ending in .md. Rename the report. Nothing was claimed." 1

  # git configuration handed over in the environment would apply to every git
  # call below, url rewrites included, and it is among what the next step
  # clears. Rather than drop it unseen, claim does not run with it.
  if [ -n "${GIT_CONFIG_PARAMETERS:-}" ] || [ -n "${GIT_CONFIG_COUNT:-}" ] || [ -n "${GIT_CONFIG:-}" ]; then
    die "git configuration is set in the environment (GIT_CONFIG_PARAMETERS,
  GIT_CONFIG_COUNT or GIT_CONFIG). claim cannot check it against the remote and
  does not run with it. Nothing was claimed." 1
  fi

  # Called from a git hook, GIT_DIR and GIT_INDEX_FILE point at the CALLER's
  # repository and would turn every git call below towards it.
  # shellcheck disable=SC2046
  unset $(git rev-parse --local-env-vars)
  slot_ledger "$table"

  CLAIM_DIR=$(mktemp -d "${TMPDIR:-/tmp}/bugtracker-claim.XXXXXX")
  name=$(basename "$CLAIM_DIR")
  CLAIM_PRIV="refs/bugtracker/$name"; CLAIM_WT="$CLAIM_DIR/$name"
  trap claim_cleanup EXIT
  row="| $num | \`$base\` | angelegt $(date +%Y-%m-%d) | belegt via bugtracker.sh claim |"

  round=0
  while [ "$round" -lt "$CLAIM_ROUNDS" ]; do
    round=$((round + 1))

    # The remote decides, not this checkout. Fetched by URL into this claim's
    # own ref, so the checkout's tracking refs are neither trusted nor moved.
    out=$(git -C "$LEDGER_REPO" fetch -q --no-tags "$LEDGER_URL" \
            "+refs/heads/$LEDGER_BRANCH:$CLAIM_PRIV" 2>&1) \
      || claim_stop "cannot read $LEDGER_REF:
$out"
    tip=$(git -C "$LEDGER_REPO" rev-parse "$CLAIM_PRIV")
    # A refused push with the branch where it was is not yet a verdict: two
    # pushes arriving together can have one turned away while the other still
    # holds the ref, and a fetch in that moment sees the old tip. So this is
    # tried again like any other round, after a pause, and only a remote that
    # refuses every round ends the claim.
    [ "$tip" != "$last" ] || sleep 1
    last=$tip

    git -C "$LEDGER_REPO" show "$tip:$LEDGER_REL" > "$CLAIM_DIR/table" 2>/dev/null \
      || claim_stop "$LEDGER_REF does not carry the slot table at $LEDGER_REL"

    # A table claim can write to has exactly one ANKER row and ends with a
    # newline. Anything else is refused as it stands: claim adds one row and
    # repairs nothing, not even a missing final newline.
    [ "$(grep -c '^| ANKER |' "$CLAIM_DIR/table" || true)" = "1" ] \
      || claim_stop "the slot table on $LEDGER_REF has no ANKER row, or more than one.
  New claims go directly under that row; without it this is not a table claim
  can write to, and claim repairs nothing: nothing was repaired."
    [ "$(tail -c 1 "$CLAIM_DIR/table" | wc -l | tr -d ' ')" = "1" ] \
      || claim_stop "the slot table on $LEDGER_REF does not end with a newline.
  claim repairs nothing: nothing was repaired."

    # Already taken? Read with slot_rows, the reading next-id uses: the number
    # counts as a number, so 300 and 0300 are the same slot. The same file means
    # nothing to do; a different one is the collision this exists to surface.
    holders=$(slot_rows "$kind" "$CLAIM_DIR/table" | awk -F'\t' -v n="$want" '$1 == n { print $2 }')
    if [ -n "$holders" ]; then
      other=$(printf '%s\n' "$holders" | grep -v -x -F -- "$base" | head -1 || true)
      if [ -z "$other" ]; then
        echo "$id already claimed by this file on $LEDGER_REF, nothing to do"
        return 0
      fi
      claim_stop "$id is already claimed by '$other' on $LEDGER_REF.
  Yours is '$base'. One of them has to move, and the later one yields.
  Get a fresh number with: $(basename "$0") next-id $kind"
    fi

    # The row goes directly under the ANKER row. This is what the claim is
    # allowed to commit; the commit is compared against it below.
    ROW="$row" awk '{ print } /^\| ANKER \|/ { print ENVIRON["ROW"] }' \
        "$CLAIM_DIR/table" > "$CLAIM_DIR/want"

    # What was just written must read back, through the one reader, as exactly
    # one entry for this number and exactly this file. If it does not, the row
    # would be invisible to the next claim, and that is how one number gets two
    # files.
    back=$(slot_rows "$kind" "$CLAIM_DIR/want" | awk -F'\t' -v n="$want" '$1 == n { print $2 }')
    [ "$back" = "$base" ] \
      && [ "$(wc -l < "$CLAIM_DIR/want" | tr -d ' ')" = "$(( $(wc -l < "$CLAIM_DIR/table" | tr -d ' ') + 1 ))" ] \
      || claim_stop "the row for $id does not read back as one entry for '$base'."

    # The commit is checked against these three values further down. They are
    # taken now, from git objects, and kept in this process: nothing that runs
    # during the commit can rewrite them.
    mode=$(git -C "$LEDGER_REPO" ls-tree "$tip" -- "$LEDGER_REL" | cut -d' ' -f1)
    blob=$(git -C "$LEDGER_REPO" rev-parse "$tip:$LEDGER_REL")
    want_blob=$(git -C "$LEDGER_REPO" hash-object -w -- "$CLAIM_DIR/want")

    # A worktree of our own at the remote tip: the repository's own hooks run,
    # and the checkout that holds $M3C_SLOT_TABLE is not written to, whatever
    # else lies uncommitted in it.
    out=$(git -C "$LEDGER_REPO" worktree add --detach "$CLAIM_WT" "$tip" 2>&1) \
      || claim_stop "cannot check out $LEDGER_REF to write the claim:
$out"
    cat "$CLAIM_DIR/want" > "$CLAIM_WT/$LEDGER_REL"
    git -C "$CLAIM_WT" add -- "$LEDGER_REL"
    out=$(git -C "$CLAIM_WT" commit -q -m "slot: $id is $base (bugtracker.sh claim)" 2>&1) \
      || claim_stop "the commit of the claim was refused (a hook, or no git identity):
$out"
    new=$(git -C "$CLAIM_WT" rev-parse HEAD)

    # Hooks of the table's repository ran during that commit. They are trusted
    # not to work against claim on purpose, but a hook that stages a file,
    # reformats the table or commits again would otherwise ride along. So the
    # commit is read back from git and compared with what was authorised:
    # its only parent is the commit that was read, and against that parent it
    # changes one path, the table, from the blob that was read to the blob
    # computed above, with the file mode unchanged. That blob is the table as
    # read plus the one row, so no other row can have been dropped or altered.
    expect=":$mode $mode $blob $want_blob M	$LEDGER_REL"
    got=$(git -C "$LEDGER_REPO" -c core.quotepath=false diff-tree -r --no-renames --raw --no-abbrev "$tip" "$new")
    [ "$(git -C "$LEDGER_REPO" rev-list --parents -n 1 "$new")" = "$new $tip" ] \
      && [ "$got" = "$expect" ] \
      || claim_stop "the commit of the claim is not the one row on top of what was read:
  a hook or a content filter of the table's repository added to it or changed
  it. This commit was not pushed.
  expected: $expect
  found:    $got"

    # The allocation. A plain push moves the branch from $tip to $new or not at
    # all: if anyone pushed in between, the remote refuses, and we start over
    # from what it holds now. Never forced, never merged.
    #
    # What happened is read from the push's status line for the branch, not
    # from its exit code alone: "ok" means the remote updated the branch, also
    # if the connection broke afterwards; "!" means the remote answered with a
    # refusal. No status line means no answer: the push may or may not have
    # landed, and that is remembered, because from then on "nothing was
    # claimed" cannot be said.
    pushes=$((pushes + 1))
    rc=0; out_push=$(git -C "$LEDGER_REPO" push --porcelain "$LEDGER_URL" "$new:refs/heads/$LEDGER_BRANCH" 2>&1) || rc=$?
    status=$(printf '%s\n' "$out_push" | grep -F -- ":refs/heads/$LEDGER_BRANCH$tab" | head -1 || true)
    case $status in
      ' '* | '+'* | '*'* | '='*) rc=0 ;;
      '!'*) [ "$rc" != 0 ] || rc=1 ;;
      *) [ "$rc" = 0 ] || unknown=$((unknown + 1)) ;;
    esac
    if [ "$rc" = 0 ]; then
      claim_cleanup
      echo "$id claimed for $base on $LEDGER_REF (${new:0:8})"
      note "claim: the row is on $LEDGER_REF. Your checkout of the table does not
  have it until you pull."
      return 0
    fi
    git -C "$LEDGER_REPO" worktree remove --force "$CLAIM_WT" >/dev/null 2>&1 || true
  done
  claim_stop "$id was not claimed in $CLAIM_ROUNDS rounds. The status of the last push:
  ${status:-no status line for the branch, the remote gave no answer}
$out_push"
}

# ----------------------------------------------------------------- close ----

cmd_close() {
  local id file kind allowed status comment="" num
  id=$(item_id "$1"); file=$(report_path "$1"); kind=$(kind_of "$id")
  allowed=$(statuses_for "$kind")
  case "$kind" in BUG) status=fixed ;; FR) status=implemented ;; esac
  shift
  while [ $# -gt 0 ]; do
    case "$1" in
      --status)  shift; status=$(canon_status "${1:-}") ;;
      --comment) shift; comment=${1:-} ;;
      *) die "close: unknown argument '$1'" ;;
    esac
    shift
  done
  case " $allowed " in *" $status "*) ;; *) die "status '$status' is not valid for a $kind (use: $allowed)";; esac

  # Solving an issue means serving the contract it belongs to. The Spec line may
  # legitimately say "none: <reason>"; what it may not do is be missing, which
  # is how the question gets skipped rather than answered.
  case " $DONE_STATES " in
    *" $status "*)
      [ -n "$(read_field "$file" Spec)" ] || die "refusing to close $id as '$status': the report has no '- **Spec:**' line.
  Record which SPEC this serves, or state 'none: <reason>' if it genuinely
  serves none. Either is an answer; a missing line is not." 1
      ;;
  esac

  set_field "$file" Status "$status"
  echo "$id: status -> $status"

  num=$(issue_ref "$file")
  [ -n "$num" ] || { note "$id has no linked issue. The private plane is up to date, nothing to close"; return 0; }

  local reason=completed
  case "$status" in wontfix|duplicate) reason="not planned" ;; esac

  local repo; repo=$(repo_for "$file")   # from the recorded Issue line, not the cwd

  need_gh
  if [ -n "$comment" ]; then
    redact_scan "$comment" || die "refusing to comment publicly on $id: the text carries private-plane content (SPEC-0358)" 1
    gh issue comment "$num" --repo "$repo" --body "$comment" >/dev/null
  fi
  gh issue close "$num" --repo "$repo" --reason "$reason" >/dev/null
  echo "closed $repo#$num ($reason)"
}

# ------------------------------------------------------------------ sync ----

cmd_sync() {
  local files drift=0 file id st num state
  if [ $# -gt 0 ]; then files=$(report_path "$1"); else files=$(find "$(bug_dir)" -maxdepth 1 \( -name 'BUG-*.md' -o -name 'FR-*.md' \) ! -name '*.public.md' | sort); fi
  need_gh
  while IFS= read -r file; do
    [ -n "$file" ] || continue
    num=$(issue_ref "$file"); [ -n "$num" ] || continue
    id=$(basename "$file" | sed -E -n 's/^((BUG|FR)-[0-9]{4}).*/\1/p')
    st=$(canon_status "$(read_field "$file" Status)")
    state=$(gh issue view "$num" --repo "$(repo_for "$file")" --json state -q .state 2>/dev/null || echo UNKNOWN)
    case "$st:$state" in
      fixed:CLOSED|implemented:CLOSED|wontfix:CLOSED|duplicate:CLOSED|open:OPEN|in-progress:OPEN) ;;
      unknown:*) echo "$id: report has no canonical Status line (issue is $state)"; drift=1 ;;
      *) echo "$id: report says '$st' but issue #$num is $state"; drift=1 ;;
    esac
  done <<<"$files"
  [ "$drift" -eq 0 ] && { echo "sync: reports and issues agree"; return 0; }
  exit 1
}

# ------------------------------------------------------------------ main ----

usage() { sed -n '3,50p' "$0" | sed 's/^#\{1,\} \{0,1\}//'; }

case "${1:-}" in
  next-id)      shift; cmd_next_id "$@" ;;
  claim)        shift; [ $# -ge 1 ] || die "claim needs an item id"; cmd_claim "$1" ;;
  path)         shift; [ $# -ge 1 ] || die "path needs an item id"; report_path "$1" ;;
  status)       shift; [ $# -ge 1 ] || die "status needs an item id"; cmd_status "$@" ;;
  issue)        shift; [ $# -ge 1 ] || die "issue needs an item id"; cmd_issue "$1" ;;
  spec)         shift; [ $# -ge 1 ] || die "spec needs an item id"; cmd_spec "$1" ;;
  redact-check) shift; cmd_redact_check "$@" ;;
  open)         shift; [ $# -ge 1 ] || die "open needs an item id"; cmd_open "$1" ;;
  close)        shift; [ $# -ge 1 ] || die "close needs an item id"; cmd_close "$@" ;;
  sync)         shift; cmd_sync "$@" ;;
  -h|--help|help|"") usage ;;
  *) die "unknown command '$1' (try --help)" ;;
esac

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
#   next-id [BUG|FR]              next free id of that kind (default BUG)
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
# Exit: 0 ok · 1 a check failed (drift, leak, refusal) · 2 usage/config error.
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
    git -C "$dir" ls-tree --name-only "$ref" bug-reports/ 2>/dev/null \
      | sed -E -n "s#.*/$kind-0*([0-9]+)-.*#\\1\\t$ref#p"
    printf '%s\n' "$ref" \
      | sed -E -n "s#.*[^a-z]$lower-?0*([0-9]+).*#\\1\\tbranch $ref#p"
  done
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

  all=$(claims "$kind" | sort -u)
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

  printf '%s-%04d\n' "$kind" "$((max + 1))"
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

#!/usr/bin/env bash
#
# scripts/bugtracker.test.sh: self-contained fixtures for scripts/bugtracker.sh.
#
# Builds a throwaway maintenance tree and stubs `gh` on PATH, so nothing here
# touches the network or creates a real issue. The point of most assertions is
# the REFUSALS: a public issue cannot be un-published, so every guard that keeps
# private-plane content off the public plane is tested from the failing side.
#
# No deps beyond bash + coreutils. Exit 0 = all assertions passed.
#
set -euo pipefail

# Fixtures legen Wegwerf-git-Repos an. Als Hook geerbte GIT_*-Variablen wuerden
# jeden git-Aufruf hier auf das AUFRUFENDE Repo umlenken. In
# m3c-tools-maintenance hat genau das 3076 Loeschungen in einen echten Index
# geschrieben (BUG-0213, zurueckgenommen, kein Datenverlust). Ein Fixture, das
# ein echtes Repo anfassen kann, ist eine Waffe, kein Test.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
      GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_PREFIX

# in_throwaway DIR: bricht ab, wenn git auf ein FREMDES Repo zeigt. Muss VOR
# dem ersten Schreibbefehl laufen: schon `git init` und `git config` schreiben,
# und `git config user.email` landete beim ersten Anlauf in der Config des
# echten Repos. "Noch kein Repo" ist in Ordnung; das ist der Normalfall vor
# `git init`. Pfade aufgeloest vergleichen (macOS: /var -> /private/var).
in_throwaway() {
  local want have
  want=$(cd "$1" 2>/dev/null && pwd -P) || { echo "FATAL: $1 fehlt" >&2; exit 2; }
  have=$(git rev-parse --show-toplevel 2>/dev/null) || return 0
  [ "$have" = "$want" ] || { echo "FATAL: git zeigt auf $have, nicht auf $want" >&2; exit 2; }
}


BT="$(cd "$(dirname "$0")" && pwd)/bugtracker.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

export M3C_MAINTENANCE_DIR="$TMP/maint"
export M3C_BUG_REPO="acme/widget"
mkdir -p "$M3C_MAINTENANCE_DIR/bug-reports"
BUGS="$M3C_MAINTENANCE_DIR/bug-reports"

# --- gh stub: records the call, answers the few things the script reads --------
mkdir -p "$TMP/bin"
cat > "$TMP/bin/gh" <<'GHEOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$GH_CALLS"
case "$1 $2" in
  "issue create") echo "https://github.com/acme/widget/issues/${GH_NEW_ISSUE:-77}" ;;
  "issue view")   echo "${GH_ISSUE_STATE:-OPEN}" ;;
  *) : ;;
esac
GHEOF
chmod +x "$TMP/bin/gh"
export PATH="$TMP/bin:$PATH"
export GH_CALLS="$TMP/gh-calls.log"
: > "$GH_CALLS"

pass=0; fail=0
ok()   { pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf '  FAIL %s\n' "$1"; }
is()   { [ "$2" = "$3" ] && ok "$1" || bad "$1 (got '$2', want '$3')"; }
# refuses DESC CMD... -> the command must exit non-zero
refuses() { local d=$1; shift; if "$@" >/dev/null 2>&1; then bad "$d (it did NOT refuse)"; else ok "$d"; fi; }
accepts() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d (it refused)"; fi; }

# --- next-id ------------------------------------------------------------------
is "next-id on an empty tree" "$("$BT" next-id)" "BUG-0001"

: > "$BUGS/BUG-0007-alpha.md"
: > "$BUGS/BUG-0042-beta.md"
: > "$BUGS/FR-0099-not-a-bug.md"
is "next-id takes the max, ignores the other kind" "$("$BT" next-id)" "BUG-0043"
is "next-id FR counts FR files"                     "$("$BT" next-id FR)" "FR-0100"
is "next-id fr is case-insensitive"                 "$("$BT" next-id fr)" "FR-0100"
rm "$BUGS/BUG-0007-alpha.md" "$BUGS/BUG-0042-beta.md" "$BUGS/FR-0099-not-a-bug.md"
is "next-id FR on an empty tree" "$("$BT" next-id FR)" "FR-0001"

# --- next-id sees claims outside the working tree ------------------------------
#
# Reading max+1 out of one tree is how two sessions get handed the same id. This
# rebuilds the real case: a number taken on master, another on someone else's
# unmerged branch, and a third claimed by a BRANCH NAME before any file exists.

GITBUGS="$TMP/gitmaint"
mkdir -p "$GITBUGS/bug-reports"
( cd "$GITBUGS"
  in_throwaway "$GITBUGS"     # VOR dem ersten Schreibbefehl
  git init -q -b master; git config user.email t@t; git config user.name t
  in_throwaway "$GITBUGS"
  printf '# FR-0001\n' > bug-reports/FR-0001-on-master.md
  git add -A >/dev/null; git commit -qm one
  # someone else's unmerged work: a file that exists on no other checkout
  git checkout -q -b feat/other
  printf '# FR-0003\n' > bug-reports/FR-0003-on-a-branch.md
  git add -A >/dev/null; git commit -qm three
  # the earliest claim there is: a branch named before its file is written
  git checkout -q -b docs/fr-0005-not-written-yet
  git checkout -q master ) >/dev/null 2>&1

is "the working tree alone sees only FR-0001" \
   "$(ls "$GITBUGS/bug-reports" | sed -nE 's/^FR-0*([0-9]+)-.*/\1/p' | sort -n | tail -1)" "1"
is "next-id skips a file on another branch AND a branch-name claim" \
   "$(M3C_MAINTENANCE_DIR=$GITBUGS "$BT" next-id FR --no-fetch)" "FR-0006"
is "the reason is reported, naming where the ceiling came from" \
   "$(M3C_MAINTENANCE_DIR=$GITBUGS "$BT" next-id FR --no-fetch 2>&1 >/dev/null | grep -c 'docs/fr-0005-not-written-yet')" "1"

# a BUG id must not be raised by an FR claim, and vice versa
is "kinds do not bleed into each other" \
   "$(M3C_MAINTENANCE_DIR=$GITBUGS "$BT" next-id BUG --no-fetch)" "BUG-0001"

# a non-git bug dir must keep working exactly as before
is "a bug-reports dir outside git still resolves" "$("$BT" next-id FR)" "FR-0001"

refuses "next-id rejects an unknown flag" "$BT" next-id FR --nope

# --- a realistic report -------------------------------------------------------
REPORT="$BUGS/BUG-0213-widget-drops-the-last-frame.md"
cat > "$REPORT" <<'EOF'
# BUG-0213: widget drops the last frame

- **Datum:** 2026-09-03
- **Severity:** S2
- **Component:** widget/render
- **Status:** Fixed (2026-03-21)

## Symptom

Internal note: the queue drains via /upload_2 against 127.0.0.1:8081.
EOF

is "id normalises from a bare number"   "$("$BT" path 213)"        "$REPORT"
is "id normalises from lowercase"       "$("$BT" path bug-0213)"   "$REPORT"
is "id normalises from a filename"      "$("$BT" path BUG-0213-widget-drops-the-last-frame.md)" "$REPORT"
refuses "path refuses an unknown id"    "$BT" path 999

# --- status: read tolerates legacy spellings, write is canonical --------------
is "legacy 'Fixed (date)' reads as fixed" "$("$BT" status 213)" "fixed"
is "status write returns the canonical value" "$("$BT" status 213 OPEN)" "open"
is "status write is canonical in the file" \
   "$(grep -c '^- \*\*Status:\*\* open$' "$REPORT")" "1"
is "status write does not duplicate the line" \
   "$(grep -c '^\s*[-* ]*\*\*Status:\*\*' "$REPORT")" "1"
refuses "status refuses an unknown value" "$BT" status 213 banana

NOSTATUS="$BUGS/BUG-0214-no-metadata-block.md"
printf '# BUG-0214, no metadata block\n\nJust prose.\n' > "$NOSTATUS"
is "status is inserted when absent" "$("$BT" status 214 open)" "open"
is "the inserted line sits under the title" "$(sed -n '3p' "$NOSTATUS")" "- **Status:** open"

# --- redact-check: the five SPEC-0358 patterns --------------------------------
accepts "redact-check passes clean text" \
  bash -c "printf 'Observed: the last frame is dropped. See BUG-0213.\n' | '$BT' redact-check -"
refuses "redact-check catches a private-repo path" \
  bash -c "printf 'see m3c-tools-maintenance/bug-reports/x.md\n' | '$BT' redact-check -"
refuses "redact-check catches an internal endpoint" \
  bash -c "printf 'against 127.0.0.1:8081\n' | '$BT' redact-check -"
refuses "redact-check catches an ER1 context-id" \
  bash -c "printf 'ctx 123456789012345678901___skills\n' | '$BT' redact-check -"
refuses "redact-check catches a secret header" \
  bash -c "printf 'send X-API-KEY: ...\n' | '$BT' redact-check -"
refuses "redact-check catches an internal API path" \
  bash -c "printf 'POST /upload_2\n' | '$BT' redact-check -"
accepts "an ID-only private reference stays clean" \
  bash -c "printf 'Tracked internally as BUG-0213.\n' | '$BT' redact-check -"

# --- open: fail-closed on every missing guard ---------------------------------
refuses "open refuses without a Public declaration" "$BT" open 213
is "no issue was created" "$(grep -c 'issue create' "$GH_CALLS" || true)" "0"

"$BT" status 213 open >/dev/null
printf '%s\n' "- **Public:** yes" >> "$REPORT"
refuses "open refuses without a redacted body" "$BT" open 213

PUB="$BUGS/BUG-0213-widget-drops-the-last-frame.public.md"
cat > "$PUB" <<'EOF'
# widget drops the last frame when the queue drains

Observed: the internal path /upload_2 is called once too often.
EOF
refuses "open refuses a redacted body that still leaks" "$BT" open 213
is "still no issue was created" "$(grep -c 'issue create' "$GH_CALLS" || true)" "0"

cat > "$PUB" <<'EOF'
# widget drops the last frame when the queue drains

**Observed:** the last frame of a drain is not written.
**Expected:** every frame is written.
**Version:** 2.11.0
EOF
accepts "open publishes once the body is clean" "$BT" open 213
is "the issue is linked back into the report" "$("$BT" issue 213)" "acme/widget#77"
is "exactly one issue was created" "$(grep -c 'issue create' "$GH_CALLS")" "1"
accepts "open is idempotent" "$BT" open 213
is "still exactly one issue was created" "$(grep -c 'issue create' "$GH_CALLS")" "1"

is "the public body is not mistaken for a report" "$("$BT" path 213)" "$REPORT"

# --- close: the Spec question must be ANSWERED, not skipped -------------------
refuses "close as done refuses a report with no Spec line" "$BT" close 213
is "the status was not changed by the refusal" "$("$BT" status 213)" "open"
accepts "close as wontfix does not need a Spec line" "$BT" close 213 --status wontfix
"$BT" status 213 open >/dev/null

printf '%s\n' "- **Spec:** none: a rendering slip, no contract to change" >> "$REPORT"
accepts "a 'none: reason' Spec answer satisfies the rule" "$BT" close 213
is "spec reads back the recorded answer" \
   "$("$BT" spec 213)" "none: a rendering slip, no contract to change"
"$BT" status 213 open >/dev/null

# --- close: both planes, and the comment is checked too -----------------------
: > "$GH_CALLS"          # count only the calls the assertions below are about
refuses "close refuses a leaking public comment" \
  "$BT" close 213 --comment "fixed in m3c-tools-maintenance/SPEC/SPEC-0001-x.md"
is "no close was issued by the leaking comment" "$(grep -c 'issue close 77' "$GH_CALLS" || true)" "0"

accepts "close sets the status and closes the issue" \
  "$BT" close 213 --comment "Fixed in v2.11.1. See BUG-0213."
is "the report is fixed"  "$("$BT" status 213)" "fixed"
is "the issue was closed as completed" \
   "$(grep -c 'issue close 77 --repo acme/widget --reason completed' "$GH_CALLS")" "1"

: > "$GH_CALLS"
accepts "close --status wontfix closes as not planned" "$BT" close 213 --status wontfix
is "wontfix closes with 'not planned'" \
   "$(grep -c "reason not planned" "$GH_CALLS")" "1"

: > "$GH_CALLS"
printf '%s\n' "- **Spec:** SPEC-0401" >> "$NOSTATUS"
accepts "close on an unlinked report touches no issue" "$BT" close 214
is "no gh call was made" "$(wc -l < "$GH_CALLS" | tr -d ' ')" "0"

# --- the FR kind: same machinery, one different word --------------------------
FR="$BUGS/FR-0096-declarative-data-requirements.md"
cat > "$FR" <<'EOF'
# FR-0096: declarative data requirements

- **Status:** open
- **Spec:** SPEC-0401 §1
- **Public:** yes
EOF
is "an FR id is resolved by kind"      "$("$BT" path FR-0096)" "$FR"
is "a lowercase short FR id resolves"  "$("$BT" path fr-96)"   "$FR"
refuses "a bare number never resolves to an FR" "$BT" path 96

is "an FR closes as implemented, not fixed" "$("$BT" status FR-0096 implemented)" "implemented"
refuses "'fixed' is not a valid FR status"  "$BT" status FR-0096 fixed
"$BT" status FR-0096 open >/dev/null
refuses "'implemented' is not a valid BUG status" "$BT" status 213 implemented

cat > "${FR%.md}.public.md" <<'EOF'
# Declare a skill's data requirements semantically

A skill should say what KIND of data it needs, not which server holds it today.
EOF
: > "$GH_CALLS"
GH_NEW_ISSUE=88 accepts "an FR opens an issue too" "$BT" open FR-0096
is "an FR is labelled enhancement, not bug" \
   "$(grep -c 'label enhancement' "$GH_CALLS")" "1"
is "the FR issue is linked back" "$("$BT" issue FR-0096)" "acme/widget#88"

: > "$GH_CALLS"
accepts "closing an FR defaults to implemented" "$BT" close FR-0096
is "the FR is implemented" "$("$BT" status FR-0096)" "implemented"
is "the FR issue closed as completed" "$(grep -c 'issue close 88 .* --reason completed' "$GH_CALLS")" "1"

# --- the target repository belongs to the ITEM, not to the cwd ----------------
#
# The regression this guards: repo_for used to read `git remote origin`, so the
# same command addressed a different repository depending on where you stood,
# and `close` ignored the repo the item had already recorded.

# a throwaway checkout whose origin is a DIFFERENT repository
OTHER="$TMP/other-checkout"
mkdir -p "$OTHER"; ( cd "$OTHER"; in_throwaway "$OTHER"; git init -q; in_throwaway "$OTHER"; git remote add origin https://github.com/someone/unrelated.git )

: > "$GH_CALLS"
( cd "$OTHER" && M3C_BUG_REPO= "$BT" close 213 --status wontfix >/dev/null 2>&1 )
is "close from a foreign checkout still targets the recorded repo" \
   "$(grep -c 'issue close 77 --repo acme/widget' "$GH_CALLS")" "1"

: > "$GH_CALLS"
( cd "$OTHER" && M3C_BUG_REPO=wrong/repo "$BT" close 213 --status wontfix >/dev/null 2>&1 )
is "a stray M3C_BUG_REPO cannot redirect an item that has an issue" \
   "$(grep -c 'issue close 77 --repo acme/widget' "$GH_CALLS")" "1"
"$BT" status 213 open >/dev/null

: > "$GH_CALLS"
( cd "$OTHER" && GH_ISSUE_STATE=OPEN M3C_BUG_REPO=wrong/repo "$BT" sync 213 >/dev/null 2>&1 )
is "sync reads the state from the recorded repo" \
   "$(grep -c 'issue view 77 --repo acme/widget' "$GH_CALLS")" "1"

# --- open, before an issue exists ---------------------------------------------
DECL="$BUGS/BUG-0215-declares-its-own-repo.md"
cat > "$DECL" <<'EOF'
# BUG-0215: declares its own repo

- **Status:** open
- **Public:** yes
- **Repo:** declared/target
EOF
cat > "${DECL%.md}.public.md" <<'EOF'
# a title

a clean body
EOF
: > "$GH_CALLS"
GH_NEW_ISSUE=91 accepts "open uses the declared Repo line" \
  bash -c "M3C_BUG_REPO=env/override '$BT' open 215"
is "the file outranks the environment" "$(grep -c 'issue create --repo declared/target' "$GH_CALLS")" "1"
is "the backlink records the repo it published to" "$("$BT" issue 215)" "declared/target#91"

NOREPO="$BUGS/BUG-0216-declares-nothing.md"
cat > "$NOREPO" <<'EOF'
# BUG-0216: declares nothing

- **Status:** open
- **Public:** yes
EOF
cp "${DECL%.md}.public.md" "${NOREPO%.md}.public.md"
: > "$GH_CALLS"
refuses "open refuses when nothing declares a target" \
  bash -c "cd '$OTHER' && M3C_BUG_REPO= '$BT' open 216"
is "nothing was created without a target" "$(grep -c 'issue create' "$GH_CALLS" || true)" "0"
accepts "M3C_BUG_REPO fills the gap when the file is silent" \
  bash -c "cd '$OTHER' && M3C_BUG_REPO=env/fallback GH_NEW_ISSUE=92 '$BT' open 216"
is "the env fallback was used" "$(grep -c 'issue create --repo env/fallback' "$GH_CALLS")" "1"

BADREPO="$BUGS/BUG-0217-malformed-repo.md"
cat > "$BADREPO" <<'EOF'
# BUG-0217: malformed repo

- **Status:** open
- **Public:** yes
- **Repo:** https://github.com/owner/repo
EOF
cp "${DECL%.md}.public.md" "${BADREPO%.md}.public.md"
refuses "a malformed Repo value is rejected, not passed to gh" "$BT" open 217

# --- claim: die Vergabe wird ein Schreibvorgang -------------------------------
#
# next-id LIEST nur. Zwei Sessions, die im selben Moment fragen, bekommen dieselbe
# Zahl; so wurde FR-0096 zweimal vergeben. claim ist der Schreibvorgang.

CLAIMED="$BUGS/BUG-0300-nimmt-eine-nummer.md"
printf '# BUG-0300\n\n- **Status:** open\n' > "$CLAIMED"

refuses "claim ohne Slot-Tabelle verweigert" \
  bash -c "M3C_SLOT_TABLE= '$BT' claim 300"
refuses "claim mit fehlender Tabelle verweigert" \
  bash -c "M3C_SLOT_TABLE=$TMP/gibt-es-nicht.md '$BT' claim 300"

TABLE="$TMP/slots.md"
printf '| 0299 | `BUG-0299-alt.md` | x | y |\n' > "$TABLE"
accepts "claim schreibt die Zeile" bash -c "M3C_SLOT_TABLE=$TABLE '$BT' claim 300"
is "die Nummer steht jetzt in der Tabelle" \
   "$(grep -c '^| 0300 | `BUG-0300-nimmt-eine-nummer.md`' "$TABLE")" "1"
accepts "claim ist idempotent" bash -c "M3C_SLOT_TABLE=$TABLE '$BT' claim 300"
is "und schreibt keine zweite Zeile" \
   "$(grep -c '^| 0300 |' "$TABLE")" "1"

# Genau der Fall, um den es geht: jemand anders hat die Nummer schon.
RIVAL="$BUGS/BUG-0299-mein-zweitanspruch.md"
printf '# BUG-0299\n' > "$RIVAL"
refuses "claim verweigert eine fremd belegte Nummer" \
  bash -c "M3C_SLOT_TABLE=$TABLE '$BT' claim 299"
OUT=$(M3C_SLOT_TABLE=$TABLE "$BT" claim 299 2>&1 || true)
grep -q 'BUG-0299-alt.md' <<<"$OUT" && ok "und nennt, wer sie hat" || bad "nennt den Inhaber nicht"
grep -q 'later one yields' <<<"$OUT" && ok "und wer weicht" || bad "sagt nicht, wer weicht"
is "die Tabelle blieb unveraendert" "$(grep -c '^| 0299 |' "$TABLE")" "1"
rm "$RIVAL" "$CLAIMED"

# next-id sagt, dass eine gelesene Zahl noch keine Vergabe ist.
OUT=$("$BT" next-id BUG 2>&1 >/dev/null)
grep -q 'NOT yet allocated' <<<"$OUT" && ok "next-id sagt, dass die Zahl noch nicht belegt ist" \
  || bad "next-id verschweigt, dass die Zahl nicht belegt ist"

# --- sync ---------------------------------------------------------------------
"$BT" status 213 fixed >/dev/null
GH_ISSUE_STATE=CLOSED accepts "sync is quiet when both agree" "$BT" sync 213
GH_ISSUE_STATE=OPEN   refuses "sync reports a fixed report with an open issue" "$BT" sync 213
"$BT" status 213 open >/dev/null
GH_ISSUE_STATE=OPEN   accepts "sync agrees again once the report reopens" "$BT" sync 213

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]

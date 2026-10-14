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

# next-id sagt, dass eine gelesene Zahl noch keine Vergabe ist.
OUT=$("$BT" next-id BUG 2>&1 >/dev/null)
grep -q 'NOT yet allocated' <<<"$OUT" && ok "next-id sagt, dass die Zahl noch nicht belegt ist" \
  || bad "next-id verschweigt, dass die Zahl nicht belegt ist"

# --- die Slot-Tabelle als vierte Quelle (2026-09-15) --------------------------
# Eine Vormerkung existiert VOR jeder Datei und jedem Branch -- das ist ihr Zweck.
# Bis hierher las claims() nur Dateien, Refs und Branchnamen, und next-id gab
# deshalb Nummern aus, die seit Tagen vergeben waren: am 2026-09-15 antwortete es
# BUG-0268, waehrend die Tabelle 0268 seit dem Vortag hielt.
RESTAB="$TMP/reservierungen.md"
cat > "$RESTAB" <<'EOF'
| id | filename | proposal | allocate |
|----|----------|----------|----------|
| ANKER | **NEUE ANSPRUECHE DIREKT UNTER DIESE ZEILE** | n/a | Regel |
| 0800 | `BUG-0800-nur-vorgemerkt.md` | x | y |
EOF
OUT=$(M3C_SLOT_TABLE=$RESTAB "$BT" next-id BUG --no-fetch 2>&1)
grep -q 'BUG-0801' <<<"$OUT" \
  && ok "next-id sieht eine Vormerkung ohne Datei und ohne Branch" \
  || bad "next-id uebergeht die Slot-Tabelle (bekam: $(tail -1 <<<"$OUT"))"
grep -q 'slot table' <<<"$OUT" \
  && ok "und nennt die Tabelle als Quelle der Obergrenze" \
  || bad "nennt die Quelle nicht"

# Ohne Tabelle darf die Antwort nicht still unvollstaendig sein.
OUT=$(env -u M3C_SLOT_TABLE "$BT" next-id BUG --no-fetch 2>&1)
grep -q 'M3C_SLOT_TABLE is not set' <<<"$OUT" \
  && ok "ohne Tabelle sagt next-id, dass es Vormerkungen uebersieht" \
  || bad "ohne Tabelle schweigt next-id ueber die Luecke"

# --- claim: die Vergabe ist ein Commit auf dem geteilten Zweig ----------------
#
# next-id LIEST nur. Zwei Sessions, die im selben Moment fragen, bekommen dieselbe
# Zahl; so wurde FR-0096 zweimal vergeben. claim ist der Schreibvorgang, und der
# Schreibvorgang ist ein Push: Exit 0 heisst, der Zweig traegt die Zeile.
#
# Gemessen am 2026-10-13 an der Fassung davor, die nur die lokale Datei schrieb:
# von 200 gleichzeitigen Paaren meldeten 4 zweimal Exit 0 und hinterliessen zwei
# Zeilen derselben Nummer; und ein Klon, dessen Remote die Nummer schon vergeben
# hatte, meldete Exit 0. Die Faelle unten sind diese beiden und ihre Verwandten.

unset M3C_SLOT_TABLE M3C_SLOT_REF
LREL="DENK/slots.md"
CLAIMTMP="$TMP/claim-tmp"; mkdir -p "$CLAIMTMP"

# ledger NAME [ART]: ein blankes Remote mit Zweig `ledger` und der Tabelle.
# ART: anker (Vorgabe) | ohne | kein-zeilenende | zwei-anker | varianten | inhaber
ledger() {
  local name=$1 art=${2:-anker} seed="$TMP/$1-seed" anker
  anker='| ANKER | **NEUE ANSPRUECHE DIREKT UNTER DIESE ZEILE** | n/a | Regel |'
  git init -q --bare -b ledger "$TMP/$name.git"
  mkdir -p "$seed"; ( cd "$seed" && in_throwaway "$seed" )
  git init -q -b ledger "$seed"
  mkdir -p "$seed/DENK"
  {
    printf '| id | filename | proposal | allocate |\n|----|----------|----------|----------|\n'
    case $art in
      ohne)            printf '| 0299 | `BUG-0299-alt.md` | x | y |\n' ;;
      kein-zeilenende) printf '%s\n| 0299 | `BUG-0299-alt.md` | x | y |' "$anker" ;;
      zwei-anker)      printf '%s\n| 0299 | `BUG-0299-alt.md` | x | y |\n%s\n' "$anker" "$anker" ;;
      varianten)       printf '%s\n| 300 | `BUG-0300-nimmt-eine-nummer.md` | x | y |\n' "$anker"
                       printf '| 0600 | BUG-0600-ohne-backticks.md | x | y |\n'
                       printf '| 0601 | `bug-reports/BUG-0601-mit-pfad.md` | x | y |\n' ;;
      inhaber)         printf '%s\n' "$anker" '| 0500 | `BUG-0500-aXb.md` | x | y |' '| 0501 | `BUG-0501-a.md.alt.md` | x | y |' \
                         '| 0502 | `BUG-0502-eigen.md` | x | y |' '| 0502 | `BUG-0502-fremd.md` | x | y |' \
                         '| 0777 | `BUG-0503-unter-anderer-nummer.md` | x | y |' ;;
      *)               printf '%s\n| 0299 | `BUG-0299-alt.md` | x | y |\n' "$anker" ;;
    esac
  } > "$seed/$LREL"
  git -C "$seed" add -- "$LREL"
  git -C "$seed" -c user.name=seed -c user.email=seed@example.invalid commit -q -m seed
  git -C "$seed" push -q "$TMP/$name.git" ledger
}
# klon NAME SUFFIX: ein Klon des Remotes, mit Identitaet, auf `ledger`.
klon() {
  local dir="$TMP/$1-$2"
  git clone -q "$TMP/$1.git" "$dir"
  git -C "$dir" config user.name "klon-$2"; git -C "$dir" config user.email "$2@example.invalid"
  printf '%s\n' "$dir"
}
# Was der ZWEIG traegt. Jede Zusicherung unten liest hier, nie eine Arbeitskopie.
remote_tabelle() { git --git-dir="$TMP/$1.git" show "ledger:$LREL"; }
remote_kopf()    { git --git-dir="$TMP/$1.git" rev-parse ledger; }
remote_zeilen()  { remote_tabelle "$1" | grep -c "^| $2 |" || true; }
# meld DIR NUM SLUG: ein Bericht in einer eigenen Wartungsebene je Sitzung.
meld() { mkdir -p "$1/bug-reports"; printf '# BUG-%s\n\n- **Status:** open\n' "$2" > "$1/bug-reports/BUG-$2-$3.md"; }
# claim_in MAINT KLON ID: claim einer Sitzung; die Tabelle liegt in ihrem Klon.
claim_in() { TMPDIR="$CLAIMTMP" M3C_MAINTENANCE_DIR="$1" M3C_SLOT_TABLE="$2/$LREL" "$BT" claim "$3"; }
# Nichts bleibt liegen: kein Worktree, kein eigener Ref, kein Temp-Verzeichnis.
sauber() {
  local d=$1 k=$2
  is "$d: kein Worktree bleibt zurueck"  "$(git -C "$k" worktree list | wc -l | tr -d ' ')" "1"
  is "$d: kein eigener Ref bleibt zurueck" "$(git -C "$k" for-each-ref refs/bugtracker | wc -l | tr -d ' ')" "0"
  is "$d: kein Temp-Verzeichnis bleibt zurueck" "$(find "$CLAIMTMP" -mindepth 1 | wc -l | tr -d ' ')" "0"
  is "$d: der Klon ist unveraendert" "$(git -C "$k" status --porcelain | wc -l | tr -d ' ')" "0"
}

MA="$TMP/maint-a"; MB="$TMP/maint-b"

# Ohne Ort, an dem eine Vergabe gelten koennte, gibt es keine.
meld "$MA" 0300 nimmt-eine-nummer
refuses "claim ohne Slot-Tabelle verweigert" \
  bash -c "M3C_MAINTENANCE_DIR='$MA' M3C_SLOT_TABLE= '$BT' claim 300"
refuses "claim mit fehlender Tabelle verweigert" \
  bash -c "M3C_MAINTENANCE_DIR='$MA' M3C_SLOT_TABLE=$TMP/gibt-es-nicht.md '$BT' claim 300"
LOSE="$TMP/lose-tabelle.md"
printf '| 0299 | `BUG-0299-alt.md` | x | y |\n' > "$LOSE"
refuses "claim an einer Tabelle ausserhalb eines Repositoriums verweigert" \
  bash -c "M3C_MAINTENANCE_DIR='$MA' M3C_SLOT_TABLE='$LOSE' '$BT' claim 300"
is "und schreibt nichts in die lose Datei" "$(grep -c '0300' "$LOSE" || true)" "0"

ledger L1
KA=$(klon L1 a)
git -C "$KA" checkout -q --detach
refuses "claim ohne bestimmbaren Zweig verweigert" claim_in "$MA" "$KA" 300
is "und der Zweig blieb, wie er war" "$(remote_zeilen L1 0300)" "0"
git -C "$KA" checkout -q ledger

# T-Erfolg: die Zeile steht auf dem ZWEIG, als ein Commit mit einer Zeile.
VOR=$(remote_kopf L1)
accepts "claim etabliert die Zuordnung" claim_in "$MA" "$KA" 300
is "die Nummer steht auf dem Zweig" \
   "$(remote_tabelle L1 | grep -c '^| 0300 | `BUG-0300-nimmt-eine-nummer.md`')" "1"
is "als genau ein Commit" "$(git --git-dir="$TMP/L1.git" rev-list --count "$VOR..ledger")" "1"
is "der genau eine Datei beruehrt" \
   "$(git --git-dir="$TMP/L1.git" diff --name-only "$VOR" ledger | wc -l | tr -d ' ')" "1"
is "und genau eine Zeile hinzufuegt" \
   "$(git --git-dir="$TMP/L1.git" diff --numstat "$VOR" ledger | cut -f1,2 | tr '\t' ' ')" "1 0"
ZEILE=$(remote_tabelle L1 | grep -n '^| 0300 |' | cut -d: -f1)
ANKZ=$(remote_tabelle L1 | grep -n '^| ANKER |' | cut -d: -f1)
is "direkt unter dem ANKER" "$ZEILE" "$((ANKZ + 1))"
is "die Arbeitskopie der Tabelle wurde nicht angefasst" "$(grep -c '^| 0300 |' "$KA/$LREL" || true)" "0"
sauber "nach dem Erfolg" "$KA"

# T6: dieselbe Nummer, dieselbe Datei, noch einmal. Bestehende Semantik: Exit 0,
# nichts zu tun. Gemessen wird, dass der Zweig dabei nicht waechst.
VOR=$(remote_kopf L1)
accepts "claim ist idempotent" claim_in "$MA" "$KA" 300
is "und schreibt keine zweite Zeile" "$(remote_zeilen L1 0300)" "1"
is "und keinen zweiten Commit" "$(remote_kopf L1)" "$VOR"

# T1: nacheinander, dieselbe Nummer, eine andere Datei.
meld "$MB" 0300 mein-zweitanspruch
KB=$(klon L1 b)
refuses "claim verweigert eine fremd belegte Nummer" claim_in "$MB" "$KB" 300
OUT=$(claim_in "$MB" "$KB" 300 2>&1 || true)
grep -q 'BUG-0300-nimmt-eine-nummer.md' <<<"$OUT" && ok "und nennt, wer sie hat" || bad "nennt den Inhaber nicht"
grep -q 'later one yields' <<<"$OUT" && ok "und wer weicht" || bad "sagt nicht, wer weicht"
is "der Zweig blieb unveraendert" "$(remote_kopf L1)" "$VOR"
is "der Gewinner steht einmal" "$(remote_zeilen L1 0300)" "1"
is "der Verlierer steht nicht" "$(remote_tabelle L1 | grep -c 'mein-zweitanspruch' || true)" "0"
sauber "nach der Verweigerung" "$KB"

# T4: das Remote hat die Nummer inzwischen vergeben, der eigene Klon weiss es
# nicht. KB ist auf dem Stand VOR dem Anspruch auf 0301 und holt nichts selbst.
meld "$MA" 0301 zuerst; meld "$MB" 0301 zu-spaet
accepts "der erste Anspruch auf die Nummer gelingt" claim_in "$MA" "$KA" 301
VOR=$(remote_kopf L1)
is "der Klon ist wirklich veraltet" "$(git -C "$KB" show "origin/ledger:$LREL" | grep -c '^| 0301 |' || true)" "0"
refuses "ein veralteter Klon bekommt eine vergebene Nummer nicht" claim_in "$MB" "$KB" 301
OUT=$(claim_in "$MB" "$KB" 301 2>&1 || true)
grep -q 'BUG-0301-zuerst.md' <<<"$OUT" && ok "und erfaehrt vom Remote, wer sie hat" || bad "nennt den Inhaber auf dem Remote nicht"
is "der Zweig blieb unveraendert" "$(remote_kopf L1)" "$VOR"
is "die Nummer steht einmal" "$(remote_zeilen L1 0301)" "1"

# T3: zwei Klone, dieselbe freie Nummer, und der Gegner gewinnt GENAU im Fenster
# zwischen dem Lesen und dem Push. Ein Hook im Klon B loest den Anspruch von A
# aus, einmal. Das ist die Verschraenkung, die ein Zufallslauf nur selten trifft,
# hier bei jedem Lauf. Kein Eingriff in bugtracker.sh.
#
# Zwei Fenster, weil sie Verschiedenes pruefen. Im pre-commit-Hook hat B noch
# nicht mit dem Remote gesprochen: dort haelt allein der nicht erzwungene Push,
# und ein `--force` wuerde den Gewinner ueberschreiben. Im pre-push-Hook hat B
# den alten Stand schon ausgehandelt: dort lehnt das Remote auch einen
# erzwungenen Push ab, und geprueft ist, dass B danach neu liest.
fenster() {  # fenster HOOK KLON MAINT_GEGNER KLON_GEGNER ID
  local art=$1; shift
  local hook; hook="$(git -C "$1" rev-parse --git-common-dir)"
  case $hook in /*) ;; *) hook="$1/$hook" ;; esac
  cat > "$hook/hooks/$art" <<HOOK
#!/usr/bin/env bash
[ -e "$TMP/fenster-$4" ] && exit 0
: > "$TMP/fenster-$4"
unset \$(git rev-parse --local-env-vars)
TMPDIR="$CLAIMTMP" M3C_MAINTENANCE_DIR="$2" M3C_SLOT_TABLE="$3/$LREL" "$BT" claim "$4" > "$TMP/fenster-$4.out" 2>&1
echo \$? > "$TMP/fenster-$4.rc"
exit 0
HOOK
  chmod +x "$hook/hooks/$art"
}
meld "$MA" 0302 im-fenster-gewonnen; meld "$MB" 0302 im-fenster-verloren
meld "$MA" 0305 beim-push-gewonnen;  meld "$MB" 0305 beim-push-verloren
git -C "$KB" pull -q
for fall in "pre-commit 0302 im-fenster" "pre-push 0305 beim-push"; do
  set -- $fall; art=$1; nr=$2; slug=$3
  fenster "$art" "$KB" "$MA" "$KA" "${nr#0}"
  OUT=$(claim_in "$MB" "$KB" "${nr#0}" 2>&1) && bad "$art: wer im Fenster ueberholt wird, bekam die Nummer" \
    || ok "$art: wer im Fenster ueberholt wird, bekommt die Nummer nicht"
  grep -q "BUG-$nr-$slug-gewonnen.md" <<<"$OUT" && ok "$art: und erfaehrt, wer sie hat" || bad "$art: erfaehrt nicht, wer die Nummer hat"
  is "$art: der Gegner hat im Fenster wirklich gewonnen" "$(cat "$TMP/fenster-${nr#0}.rc" 2>/dev/null)" "0"
  is "$art: genau eine Zeile fuer die Nummer" "$(remote_zeilen L1 "$nr")" "1"
  is "$art: und es ist die des Gewinners" "$(remote_tabelle L1 | grep -c "^| $nr | \`BUG-$nr-$slug-gewonnen.md\`")" "1"
  is "$art: der Verlierer steht nirgends" "$(remote_tabelle L1 | grep -c "$slug-verloren" || true)" "0"
  is "$art: der Zweig hat keinen Merge-Commit" "$(git --git-dir="$TMP/L1.git" rev-list --merges --count ledger)" "0"
  sauber "$art: nach dem verlorenen Fenster" "$KB"
  rm -f "$KB/.git/hooks/$art"
done

# T5, verschraenkt: im selben Fenster zieht der Gegner eine ANDERE Nummer. Dann
# darf der zweite nicht scheitern: er liest neu und etabliert seine eigene.
meld "$MA" 0303 andere-nummer; meld "$MB" 0304 eigene-nummer
VOR=$(remote_kopf L1)
fenster pre-commit "$KB" "$MA" "$KA" 303
accepts "eine fremde Nummer im Fenster verhindert die eigene nicht" claim_in "$MB" "$KB" 304
is "die fremde steht" "$(remote_zeilen L1 0303)" "1"
is "die eigene steht" "$(remote_zeilen L1 0304)" "1"
is "zwei Commits, kein Merge" "$(git --git-dir="$TMP/L1.git" rev-list --count "$VOR..ledger") $(git --git-dir="$TMP/L1.git" rev-list --merges --count ledger)" "2 0"
rm -f "$KB/.git/hooks/pre-commit"

# T2 und T5, gleichzeitig: zwei Prozesse in EINER Arbeitskopie. Je Durchgang eine
# frische Nummer fuer beide (T2) und zwei verschiedene (T5). Vorgabe klein, weil
# jeder Anspruch einen Worktree anlegt; BT_CLAIM_RACE_N=500 faehrt die Messung.
N=${BT_CLAIM_RACE_N:-12}
ledger L2; KS=$(klon L2 s)
beide=0; keiner=0; doppelt=0; verschieden_rot=0
for i in $(seq 1 "$N"); do
  n=$(printf '%04d' $((1000 + i))); p=$(printf '%04d' $((3000 + i))); q=$(printf '%04d' $((5000 + i)))
  meld "$MA" "$n" links; meld "$MB" "$n" rechts; meld "$MA" "$p" links; meld "$MB" "$q" rechts
  ( rc=0; claim_in "$MA" "$KS" "$n" >/dev/null 2>&1 || rc=$?; echo "$rc" > "$TMP/r1" ) &
  ( rc=0; claim_in "$MB" "$KS" "$n" >/dev/null 2>&1 || rc=$?; echo "$rc" > "$TMP/r2" ) &
  wait
  a=$(cat "$TMP/r1"); b=$(cat "$TMP/r2")
  [ "$a" = 0 ] && [ "$b" = 0 ] && beide=$((beide + 1))
  [ "$a" != 0 ] && [ "$b" != 0 ] && keiner=$((keiner + 1))
  [ "$(remote_zeilen L2 "$n")" = 1 ] || doppelt=$((doppelt + 1))
  ( rc=0; claim_in "$MA" "$KS" "$p" >/dev/null 2>&1 || rc=$?; echo "$rc" > "$TMP/r1" ) &
  ( rc=0; claim_in "$MB" "$KS" "$q" >/dev/null 2>&1 || rc=$?; echo "$rc" > "$TMP/r2" ) &
  wait
  [ "$(cat "$TMP/r1")$(cat "$TMP/r2")" = 00 ] && [ "$(remote_zeilen L2 "$p")$(remote_zeilen L2 "$q")" = 11 ] \
    || verschieden_rot=$((verschieden_rot + 1))
done
is "gleichzeitig, gleiche Nummer, $N Durchgaenge: nie zwei Erfolge" "$beide" "0"
is "gleichzeitig, gleiche Nummer: immer genau ein Gewinner" "$keiner" "0"
is "gleichzeitig, gleiche Nummer: immer genau eine Zeile" "$doppelt" "0"
is "gleichzeitig, verschiedene Nummern, $N Durchgaenge: beide etabliert" "$verschieden_rot" "0"
is "der Zweig traegt keine Nummer doppelt" \
   "$(remote_tabelle L2 | sed -n -E 's/^\| ([0-9]+) \|.*/\1/p' | sort | uniq -d | wc -l | tr -d ' ')" "0"
is "der Zweig waechst um genau einen Commit je Vergabe" \
   "$(git --git-dir="$TMP/L2.git" rev-list --count ledger)" "$((1 + 3 * N))"
sauber "nach $N gleichzeitigen Durchgaengen" "$KS"

# Exit 0 erst nach der Etablierung: ein Remote, das den Push ablehnt.
ledger L3; KC=$(klon L3 c)
printf '#!/bin/sh\nexit 1\n' > "$TMP/L3.git/hooks/pre-receive"; chmod +x "$TMP/L3.git/hooks/pre-receive"
meld "$MA" 0320 abgelehnt
VOR=$(remote_kopf L3)
refuses "lehnt das Remote ab, ist nichts vergeben" claim_in "$MA" "$KC" 320
is "und der Zweig blieb, wie er war" "$(remote_kopf L3)" "$VOR"
OUT=$(claim_in "$MA" "$KC" 320 2>&1 || true)
grep -q 'Nothing was claimed' <<<"$OUT" && ok "und claim sagt, dass nichts vergeben ist" || bad "verschweigt, dass nichts vergeben ist"
grep -q 'pre-receive hook declined' <<<"$OUT" && ok "und nennt den Status des letzten Push" || bad "nennt den Status des letzten Push nicht"
grep -q 'NOT_ESTABLISHED' <<<"$OUT" && ok "und den Zustand NOT_ESTABLISHED" || bad "nennt den Zustand nicht"
sauber "nach dem abgelehnten Push" "$KC"

# Eine Ablehnung, nach der der Zweig steht, wo er stand, ist noch kein Urteil.
# Gemessen am 2026-10-13: in 1 von 500 gleichzeitigen Paaren mit verschiedenen
# Nummern scheiterte ein Anspruch, weil zwei Pushes zusammen ankamen, das Remote
# einen abwies, und der Blick danach noch den alten Stand sah. Hier lehnt das
# Remote genau den ersten Push ab und bewegt sich nicht; der Anspruch muss in
# der naechsten Runde gelingen.
meld "$MA" 0321 einmal-abgewiesen
printf '#!/bin/sh\n[ -e "%s" ] && exit 0\n: > "%s"\nexit 1\n' "$TMP/einmal" "$TMP/einmal" > "$TMP/L3.git/hooks/pre-receive"; chmod +x "$TMP/L3.git/hooks/pre-receive"
accepts "eine einzelne Ablehnung ohne Bewegung beendet den Anspruch nicht" claim_in "$MA" "$KC" 321
is "das Remote hat wirklich einmal abgewiesen" "$([ -e "$TMP/einmal" ] && echo ja)" "ja"
is "und die Zeile steht" "$(remote_zeilen L3 0321)" "1"
printf '#!/bin/sh\nexit 1\n' > "$TMP/L3.git/hooks/pre-receive"
VOR=$(remote_kopf L3)
rm -f "$TMP/L3.git/hooks/pre-receive"

# Die Hooks des Tabellen-Repositoriums laufen, sie werden nicht umgangen.
printf '#!/bin/sh\necho "tabellenpruefung: rot" >&2\nexit 1\n' > "$KC/.git/hooks/pre-commit"; chmod +x "$KC/.git/hooks/pre-commit"
refuses "ein roter pre-commit-Hook des Tabellen-Repos haelt den Anspruch an" claim_in "$MA" "$KC" 320
is "und nichts erreicht den Zweig" "$(remote_kopf L3)" "$VOR"
rm -f "$KC/.git/hooks/pre-commit"

# Eine geteilte, schmutzige Arbeitskopie: fremde Aenderungen, gestagt und nicht,
# gehen weder in den Commit noch verloren.
printf 'fremd, gestagt\n' > "$KC/fremd-gestagt.txt"; git -C "$KC" add -- fremd-gestagt.txt
printf 'fremd, lose\n' > "$KC/fremd-lose.txt"
printf '| 0998 | `BUG-0998-fremde-handzeile.md` | x | y |\n' >> "$KC/$LREL"
VORHER=$(git -C "$KC" status --porcelain)
accepts "claim gelingt neben fremden Aenderungen" claim_in "$MA" "$KC" 320
is "der Commit beruehrt nur die Tabelle" \
   "$(git --git-dir="$TMP/L3.git" diff --name-only "$VOR" ledger)" "$LREL"
is "die fremde Handzeile ist nicht mitgegangen" "$(remote_zeilen L3 0998)" "0"
is "die fremden Aenderungen liegen unveraendert da" "$(git -C "$KC" status --porcelain)" "$VORHER"

# --- was eine Tabelle sein muss, damit claim in sie schreibt -------------------
#
# Der ANKER ist Voraussetzung, nicht Empfehlung. Und claim repariert nichts: eine
# Tabelle ohne Zeilenende am Dateiende wird abgelehnt, wie sie ist. Gemessen an
# der Fassung davor: ohne ANKER und ohne Zeilenende klebte die neue Zeile an der
# letzten, wurde danach nicht mehr erkannt, und zwei Dateien bekamen dieselbe
# Nummer, beide mit Exit 0.
meld "$MA" 0811 erster; meld "$MB" 0811 zweiter
for art in ohne kein-zeilenende zwei-anker; do
  ledger "T-$art" "$art"; KT=$(klon "T-$art" t); KU=$(klon "T-$art" u)
  VOR=$(remote_kopf "T-$art")
  refuses "$art: claim verweigert" claim_in "$MA" "$KT" 811
  refuses "$art: auch der zweite bekommt die Nummer nicht" claim_in "$MB" "$KU" 811
  is "$art: der Zweig blieb, wie er war" "$(remote_kopf "T-$art")" "$VOR"
  OUT=$(claim_in "$MA" "$KT" 811 2>&1 || true)
  grep -q 'nothing was repaired' <<<"$OUT" && ok "$art: und claim sagt, dass es nichts repariert" \
    || bad "$art: verschweigt, dass nichts repariert wurde"
  sauber "$art" "$KT"
done

# --- eine Nummer ist eine Zahl, fuer next-id und fuer claim ---------------------
#
# Beide lesen ueber slot_rows. Eine ungepolsterte Zeile `| 300 |` belegt 0300.
# Eine Zeile ohne Backticks oder mit Pfad vor dem Namen ist fuer KEINEN der
# beiden eine Slot-Zeile; geprueft wird, dass sie sich darin einig sind, nicht,
# dass solche Zeilen erkannt wuerden.
ledger LV varianten; KV=$(klon LV v)
MN="$TMP/maint-leer"; mkdir -p "$MN/bug-reports"
meld "$MB" 0300 mein-zweitanspruch
VOR=$(remote_kopf LV)
refuses "eine ungepolstert belegte Nummer ist belegt" claim_in "$MB" "$KV" 300
OUT=$(claim_in "$MB" "$KV" 300 2>&1 || true)
grep -q 'BUG-0300-nimmt-eine-nummer.md' <<<"$OUT" && ok "und claim nennt den Inhaber der ungepolsterten Zeile" \
  || bad "nennt den Inhaber der ungepolsterten Zeile nicht"
accepts "dieselbe Datei auf der ungepolsterten Zeile: nichts zu tun" claim_in "$MA" "$KV" 300
is "und der Zweig blieb, wie er war" "$(remote_kopf LV)" "$VOR"
is "next-id liest dieselbe Zeile als 300" \
   "$(M3C_MAINTENANCE_DIR="$MN" M3C_SLOT_TABLE="$KV/$LREL" "$BT" next-id BUG --no-fetch 2>/dev/null)" "BUG-0301"
meld "$MA" 0600 neben-zeile-ohne-backticks; meld "$MA" 0601 neben-zeile-mit-pfad
accepts "eine Zeile ohne Backticks ist fuer claim keine Slot-Zeile" claim_in "$MA" "$KV" 600
accepts "eine Zeile mit Pfad vor dem Namen ist fuer claim keine Slot-Zeile" claim_in "$MA" "$KV" 601
git -C "$KV" pull -q
is "und next-id zaehlt danach genau die kanonischen Zeilen" \
   "$(M3C_MAINTENANCE_DIR="$MN" M3C_SLOT_TABLE="$KV/$LREL" "$BT" next-id BUG --no-fetch 2>/dev/null)" "BUG-0602"

# Die Art gehoert zur Nummer: BUG-0300 und FR-0300 sind zwei Slots.
printf '# FR-0300\n\n- **Status:** open\n' > "$MA/bug-reports/FR-0300-gleiche-zahl-andere-art.md"
accepts "dieselbe Zahl einer anderen Art ist frei" claim_in "$MA" "$KA" FR-300
is "und steht neben der BUG-Zeile" "$(remote_zeilen L1 0300)" "2"

# --- eine Authority, und sie muss eindeutig sein --------------------------------
#
# Gemessen an der Fassung davor: claim verglich die aufgeloesten URLs und gab
# sie dann als URL an git, das sie ein zweites Mal umschrieb. Mit insteadOf plus
# pushInsteadOf, oder wenn die URL eines Remotes dem Namen eines anderen glich,
# landete der Push in einem anderen Repositorium, Exit 0. Jetzt wird jede
# Konfiguration verweigert, die nicht erkennbar schlicht ist.
ledger LA; ledger LB; KW=$(klon LA w)
meld "$MA" 0343 authority
authority_bleibt() {  # authority_bleibt DESC: keines der beiden Repositorien bewegt, nichts angelegt
  is "$1: das gelesene Repositorium blieb, wie es war" "$(remote_kopf LA)" "$VORA"
  is "$1: das andere auch" "$(remote_kopf LB)" "$VORB"
  is "$1: nichts angelegt, bevor verweigert wurde" "$(find "$CLAIMTMP" -mindepth 1 | wc -l | tr -d ' ')" "0"
}
VORA=$(remote_kopf LA); VORB=$(remote_kopf LB)

git -C "$KW" config "url.$TMP/LB.git.pushInsteadOf" "$TMP/LA.git"
refuses "pushInsteadOf auf ein anderes Repositorium wird verweigert" claim_in "$MA" "$KW" 343
authority_bleibt "pushInsteadOf"
git -C "$KW" config --unset "url.$TMP/LB.git.pushInsteadOf"

git -C "$KW" config "url.$TMP/LB.git.insteadOf" "$TMP/LA.git"
refuses "insteadOf auf ein anderes Repositorium wird verweigert" claim_in "$MA" "$KW" 343
authority_bleibt "insteadOf"
git -C "$KW" config --unset "url.$TMP/LB.git.insteadOf"

# Nur die Lese-Seite umgeschrieben: insteadOf lenkt auf das andere Repositorium,
# eine pushInsteadOf-Regel haelt die Schreib-Seite auf dem konfigurierten.
git -C "$KW" config "url.$TMP/LB.git.insteadOf" "$TMP/LA.git"
git -C "$KW" config "url.$TMP/LA.git.pushInsteadOf" "$TMP/LA.git"
is "die Probe steht: gelesen wird woanders, geschrieben nicht" \
   "$(git -C "$KW" remote get-url origin) $(git -C "$KW" remote get-url --push origin)" "$TMP/LB.git $TMP/LA.git"
refuses "eine Umschreibung nur der Lese-Seite wird verweigert" claim_in "$MA" "$KW" 343
authority_bleibt "nur Lese-Seite"
git -C "$KW" config --unset "url.$TMP/LB.git.insteadOf"; git -C "$KW" config --unset "url.$TMP/LA.git.pushInsteadOf"

# Der Fall des Lesers: ein Alias loest auf das gelesene Repositorium auf, und
# erst die aufgeloeste URL trifft eine pushInsteadOf-Regel.
git -C "$KW" remote set-url origin "alias:la"
git -C "$KW" config "url.$TMP/LA.git.insteadOf" "alias:la"
git -C "$KW" config "url.$TMP/LB.git.pushInsteadOf" "$TMP/LA.git"
refuses "Alias plus pushInsteadOf wird verweigert" claim_in "$MA" "$KW" 343
authority_bleibt "Alias plus pushInsteadOf"
git -C "$KW" config --unset "url.$TMP/LB.git.pushInsteadOf"
refuses "ein Alias allein wird auch verweigert: claim folgt keiner Umschreibung" claim_in "$MA" "$KW" 343
authority_bleibt "Alias allein"
git -C "$KW" config --unset "url.$TMP/LA.git.insteadOf"
git -C "$KW" remote set-url origin "$TMP/LA.git"

# Die URL eines Remotes ist zugleich der Name eines anderen: git naehme den.
git -C "$KW" remote add spiegel "$TMP/LB.git"
git -C "$KW" remote set-url origin spiegel
refuses "eine URL, die ein Remote-Name ist, wird verweigert" claim_in "$MA" "$KW" 343
authority_bleibt "URL gleich Remote-Name"
git -C "$KW" remote set-url origin "$TMP/LA.git"
git -C "$KW" remote remove spiegel
# Dasselbe mit einem Namen, der einen Schraegstrich traegt und darum an der
# Regel fuer nackte Namen vorbeigeht.
git -C "$KW" config remote.spiegel/b.url "$TMP/LB.git"
git -C "$KW" remote set-url origin spiegel/b
refuses "eine URL, die ein Remote-Name mit Schraegstrich ist, wird verweigert" claim_in "$MA" "$KW" 343
authority_bleibt "URL gleich Remote-Name mit Schraegstrich"
git -C "$KW" remote set-url origin "$TMP/LA.git"
git -C "$KW" config --remove-section remote.spiegel/b

# Jede pushurl, auch eine gleichlautende: die Authority ist die url allein.
git -C "$KW" remote set-url --push origin "$TMP/LB.git"
refuses "eine pushurl auf ein anderes Repositorium wird verweigert" claim_in "$MA" "$KW" 343
authority_bleibt "pushurl"
git -C "$KW" remote set-url --push origin "$TMP/LA.git"
refuses "auch eine gleichlautende pushurl wird verweigert" claim_in "$MA" "$KW" 343
authority_bleibt "gleichlautende pushurl"
git -C "$KW" config --unset remote.origin.pushurl
git -C "$KW" config --add remote.origin.url "$TMP/LB.git"
refuses "zwei urls auf einem Remote werden verweigert" claim_in "$MA" "$KW" 343
authority_bleibt "zwei urls"
git -C "$KW" config --unset remote.origin.url "$TMP/LB.git"

# Ein Remote-Name mit Schraegstrich: der Zweig wird nicht am ersten Schraegstrich
# geraten. Passen zwei Remotes auf den Ref, ist er nicht eindeutig.
git -C "$KW" config remote.origin/zwei.url "$TMP/LB.git"   # nicht `remote add`: neueres git lehnt diesen Namen dort ab
refuses "ein Ref, auf den zwei Remote-Namen passen, wird verweigert" \
  env TMPDIR="$CLAIMTMP" M3C_MAINTENANCE_DIR="$MA" M3C_SLOT_TABLE="$KW/$LREL" M3C_SLOT_REF=origin/zwei/ledger "$BT" claim 343
authority_bleibt "zwei passende Remotes"
git -C "$KW" config --remove-section remote.origin/zwei

accepts "die schlichte Konfiguration geht" claim_in "$MA" "$KW" 343
is "und die Zeile steht im gelesenen Repositorium" "$(remote_zeilen LA 0343)" "1"
is "und nicht im anderen" "$(remote_zeilen LB 0343)" "0"

# Eine relative Remote-URL wird vom Repositorium aus aufgeloest, nicht vom
# temporaeren Worktree aus.
meld "$MA" 0341 relative-url
git -C "$KW" remote set-url origin ../LA.git
accepts "eine relative Remote-URL geht" claim_in "$MA" "$KW" 341
is "und die Zeile steht" "$(remote_zeilen LA 0341)" "1"

# M3C_SLOT_REF benennt den Zweig, wenn die Arbeitskopie woanders steht.
git -C "$KW" checkout -q --detach
meld "$MA" 0812 benannter-zweig
accepts "M3C_SLOT_REF benennt den kanonischen Zweig" \
  env TMPDIR="$CLAIMTMP" M3C_MAINTENANCE_DIR="$MA" M3C_SLOT_TABLE="$KW/$LREL" M3C_SLOT_REF=origin/ledger "$BT" claim 812
is "und dort steht die Zeile" "$(remote_zeilen LA 0812)" "1"
git -C "$KW" checkout -q ledger

# Aus einem Hook gerufen, zeigen GIT_INDEX_FILE und Verwandte auf das rufende
# Repositorium. claim legt sie ab, sonst schriebe es in den Index der Kopie.
meld "$MA" 0342 geerbte-umgebung
printf 'fremd, gestagt\n' > "$KW/fremd.txt"; git -C "$KW" add -- fremd.txt
VORHER=$(git -C "$KW" status --porcelain)
accepts "claim mit geerbtem GIT_INDEX_FILE gelingt" \
  env GIT_INDEX_FILE="$KW/.git/index" TMPDIR="$CLAIMTMP" M3C_MAINTENANCE_DIR="$MA" M3C_SLOT_TABLE="$KW/$LREL" "$BT" claim 342
is "und der Index der Arbeitskopie ist unveraendert" "$(git -C "$KW" status --porcelain)" "$VORHER"
is "und die Zeile steht" "$(remote_zeilen LA 0342)" "1"

# --- ein Dateiname ist ein Bezeichner ------------------------------------------------
#
# Gemessen an der Fassung davor: ein Dateiname mit `\n` wurde von awk als
# Zeilenumbruch geschrieben, slot_rows las die Zeile nicht mehr, und ein Zweiter
# bekam dieselbe Nummer mit Exit 0. Jetzt wird der Name geprueft, bevor
# irgendetwas geschieht, und die geschriebene Zeile wird zurueckgelesen.
ledger LN; KN=$(klon LN n); MX="$TMP/maint-x"; mkdir -p "$MX/bug-reports"
VOR=$(remote_kopf LN)
nr=400
for name in 'a\nb' 'a`b' 'a|b' 'gut.md|rest' 'a b' 'a>b' 'a,b' 'a+b' "a'b" 'a$b' 'a*b' 'ae-ä'; do
  nr=$((nr + 1))
  printf '# x\n' > "$MX/bug-reports/BUG-0$nr-$name.md"
  refuses "Dateiname mit [$name] wird verweigert" claim_in "$MX" "$KN" "$nr"
done
nr=$((nr + 1)); printf '# x\n' > "$MX/bug-reports/BUG-0$nr-a"$'\r'"b.md"
refuses "Dateiname mit Wagenruecklauf wird verweigert" claim_in "$MX" "$KN" "$nr"
nr=$((nr + 1)); printf '# x\n' > "$MX/bug-reports/BUG-0$nr-a"$'\n'"b.md"
refuses "Dateiname mit Zeilenumbruch wird verweigert" claim_in "$MX" "$KN" "$nr"
is "nach allen verweigerten Namen blieb der Zweig, wie er war" "$(remote_kopf LN)" "$VOR"
is "und es wurde nichts angelegt" "$(find "$CLAIMTMP" -mindepth 1 | wc -l | tr -d ' ')" "0"
OUT=$(claim_in "$MX" "$KN" 401 2>&1 || true)
grep -q 'cannot be a slot row' <<<"$OUT" && ok "und claim nennt den Grund" || bad "nennt den Grund nicht"

# Hin und zurueck: die Zeile, die claim schreibt, liest slot_rows als genau einen
# Eintrag derselben Nummer und derselben Datei, wortgleich.
meld "$MA" 0420 Hin_und.zurueck-1.2
accepts "ein Name aus dem erlaubten Vorrat geht" claim_in "$MA" "$KN" 420
remote_tabelle LN > "$TMP/hin-zurueck.md"
is "und liest sich als genau ein Eintrag derselben Zuordnung zurueck" \
   "$(bash -c 'source <(sed -n "/^slot_rows()/,/^}/p" "$1"); slot_rows BUG "$2"' _ "$BT" "$TMP/hin-zurueck.md" | awk -F'\t' '$1 == 420')" \
   "420	BUG-0420-Hin_und.zurueck-1.2.md"

# --- wer als Inhaber gilt ------------------------------------------------------------
#
# Die eigene Datei ist Inhaber nur bei wortgleichem Namen unter DIESER Nummer.
# Vier Faelle, in denen eine nachlaessigere Lesart Exit 0 gaebe, ohne dass die
# Zuordnung steht.
ledger LI inhaber; KI=$(klon LI i); MI="$TMP/maint-i"
VOR=$(remote_kopf LI)
meld "$MI" 0500 a.b
refuses "ein Name, der nur als Muster passt (a.b gegen aXb), ist nicht derselbe" claim_in "$MI" "$KI" 500
meld "$MI" 0501 a
refuses "ein Name, der nur als Anfang passt, ist nicht derselbe" claim_in "$MI" "$KI" 501
meld "$MI" 0502 eigen
refuses "die eigene Zeile neben einem fremden Inhaber genuegt nicht" claim_in "$MI" "$KI" 502
is "in allen drei Faellen blieb der Zweig, wie er war" "$(remote_kopf LI)" "$VOR"
OUT=$(claim_in "$MI" "$KI" 502 2>&1 || true)
grep -q "BUG-0502-fremd.md" <<<"$OUT" && ok "und claim nennt den fremden Inhaber" || bad "nennt den fremden Inhaber nicht"
meld "$MI" 0503 unter-anderer-nummer
accepts "der eigene Name unter einer ANDEREN Nummer belegt diese nicht" claim_in "$MI" "$KI" 503
is "und die Zeile fuer die eigene Nummer steht danach" "$(remote_zeilen LI 0503)" "1"

# Eine Zeile, die nur in der eigenen Arbeitskopie steht, ist keine Vergabe.
meld "$MI" 0504 nur-lokal-notiert
git -C "$KI" pull -q
printf '| 0504 | `BUG-0504-nur-lokal-notiert.md` | von Hand | nicht geschoben |\n' >> "$KI/$LREL"
accepts "eine nur lokal notierte Zeile ersetzt den Anspruch nicht" claim_in "$MI" "$KI" 504
is "die Zeile steht jetzt auf dem Zweig" "$(remote_zeilen LI 0504)" "1"
git -C "$KI" checkout -q -- "$LREL"

# --- was ein Hook des Tabellen-Repositoriums nicht kann -------------------------
#
# Gemessen an der Fassung davor: ein pre-commit-Hook, der selbst eine Datei
# stagt, bekam sie in den Commit des Anspruchs, und der wurde mit Exit 0
# geschoben. Jetzt wird der fertige Commit gegen die eine geschriebene Zeile
# verglichen, bevor irgendetwas das Repositorium verlaesst.
ledger LH; KH=$(klon LH h)
meld "$MA" 0350 hook-stagt-datei
VOR=$(remote_kopf LH)
printf '#!/bin/sh\necho eingeschleust > extra.txt\ngit add -- extra.txt\n' > "$KH/.git/hooks/pre-commit"; chmod +x "$KH/.git/hooks/pre-commit"
refuses "ein Hook, der eine Datei dazustagt, bekommt keinen Anspruch durch" claim_in "$MA" "$KH" 350
is "und nichts erreicht den Zweig" "$(remote_kopf LH)" "$VOR"
OUT=$(claim_in "$MA" "$KH" 350 2>&1 || true)
grep -q 'This commit was not pushed' <<<"$OUT" && ok "und claim sagt, dass dieser Commit nicht geschoben wurde" || bad "verschweigt, dass nichts geschoben wurde"
printf '#!/bin/sh\nprintf "%%s\\n" "| 0999 | \\`BUG-0999-vom-hook.md\\` | x | y |" >> %s\ngit add -- %s\n' "$LREL" "$LREL" > "$KH/.git/hooks/pre-commit"
refuses "ein Hook, der die Tabelle umschreibt, bekommt keinen Anspruch durch" claim_in "$MA" "$KH" 350
is "und nichts erreicht den Zweig" "$(remote_kopf LH)" "$VOR"
# Der Hook aendert das Dateirecht der Tabelle im selben Commit.
printf '#!/bin/sh\ngit update-index --chmod=+x -- %s\n' "$LREL" > "$KH/.git/hooks/pre-commit"
refuses "ein Hook, der das Dateirecht der Tabelle aendert, bekommt keinen Anspruch durch" claim_in "$MA" "$KH" 350
is "und nichts erreicht den Zweig" "$(remote_kopf LH)" "$VOR"
# Der Hook entfernt eine fremde Slot-Zeile und laesst die neue stehen.
printf '#!/bin/sh\ngrep -v "BUG-0299-alt.md" %s > %s.neu && mv %s.neu %s\ngit add -- %s\n' "$LREL" "$LREL" "$LREL" "$LREL" "$LREL" > "$KH/.git/hooks/pre-commit"
refuses "ein Hook, der eine fremde Zeile entfernt, bekommt keinen Anspruch durch" claim_in "$MA" "$KH" 350
is "und die fremde Zeile steht noch" "$(remote_zeilen LH 0299)" "1"
is "und nichts erreicht den Zweig" "$(remote_kopf LH)" "$VOR"
# Der Hook schreibt auch die Arbeitsdateien des Anspruchs um, die neben dem
# Worktree liegen. Die Vergleichswerte stehen nicht in einer Datei.
printf '#!/bin/sh\nfor f in ../want ../table; do grep -v "BUG-0299-alt.md" "$f" > "$f.neu" && mv "$f.neu" "$f"; done\ngrep -v "BUG-0299-alt.md" %s > %s.neu && mv %s.neu %s\ngit add -- %s\n' "$LREL" "$LREL" "$LREL" "$LREL" "$LREL" > "$KH/.git/hooks/pre-commit"
refuses "auch wenn der Hook die Arbeitsdateien des Anspruchs mit umschreibt" claim_in "$MA" "$KH" 350
is "steht die fremde Zeile noch" "$(remote_zeilen LH 0299)" "1"
is "und nichts erreicht den Zweig" "$(remote_kopf LH)" "$VOR"
rm -f "$KH/.git/hooks/pre-commit"
# Ein post-commit-Hook, der einen zweiten Commit daraufsetzt.
printf '#!/bin/sh\n[ -e "%s" ] && exit 0\n: > "%s"\ngit commit -q --allow-empty --no-verify -m zweiter\n' "$TMP/zweiter" "$TMP/zweiter" > "$KH/.git/hooks/post-commit"; chmod +x "$KH/.git/hooks/post-commit"
refuses "ein Hook, der einen zweiten Commit daraufsetzt, bekommt keinen Anspruch durch" claim_in "$MA" "$KH" 350
is "und nichts erreicht den Zweig" "$(remote_kopf LH)" "$VOR"
rm -f "$KH/.git/hooks/post-commit"
sauber "nach den Hook-Versuchen" "$KH"

# --- zwei Ansprueche zur selben Zeit im selben Repositorium ---------------------
#
# Kein Zufallslauf: ein pre-commit-Hook startet mitten im ersten Anspruch einen
# zweiten in DERSELBEN Arbeitskopie. Waehrend der zweite committet, laufen beide,
# und der Hook zaehlt, was nebeneinander liegt. Zwei Verzeichnisse, zwei Refs,
# zwei Worktrees: geteilt ist kein Pfad.
meld "$MA" 0360 aussen; meld "$MB" 0361 innen
cat > "$KH/.git/hooks/pre-commit" <<HOOK
#!/usr/bin/env bash
unset \$(git rev-parse --local-env-vars)
if [ -e "$TMP/zugleich-aussen" ]; then
  [ -e "$TMP/zugleich-refs" ] && exit 0   # nur der innere Commit zaehlt, nicht die zweite Runde des aeusseren
  find "$CLAIMTMP" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ' > "$TMP/zugleich-verzeichnisse"
  find "$CLAIMTMP" -mindepth 2 -maxdepth 2 -type f \\( -name table -o -name want \\) | wc -l | tr -d ' ' > "$TMP/zugleich-dateien"
  git -C "$KH" for-each-ref refs/bugtracker | wc -l | tr -d ' ' > "$TMP/zugleich-refs"
  git -C "$KH" worktree list | wc -l | tr -d ' ' > "$TMP/zugleich-worktrees"
  exit 0
fi
: > "$TMP/zugleich-aussen"
TMPDIR="$CLAIMTMP" M3C_MAINTENANCE_DIR="$MB" M3C_SLOT_TABLE="$KH/$LREL" "$BT" claim 361 > "$TMP/zugleich-innen.out" 2>&1
echo \$? > "$TMP/zugleich-innen.rc"
HOOK
chmod +x "$KH/.git/hooks/pre-commit"
accepts "der aeussere Anspruch gelingt, obwohl mittendrin ein zweiter lief" claim_in "$MA" "$KH" 360
is "der innere gelang auch" "$(cat "$TMP/zugleich-innen.rc" 2>/dev/null)" "0"
is "zugleich: zwei eigene Verzeichnisse" "$(cat "$TMP/zugleich-verzeichnisse" 2>/dev/null)" "2"
is "zugleich: jedes haelt seinen eigenen Tabellenstand und seine eigene Soll-Fassung" "$(cat "$TMP/zugleich-dateien" 2>/dev/null)" "4"
is "zugleich: zwei eigene Refs" "$(cat "$TMP/zugleich-refs" 2>/dev/null)" "2"
is "zugleich: zwei eigene Worktrees neben der Arbeitskopie" "$(cat "$TMP/zugleich-worktrees" 2>/dev/null)" "3"
is "beide Zeilen stehen" "$(remote_zeilen LH 0360)$(remote_zeilen LH 0361)" "11"
sauber "nach zwei Anspruechen zugleich" "$KH"
rm -f "$KH/.git/hooks/pre-commit"

# --- die Rundengrenze ---------------------------------------------------------------
# Bewegt sich der Zweig in JEDER Runde, gibt claim nach fuenf Runden auf, ohne
# etwas hinterlassen zu haben. Der Gegner zieht je Runde eine neue Nummer.
meld "$MA" 0370 kommt-nie-dran
for i in 1 2 3 4 5 6 7; do meld "$MB" "038$i" gegner; done
KG=$(klon LH g)
cat > "$KH/.git/hooks/pre-commit" <<HOOK
#!/usr/bin/env bash
unset \$(git rev-parse --local-env-vars)
n=\$(( \$(cat "$TMP/runden" 2>/dev/null || echo 0) + 1 )); echo \$n > "$TMP/runden"
TMPDIR="$CLAIMTMP" M3C_MAINTENANCE_DIR="$MB" M3C_SLOT_TABLE="$KG/$LREL" "$BT" claim "38\$n" >/dev/null 2>&1
exit 0
HOOK
chmod +x "$KH/.git/hooks/pre-commit"
OUT=$(claim_in "$MA" "$KH" 370 2>&1) && bad "claim gab nicht auf, obwohl der Zweig sich jede Runde bewegte" \
  || ok "claim gibt auf, wenn der Zweig sich jede Runde bewegt"
grep -q 'in 5 rounds' <<<"$OUT" && grep -q 'rejected' <<<"$OUT" && ok "und nennt die Zahl der Runden und den Status des letzten Push" || bad "nennt Rundenzahl oder Status nicht"
is "es waren genau fuenf Runden" "$(cat "$TMP/runden")" "5"
is "und die eigene Nummer steht nicht" "$(remote_zeilen LH 0370)" "0"
sauber "nach der Rundengrenze" "$KH"
rm -f "$KH/.git/hooks/pre-commit"

# Der letzte entscheidende Grund steht in der Meldung. Runde 1 verliert gegen
# einen Gegner (der Zweig bewegt sich), danach lehnt ein pre-push-Hook jede
# Runde ab und der Zweig steht. Gemessen an der Fassung davor: die Meldung
# lautete "kept moving" und der Text der Ablehnung fehlte.
meld "$MA" 0371 erst-bewegt-dann-abgelehnt; meld "$MB" 0372 gegner-einmal
cat > "$KH/.git/hooks/pre-push" <<HOOK
#!/usr/bin/env bash
unset \$(git rev-parse --local-env-vars)
if [ ! -e "$TMP/grund-einmal" ]; then
  : > "$TMP/grund-einmal"
  TMPDIR="$CLAIMTMP" M3C_MAINTENANCE_DIR="$MB" M3C_SLOT_TABLE="$KG/$LREL" "$BT" claim 372 >/dev/null 2>&1
  exit 0
fi
echo "richtlinie: freitags wird nicht geschoben" >&2
exit 1
HOOK
chmod +x "$KH/.git/hooks/pre-push"
OUT=$(claim_in "$MA" "$KH" 371 2>&1) && bad "claim gelang trotz ablehnendem Hook" || ok "claim scheitert am ablehnenden Hook"
is "der Gegner hat in Runde 1 wirklich gewonnen" "$(remote_zeilen LH 0372)" "1"
grep -q 'freitags wird nicht geschoben' <<<"$OUT" && ok "die Meldung traegt den Text der letzten Ablehnung" || bad "der Text der Ablehnung fehlt"
grep -q 'OUTCOME_UNKNOWN' <<<"$OUT" && ok "und sagt, dass ein lokal abgelehnter Push von aussen offen bleibt" || bad "nennt den Zustand nicht"
grep -q 'moved again' <<<"$OUT" && bad "und behauptet faelschlich Bewegung" || ok "und behauptet keine Bewegung"
sauber "nach erst bewegt, dann abgelehnt" "$KH"
rm -f "$KH/.git/hooks/pre-push"

# --- nach Beginn eines Push nur sagen, was zu sehen ist ---------------------------
#
# Gemessen an der Fassung davor: brach die Verbindung nach der Ref-Aktualisierung
# ab, meldete die naechste Runde "nothing was claimed", waehrend die Zeile stand.
# Jetzt endet ein Anspruch nach einem Push in einem von drei Zustaenden:
# ESTABLISHED (Exit 0), NOT_ESTABLISHED (Exit 1, jeder Push wurde mit einer
# Ablehnung beantwortet) oder OUTCOME_UNKNOWN (Exit 3).
ledger LU; KU2=$(klon LU u2)
# Das Remote aktualisiert den Zweig und reisst danach die Verbindung ab.
meld "$MA" 0450 verbindung-nach-dem-update-weg
printf '#!/bin/sh\nkill -9 $PPID\n' > "$TMP/LU.git/hooks/post-receive"; chmod +x "$TMP/LU.git/hooks/post-receive"
OUT=$(claim_in "$MA" "$KU2" 450 2>&1) && ok "Abbruch nach der Ref-Aktualisierung: Exit 0" || bad "Abbruch nach der Ref-Aktualisierung: kein Exit 0"
grep -q 'BUG-0450 claimed for BUG-0450-verbindung-nach-dem-update-weg.md' <<<"$OUT" \
  && ok "schon in dieser Runde aus der Statuszeile erkannt" || bad "die ok-Statuszeile wurde nicht als Erfolg gelesen"
is "und die Zeile steht" "$(remote_zeilen LU 0450)" "1"
grep -q 'nothing was claimed\|Nothing was claimed' <<<"$OUT" && bad "und behauptet, nichts sei vergeben" || ok "und behauptet nicht, nichts sei vergeben"
rm -f "$TMP/LU.git/hooks/post-receive"
# Das Remote bricht ab, bevor es den Zweig anfasst: kein Statusbericht. Ob der
# Push ankam, ist von aussen nicht zu sehen; claim sagt das und nicht mehr.
meld "$MA" 0451 keine-antwort
VOR=$(remote_kopf LU)
printf '#!/bin/sh\nkill -9 $PPID\n' > "$TMP/LU.git/hooks/pre-receive"; chmod +x "$TMP/LU.git/hooks/pre-receive"
rc=0; OUT=$(claim_in "$MA" "$KU2" 451 2>&1) || rc=$?
is "ohne Antwort des Remotes: Exit 3" "$rc" "3"
grep -q 'OUTCOME_UNKNOWN' <<<"$OUT" && ok "und der Zustand heisst OUTCOME_UNKNOWN" || bad "der Zustand fehlt"
grep -q 'nothing was claimed\|Nothing was claimed' <<<"$OUT" && bad "und behauptet, nichts sei vergeben" || ok "und behauptet nicht, nichts sei vergeben"
is "der Zweig blieb, wie er war" "$(remote_kopf LU)" "$VOR"
sauber "nach dem offenen Ausgang" "$KU2"
rm -f "$TMP/LU.git/hooks/pre-receive"
accepts "derselbe Anspruch noch einmal gleicht ab und gelingt" claim_in "$MA" "$KU2" 451
is "und die Zeile steht genau einmal" "$(remote_zeilen LU 0451)" "1"
# Der Fall des Lesers: nach einem Push ohne Antwort ist der Zweig nicht mehr
# lesbar. Auch das ist OUTCOME_UNKNOWN, nicht "nothing was claimed".
meld "$MA" 0452 danach-unlesbar
cat > "$TMP/LU.git/hooks/pre-receive" <<HOOK
#!/bin/sh
mv "$TMP/LU.git" "$TMP/LU.weg"
kill -9 \$PPID
HOOK
chmod +x "$TMP/LU.git/hooks/pre-receive"
rc=0; OUT=$(claim_in "$MA" "$KU2" 452 2>&1) || rc=$?
is "Push ohne Antwort, danach unlesbar: Exit 3" "$rc" "3"
grep -q 'OUTCOME_UNKNOWN' <<<"$OUT" && ok "und OUTCOME_UNKNOWN" || bad "der Zustand fehlt"
grep -q 'nothing was claimed\|Nothing was claimed' <<<"$OUT" && bad "und behauptet, nichts sei vergeben" || ok "und behauptet nicht, nichts sei vergeben"
mv "$TMP/LU.weg" "$TMP/LU.git"; rm -f "$TMP/LU.git/hooks/pre-receive"
accepts "wieder lesbar: derselbe Anspruch gelingt" claim_in "$MA" "$KU2" 452
is "und die Zeile steht genau einmal" "$(remote_zeilen LU 0452)" "1"

# Die Schlussmeldung traegt den Status des letzten Push und behauptet keine
# Ursache. Der Fall des Lesers: das Remote lehnt jeden Anspruch aus Richtlinie
# ab, und in der letzten Runde landet zugleich ein fremder Push. Davor hiess das
# "moved again ... try again".
meld "$MA" 0453 richtlinie-und-fremder-push
KF=$(klon LU f)
cat > "$TMP/LU.git/hooks/pre-receive" <<'HOOK'
#!/bin/sh
while read -r alt neu ref; do
  case $(git log -1 --format=%s "$neu") in slot:*) echo "RICHTLINIE: slot-Commits nur montags" >&2; exit 1 ;; esac
done
exit 0
HOOK
chmod +x "$TMP/LU.git/hooks/pre-receive"
cat > "$KU2/.git/hooks/pre-push" <<HOOK
#!/usr/bin/env bash
unset \$(git rev-parse --local-env-vars)
n=\$(( \$(cat "$TMP/richtlinie-runde" 2>/dev/null || echo 0) + 1 )); echo \$n > "$TMP/richtlinie-runde"
[ "\$n" = 5 ] || exit 0
git -C "$KF" pull -q
echo fremd >> "$KF/fremd.txt"; git -C "$KF" add -- fremd.txt; git -C "$KF" commit -q -m fremd; git -C "$KF" push -q origin ledger
HOOK
chmod +x "$KU2/.git/hooks/pre-push"
VOR=$(remote_kopf LU)
rc=0; OUT=$(claim_in "$MA" "$KU2" 453 2>&1) || rc=$?
is "es waren fuenf Runden" "$(cat "$TMP/richtlinie-runde")" "5"
is "der fremde Push ist gelandet" "$([ "$(remote_kopf LU)" != "$VOR" ] && echo ja)" "ja"
is "Exit 1: jeder Push wurde abgelehnt, die Zeile steht nicht" "$rc" "1"
grep -q 'pre-receive hook declined' <<<"$OUT" && ok "die Meldung traegt den Status des letzten Push" || bad "der Status des letzten Push fehlt"
grep -q 'RICHTLINIE' <<<"$OUT" && ok "und den Text der Ablehnung" || bad "der Text der Ablehnung fehlt"
grep -q 'moved' <<<"$OUT" && bad "und behauptet eine Bewegung als Grund" || ok "und behauptet keine Ursache"
grep -q 'NOT_ESTABLISHED' <<<"$OUT" && ok "der Zustand heisst NOT_ESTABLISHED" || bad "der Zustand fehlt"
rm -f "$KU2/.git/hooks/pre-push" "$TMP/LU.git/hooks/pre-receive"

# In der letzten Runde landet der eigene Push, aber die Antwort geht verloren:
# der reference-transaction-Hook des Remotes beendet den Empfaenger, nachdem
# der Zweig umgesetzt ist und bevor ein Status zurueckgeht. Die Runden davor
# verliert der Anspruch gegen einen Gegner. Nach der fuenften Runde sieht
# claim nach und findet die eigene Zeile: ESTABLISHED, Exit 0.
ledger LE; KE=$(klon LE e); KE2=$(klon LE e2)
meld "$MA" 0480 landet-in-runde-fuenf
for i in 1 2 3 4; do meld "$MB" "048$((i + 4))" gegner-runde-$i; done
cat > "$KE/.git/hooks/pre-commit" <<HOOK
#!/usr/bin/env bash
unset \$(git rev-parse --local-env-vars)
n=\$(( \$(cat "$TMP/runde-fuenf" 2>/dev/null || echo 0) + 1 )); echo \$n > "$TMP/runde-fuenf"
[ "\$n" -le 4 ] || exit 0
TMPDIR="$CLAIMTMP" M3C_MAINTENANCE_DIR="$MB" M3C_SLOT_TABLE="$KE2/$LREL" "$BT" claim "048\$((n + 4))" >/dev/null 2>&1
exit 0
HOOK
chmod +x "$KE/.git/hooks/pre-commit"
cat > "$TMP/LE.git/hooks/reference-transaction" <<'HOOK'
#!/bin/sh
[ "$1" = committed ] || exit 0
while read -r alt neu ref; do
  case $(git log -1 --format=%s "$neu" 2>/dev/null) in "slot: BUG-0480 "*) kill -9 $PPID ;; esac
done
exit 0
HOOK
chmod +x "$TMP/LE.git/hooks/reference-transaction"
rc=0; OUT=$(claim_in "$MA" "$KE" 480 2>&1) || rc=$?
is "fuenf Runden, die ersten vier verloren" "$(cat "$TMP/runde-fuenf")" "5"
is "der eigene Push der letzten Runde landete ohne Antwort: Exit 0" "$rc" "0"
grep -q 'ESTABLISHED' <<<"$OUT" && ok "und claim meldet ESTABLISHED nach dem Nachsehen" || bad "meldet ESTABLISHED nicht"
is "die Zeile steht genau einmal" "$(remote_zeilen LE 0480)" "1"
sauber "nach ESTABLISHED in der letzten Runde" "$KE"
rm -f "$KE/.git/hooks/pre-commit" "$TMP/LE.git/hooks/reference-transaction"

# --- keine nackten Namen, keine Konfiguration aus der Umgebung --------------------
#
# Gemessen an der Fassung davor: mit einer url ohne "/" und ":" und einer
# gleichnamigen Datei unter .git/remotes las git die url als altes Remote, und
# der Anspruch landete woanders, Exit 0. Und eine insteadOf-Regel aus
# GIT_CONFIG_COUNT wurde mit den anderen GIT_*-Variablen abgelegt, statt
# verweigert zu werden.
ledger LR; ledger LS2; KR=$(klon LR r)
meld "$MA" 0460 nackter-name
VORA=$(remote_kopf LR); VORB=$(remote_kopf LS2)
ln -s "$TMP/LR.git" "$KR/tbl"
git -C "$KR" remote set-url origin tbl
refuses "eine url ohne / und : wird verweigert" claim_in "$MA" "$KR" 460
mkdir -p "$KR/.git/remotes"; printf 'URL: %s\n' "$TMP/LS2.git" > "$KR/.git/remotes/tbl"
refuses "auch mit gleichnamiger Datei unter .git/remotes" claim_in "$MA" "$KR" 460
rm -f "$KR/.git/remotes/tbl"
git -C "$KR" remote set-url origin "zz:la"
printf 'URL: %s\n' "$TMP/LS2.git" > "$KR/.git/remotes/zz:la"
refuses "eine alte Remote-Datei fuer die url wird verweigert, auch mit Doppelpunkt" claim_in "$MA" "$KR" 460
rm -f "$KR/.git/remotes/zz:la"
mkdir -p "$KR/.git/branches"; printf '%s#ledger\n' "$TMP/LS2.git" > "$KR/.git/branches/zz:la"
refuses "ebenso unter .git/branches" claim_in "$MA" "$KR" 460
rm -f "$KR/.git/branches/zz:la"
git -C "$KR" remote set-url origin "$TMP/LR.git"
is "das gelesene Repositorium blieb, wie es war" "$(remote_kopf LR)" "$VORA"
is "das andere auch" "$(remote_kopf LS2)" "$VORB"
refuses "eine insteadOf-Regel aus GIT_CONFIG_COUNT wird verweigert" \
  env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="url.$TMP/LS2.git.insteadOf" GIT_CONFIG_VALUE_0="$TMP/LR.git" \
      TMPDIR="$CLAIMTMP" M3C_MAINTENANCE_DIR="$MA" M3C_SLOT_TABLE="$KR/$LREL" "$BT" claim 460
refuses "eine Regel aus GIT_CONFIG_PARAMETERS wird verweigert" \
  env GIT_CONFIG_PARAMETERS="'url.$TMP/LS2.git.pushinsteadof'='$TMP/LR.git'" \
      TMPDIR="$CLAIMTMP" M3C_MAINTENANCE_DIR="$MA" M3C_SLOT_TABLE="$KR/$LREL" "$BT" claim 460
is "und keines der beiden Repositorien wurde beruehrt" "$(remote_kopf LR) $(remote_kopf LS2)" "$VORA $VORB"
is "und nichts wurde angelegt" "$(find "$CLAIMTMP" -mindepth 1 | wc -l | tr -d ' ')" "0"
accepts "ohne all das geht derselbe Anspruch" claim_in "$MA" "$KR" 460
is "und die Zeile steht im gelesenen Repositorium" "$(remote_zeilen LR 0460)" "1"

# --- abgebrochen, waehrend der Push lief --------------------------------------------
#
# Ein Exit ungleich 0 nach Beginn des Push sagt nicht, dass nichts vergeben ist.
# Hier beendet das Remote den Anspruch per Signal, NACHDEM es den Zweig bewegt
# hat. Der Anspruch endet mit einem Fehler, die Zeile steht. Derselbe Anspruch
# noch einmal liest den Zweig, findet die eigene Zeile und hat nichts zu tun.
ledger LS; KS2=$(klon LS s)
meld "$MA" 0390 mitten-im-push-beendet
printf '#!/bin/sh\nkill -TERM "$(cat "%s")" 2>/dev/null\nsleep 1\n' "$TMP/claim.pid" > "$TMP/LS.git/hooks/post-receive"
chmod +x "$TMP/LS.git/hooks/post-receive"
rc=0
TMPDIR="$CLAIMTMP" M3C_MAINTENANCE_DIR="$MA" M3C_SLOT_TABLE="$KS2/$LREL" \
  bash -c 'echo $$ > "$1"; exec "$2" claim 390' _ "$TMP/claim.pid" "$BT" >/dev/null 2>&1 || rc=$?
[ "$rc" -ne 0 ] && ok "der abgebrochene Anspruch endet mit einem Fehler (Exit $rc)" \
  || bad "der Anspruch wurde nicht abgebrochen; der Fall ist nicht gestellt"
is "und die Zeile steht trotzdem auf dem Zweig" "$(remote_zeilen LS 0390)" "1"
rm -f "$TMP/LS.git/hooks/post-receive"
VOR=$(remote_kopf LS)
OUT=$(claim_in "$MA" "$KS2" 390 2>&1) && ok "derselbe Anspruch noch einmal: Exit 0" || bad "der zweite Anlauf scheitert"
grep -q 'already claimed by this file' <<<"$OUT" && ok "und er erkennt die eigene Zeile" || bad "erkennt die eigene Zeile nicht"
is "ohne zweiten Commit" "$(remote_kopf LS)" "$VOR"
is "und ohne zweite Zeile" "$(remote_zeilen LS 0390)" "1"
sauber "nach dem abgebrochenen Anspruch" "$KS2"

# --- sync ---------------------------------------------------------------------
"$BT" status 213 fixed >/dev/null
GH_ISSUE_STATE=CLOSED accepts "sync is quiet when both agree" "$BT" sync 213
GH_ISSUE_STATE=OPEN   refuses "sync reports a fixed report with an open issue" "$BT" sync 213
"$BT" status 213 open >/dev/null
GH_ISSUE_STATE=OPEN   accepts "sync agrees again once the report reopens" "$BT" sync 213

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]

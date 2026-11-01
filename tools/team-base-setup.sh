#!/usr/bin/env bash
# team-base-setup.sh: prepare ONE machine for human-agent team work.
#
# The point of this script is what the person does NOT have to do. A team
# member who receives skills should meet the agent framework twice: once when
# this script runs, and never again. Everything the daily work needs after that
# is a folder and a file, not a command.
#
# Two roles, one workspace layout:
#
#   author   the person who BUILDS and hands over skills. Gets a signing
#            keypair, a skills/ source tree and a bundles/ output tree.
#   member   the person who RECEIVES them. Gets the same workspace, plus the
#            author's key pinned in the trust roots, and no key of their own.
#            Pinning is TWO steps, because the verifier checks the registry
#            signature as well as the author signature: the registry name gets
#            a key, then the author identity gets one under that name. With no
#            registry server in the picture the author is their own registry,
#            which is what --registry-key defaults to.
#
#   check    read-only: report what exists on this machine and what is missing.
#
# Usage:
#   tools/team-base-setup.sh author --id id:bob@example [--workspace DIR] [--contexts a,b]
#   tools/team-base-setup.sh member --author-id id:bob@example \
#       --author-key bob.pub --pin sha256:<hex> [--peer-registry local:///pfad] \
#       [--workspace DIR]
#   tools/team-base-setup.sh check [--workspace DIR]
#
# Common flags:
#   --workspace DIR   where the daily-work tree lives (default: ~/agent-team)
#   --contexts a,b,c  names using letters, digits, underscore or hyphen.
#                     Default: one context named "allgemein".
#   --peer-registry P local:// path (or git URL) of the shared skill registry.
#                     When given, the member is ALSO pinned as a peer, which is
#                     what `skillctl pull` needs. The two pins are separate on
#                     purpose: `trust add-author` serves the file-by-hand path
#                     (`verify --bundle`, `install --bundle`), `peer add` serves
#                     the registry path (`pull`). They read different files.
#   --peer-only      configure only the peer path; requires --peer-registry.
#                     No HTTP/file trust roots are created or changed.
#   --registry URL    the registry NAME the author publishes under. On the
#                     offline bundle path it is a LABEL and is never called,
#                     but it is validated as a URL, so it has to look like one
#                     (default: https://author.example/api/skills)
#   --registry-pin F confirmed fingerprint of a separate --registry-key.
#                     Required when registry and author keys differ.
#   --skillctl PATH   the binary to use (default: $SKILLCTL, then PATH)
#   --dry-run         print what would happen, change nothing
#
# Exit: 0 done (or nothing to do) · 1 something is present and unusable
#       2 usage error
#
# This script does NOT install skillctl, does NOT reach the network, and does
# NOT decide what a person may do. It lays out folders, generates or pins one
# key, and then asks `skillctl doctor` whether the machine is ready.
set -euo pipefail

# The header comment above IS the usage text: one place to keep current.
usage() { awk 'NR>1 && /^#/ { sub(/^# ?/, ""); print; next } NR>1 { exit }' "$0"; }

ROLE="${1:-}"
case "$ROLE" in
  ""|-h|--help) usage; [ -n "$ROLE" ] && exit 0 || exit 2 ;;
esac
shift

WORKSPACE="${HOME}/agent-team"
CONTEXTS="allgemein"
REGISTRY="https://author.example/api/skills"
IDENTITY=""
AUTHOR_ID=""
AUTHOR_KEY=""
REGISTRY_KEY=""
REGISTRY_PIN=""
PEER_REGISTRY=""
PEER_ONLY=0
PIN=""
SKILLCTL_BIN="${SKILLCTL:-}"
DRY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --workspace|--contexts|--registry|--id|--author-id|--author-key|--registry-key|--registry-pin|--peer-registry|--pin|--skillctl)
      [ $# -ge 2 ] && [ -n "$2" ] || { echo "$1 requires a nonempty value" >&2; exit 2; }
      case "$2" in --*) echo "$1 requires a value before $2" >&2; exit 2 ;; esac ;;
  esac
  case "$1" in
    --workspace)  WORKSPACE="${2:?--workspace needs a directory}"; shift 2 ;;
    --contexts)   CONTEXTS="${2:?--contexts needs a comma-separated list}"; shift 2 ;;
    --registry)   REGISTRY="${2:?--registry needs a name}"; shift 2 ;;
    --id)         IDENTITY="${2:?--id needs an identity id}"; shift 2 ;;
    --author-id)  AUTHOR_ID="${2:?--author-id needs an identity id}"; shift 2 ;;
    --author-key) AUTHOR_KEY="${2:?--author-key needs a path}"; shift 2 ;;
    --registry-pin) REGISTRY_PIN="${2:?--registry-pin needs a fingerprint}"; shift 2 ;;
    --registry-key) REGISTRY_KEY="${2:?--registry-key needs a path}"; shift 2 ;;
    --peer-only)    PEER_ONLY=1; shift ;;
    --peer-registry) PEER_REGISTRY="${2:?--peer-registry needs a local:// path or git URL}"; shift 2 ;;
    --pin)        PIN="${2:?--pin needs sha256:<hex>}"; shift 2 ;;
    --skillctl)   SKILLCTL_BIN="${2:?--skillctl needs a path}"; shift 2 ;;
    --dry-run)    DRY=1; shift ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

say()  { printf '%s\n' "$*"; }
ok()   { printf '  ok      %s\n' "$*"; }
note() { printf '  note    %s\n' "$*"; }
MISSING=0
miss() { MISSING=1; printf '  MISSING %s\n' "$*"; }
run()  { if [ "$DRY" -eq 1 ]; then printf '  would   %s\n' "$*"; else "$@"; fi; }

# Read raw public-key bytes through skillctl, including on stock macOS.
peer_b64_from_pub() {
  "$SKILLCTL_BIN" trust fingerprint --b64 "$1"
}

fail() { printf '%s\n' "$*" >&2; exit 1; }
usage_error() { printf '%s\n' "$*" >&2; exit 2; }

# Reject symlink components rather than following them into another workspace.
check_path() {
  local path="$1" part current="" rest
  case "$path" in /*) ;; *) path="$PWD/$path" ;; esac
  rest="${path#/}"
  while [ -n "$rest" ]; do
    part="${rest%%/*}"
    if [ "$rest" = "$part" ]; then rest=""; else rest="${rest#*/}"; fi
    case "$part" in ""|.) continue ;; ..) usage_error "Parent path segments are not allowed: $path" ;; esac
    current="$current/$part"
    [ ! -L "$current" ] || fail "Symlink path is not allowed: $current"
  done
}

validate_paths() {
  local ctx path part
  [ -n "$WORKSPACE" ] || usage_error "--workspace must not be empty"
  [ ! -e "$WORKSPACE" ] || [ -d "$WORKSPACE" ] || fail "Workspace path is not a directory: $WORKSPACE"
  for path in "$WORKSPACE/contexts" "$WORKSPACE/keys" "$WORKSPACE/skills" "$WORKSPACE/bundles" "$HOME/.claude"; do
    [ ! -e "$path" ] || [ -d "$path" ] || fail "Expected a directory: $path"
  done
  case "$CONTEXTS" in ""|,*|*,|*,,*) usage_error "--contexts needs nonempty names separated by commas" ;; esac
  IFS=',' read -r -a CTX_LIST <<< "$CONTEXTS"
  for ctx in "${CTX_LIST[@]}"; do
    case "$ctx" in ""|*[!A-Za-z0-9_-]*) usage_error "Invalid context name: $ctx (use letters, digits, underscore or hyphen)" ;; esac
  done
  for path in "$WORKSPACE" "$WORKSPACE/CLAUDE.md" "$WORKSPACE/.gitignore" "$WORKSPACE/keys/author.priv" "$WORKSPACE/keys/author.pub" "$WORKSPACE/skills" "$WORKSPACE/bundles" "$HOME/.claude/skill-trust-roots.yaml" "$HOME/.claude/skill-peers.yaml"; do check_path "$path"; done
  for ctx in "${CTX_LIST[@]}"; do
    for part in inbox wlog reports reflections README.md; do check_path "$WORKSPACE/contexts/$ctx/$part"; done
    path="$WORKSPACE/contexts/$ctx/README.md"
    [ ! -e "$path" ] || [ -f "$path" ] || fail "Expected a regular file: $path"
    for part in inbox wlog reports reflections; do
      path="$WORKSPACE/contexts/$ctx/$part"
      [ ! -e "$path" ] || [ -d "$path" ] || fail "Context path is not a directory: $path"
    done
  done
  for path in "$WORKSPACE/CLAUDE.md" "$WORKSPACE/.gitignore"; do
    [ ! -e "$path" ] || [ -f "$path" ] || fail "Expected a regular file: $path"
  done
}

check_existing_pair() {
  local challenge
  challenge="$(mktemp -d)" || fail "Cannot create keypair check"
  trap 'rm -rf "$challenge"' EXIT
  mkdir "$challenge/skill"
  printf '%s\n' '---' 'name: keypair-check' 'description: Local keypair check.' '---' 'Local check only.' > "$challenge/skill/SKILL.md"
  "$SKILLCTL_BIN" pack --skill "$challenge/skill" -o "$challenge/check.skb" --name keypair-check --version 1.0.0 >/dev/null || fail "Cannot prepare keypair check"
  "$SKILLCTL_BIN" sign --key "$WORKSPACE/keys/author.priv" "$challenge/check.skb" >/dev/null || fail "Existing private key is invalid"
  "$SKILLCTL_BIN" verify-sig --pubkey "$WORKSPACE/keys/author.pub" "$challenge/check.skb" >/dev/null || fail "Existing public and private keys do not match"
  rm -rf "$challenge"
  trap - EXIT
}

validate_existing_pair() {
  local mode
  if [ -e "$WORKSPACE/keys/author.priv" ] || [ -e "$WORKSPACE/keys/author.pub" ]; then
    [ -f "$WORKSPACE/keys/author.priv" ] && [ -f "$WORKSPACE/keys/author.pub" ] || fail "Existing keypair is incomplete; restore the missing file before setup"
    mode="$(stat -c %a "$WORKSPACE/keys/author.priv" 2>/dev/null || stat -f %Lp "$WORKSPACE/keys/author.priv")"
    [ "$mode" = 600 ] || fail "Existing private key must have mode 0600"
    "$SKILLCTL_BIN" trust fingerprint "$WORKSPACE/keys/author.pub" >/dev/null || fail "Existing public key is invalid"
    check_existing_pair
  fi
}

verify_pin() {
  local got
  [ -f "$1" ] || fail "No public-key file: $1"
  got="$("$SKILLCTL_BIN" trust fingerprint "$1")" || fail "Cannot read public key: $1"
  [ "$got" = "$2" ] || fail "Fingerprint mismatch for $1. Stop and confirm it over the second channel."
}

find_skillctl() {
  if [ -n "$SKILLCTL_BIN" ]; then
    [ -x "$SKILLCTL_BIN" ] || { echo "not executable: $SKILLCTL_BIN" >&2; exit 1; }
    return
  fi
  SKILLCTL_BIN="$(command -v skillctl || true)"
}

# --------------------------------------------------------------------------
# The workspace. One tree per person, one subtree per work context.
#
# The four folders under a context are not decoration, they are the four
# stations of the loop the team runs: raw material arrives in inbox/, the day
# is written down in wlog/, the aggregate is written to reports/, and what was
# learned about the WAY of working goes to reflections/. The last one is the
# one people skip, and it is the one a skill is later derived from.
# --------------------------------------------------------------------------
make_workspace() {
  run mkdir -p "$WORKSPACE"
  local ctx
  IFS=',' read -r -a CTX_LIST <<< "$CONTEXTS"
  for ctx in "${CTX_LIST[@]}"; do
    run mkdir -p "$WORKSPACE/contexts/$ctx/inbox" \
                 "$WORKSPACE/contexts/$ctx/wlog" \
                 "$WORKSPACE/contexts/$ctx/reports" \
                 "$WORKSPACE/contexts/$ctx/reflections"
    if [ "$DRY" -eq 0 ] && [ ! -f "$WORKSPACE/contexts/$ctx/README.md" ]; then
      write_context_readme "$ctx" > "$WORKSPACE/contexts/$ctx/README.md"
    fi
    ok "context $ctx (inbox, wlog, reports, reflections)"
  done
  if [ "$DRY" -eq 0 ] && [ ! -f "$WORKSPACE/CLAUDE.md" ]; then
    write_workspace_claude_md > "$WORKSPACE/CLAUDE.md"
    ok "CLAUDE.md (the house rules the agent reads on every session)"
  else
    [ "$DRY" -eq 1 ] && note "would write CLAUDE.md" || ok "CLAUDE.md exists, left alone"
  fi
  if [ "$DRY" -eq 0 ] && [ ! -f "$WORKSPACE/.gitignore" ]; then
    printf 'keys/\n*.priv\nbundles/\n' > "$WORKSPACE/.gitignore"
    ok ".gitignore (keys and bundles excluded from normal git add; review tracked files separately)"
  fi
}

write_context_readme() {
  cat <<CTX_EOF
# Kontext: $1

Dieser Kontext sammelt Arbeitsmaterial und Ergebnisse. Pruefen Sie vor der
Verarbeitung, welche Daten der Agent verwenden darf. Ordnernamen schuetzen
keine vertraulichen Inhalte.

| Ordner | Was hier hineingehoert | Wer schreibt |
|---|---|---|
| \`inbox/\` | Rohmaterial: Transkripte, Notizen, Mails, Exporte | Mensch |
| \`wlog/\` | ein Arbeitslog je Tag, \`JJJJ-MM-TT.md\` | Mensch und Agent |
| \`reports/\` | Zusammenfassungen wie Wochenbericht oder Blockerliste | Agent |
| \`reflections/\` | was ueber die ARBEITSWEISE gelernt wurde | Mensch und Agent |

## Die Rubriken heissen so und nicht anders

Ein Bericht traegt die vier Woerter woertlich, als Ueberschrift:

\`\`\`
## Progress
## Plans
## Problems
## Proposals
\`\`\`

Die festen Rubriken erleichtern die Zuordnung. Fehlende Angaben werden
als fehlend markiert. Der Mensch prueft, ob jede Aussage durch eine
Quelldatei belegt ist. Die Ueberschriften ersetzen diese Pruefung nicht.

## Der Takt

Traegt dieser Kontext einen festen Takt (woechentlich, zweiwoechentlich,
monatlich), dann steht er hier, zusammen mit dem Wochentag und dem Kanal,
ueber den die Erinnerung kommt. Legen Sie auch fest, wer die Erinnerung
einrichtet und wer den Bericht prueft.

Takt: (noch nicht festgelegt)
Erinnerung: (noch nicht festgelegt)
CTX_EOF
}

write_workspace_claude_md() {
  cat <<'MD_EOF'
# Arbeitsraum eines Mensch-Agent-Teams

Dieser Ordner enthaelt Arbeitsmaterial, Berichte und Reflexionen einer
Person. Der Mensch legt fest, welche Daten der Agent verarbeiten darf.

## Die drei Ebenen, getrennt gehalten

| Farbe | Was es ist | Wo es liegt |
|---|---|---|
| rot | fachliche Inhalte, moeglicherweise vertraulich | `inbox/`, `wlog/` und `reports/` pruefen |
| grau | die Arbeitsweise und ihre dokumentierten Schritte | `contexts/*/reflections/` |
| blau | die Pruefung: wurde der Zweck erreicht | `contexts/*/reports/` |

Pruefen Sie jede Reflexion auf vertrauliche Inhalte. Ein Ordnername ersetzt
keine Freigabe. Geben Sie nur Inhalte weiter, die dafuer freigegeben sind.

## Was am Tagesende passiert

1. Was habe ich heute getan: in `wlog/JJJJ-MM-TT.md`, mit den vier Rubriken.
2. Mit wem habe ich worueber geredet, und was wollte ich davon wissen.
3. Was habe ich ueber die ARBEITSWEISE gelernt: nach `reflections/`.

Die Reflexion dokumentiert, welche Schritte nuetzlich waren. Halten Sie
auch Fehler und Aenderungsvorschlaege fest. Diese Beobachtungen helfen dem
Team, einen Skill zu entwerfen und spaeter zu verbessern.

## Regeln fuer den Agent in diesem Raum

- Rubriken woertlich lesen, nie raten. Fehlt eine, sag es, erfinde sie nicht.
- Beim Aggregieren jede Aussage an die Datei binden, aus der sie stammt.
- Vor externer Verarbeitung die freigegebenen Daten und Werkzeuge pruefen.
- Ein lokaler Ordner verhindert keine Uebertragung durch einen Cloud-Agenten.
- Bei einer Frage, die eine Entscheidung braucht: fragen, nicht entscheiden.
MD_EOF
}

# --------------------------------------------------------------------------
setup_author() {
  [ -n "$IDENTITY" ] || { echo "author needs --id (e.g. --id id:bob@example)" >&2; exit 2; }
  say "role: author, identity $IDENTITY"
  make_workspace
  run mkdir -p "$WORKSPACE/skills" "$WORKSPACE/bundles" "$WORKSPACE/keys"
  [ "$DRY" -eq 1 ] || chmod 700 "$WORKSPACE/keys"
  ok "skills/, bundles/, keys/ (keys/ mode 0700)"

  local base="$WORKSPACE/keys/author"
  if [ -f "$base.priv" ]; then
    note "keypair exists, NOT regenerated: $base.priv"
    note "existing signatures remain verifiable; manage key changes explicitly"
  else
    find_skillctl
    if [ -z "$SKILLCTL_BIN" ]; then
      fail "skillctl not found; install it before setup"
    else
      run "$SKILLCTL_BIN" keygen --out "$base"
      ok "keypair: $base.priv (secret) and $base.pub (shareable)"
    fi
  fi

  if [ "$DRY" -eq 0 ] && [ -f "$base.pub" ]; then
    find_skillctl
    if [ -n "$SKILLCTL_BIN" ]; then
      say ""
      say "Read this fingerprint aloud on a call. It is what the other side pins:"
      "$SKILLCTL_BIN" trust fingerprint "$base.pub" || true
    fi
  fi
  finish
}

setup_member() {
  local stage listing registry_b64 peer_b64 peer_name existing output staged_home
  [ -n "$AUTHOR_ID" ] && [ -n "$AUTHOR_KEY" ] && [ -n "$PIN" ] || usage_error "member requires --author-id, --author-key and --pin"
  [ "$PEER_ONLY" -eq 0 ] || [ -n "$PEER_REGISTRY" ] || usage_error "--peer-only requires --peer-registry"
  find_skillctl
  [ -n "$SKILLCTL_BIN" ] || fail "skillctl not found; install it before setup"
  verify_pin "$AUTHOR_KEY" "$PIN"
  [ -n "$REGISTRY_KEY" ] || REGISTRY_KEY="$AUTHOR_KEY"
  registry_b64="$(peer_b64_from_pub "$REGISTRY_KEY")" || fail "Cannot read registry public key"
  peer_b64="$(peer_b64_from_pub "$AUTHOR_KEY")" || fail "Cannot read author public key"
  if [ "$registry_b64" = "$peer_b64" ]; then
    REGISTRY_PIN="$PIN"
  else
    [ -n "$REGISTRY_PIN" ] || usage_error "A separate --registry-key requires --registry-pin confirmed over a second channel"
    verify_pin "$REGISTRY_KEY" "$REGISTRY_PIN"
  fi
  # Build the pin changes in an isolated profile. A rejected operation must not
  # leave a partially configured registry in the actual profile.
  stage="$(mktemp -d)" || fail "Cannot create temporary profile"
  trap 'rm -rf "$stage"' EXIT
  mkdir -p "$stage/.claude"
  for existing in skill-trust-roots.yaml skill-peers.yaml; do
    [ "$PEER_ONLY" -eq 0 ] || [ "$existing" != skill-trust-roots.yaml ] || continue
    [ ! -e "$HOME/.claude/$existing" ] || cp -p "$HOME/.claude/$existing" "$stage/.claude/$existing"
  done
  staged_home="$stage"
  if [ "$PEER_ONLY" -eq 0 ]; then
  listing="$(HOME="$staged_home" "$SKILLCTL_BIN" trust list)" || fail "Cannot read existing registry pins"
  existing="$(printf '%s\n' "$listing" | awk -v url="${REGISTRY%/}" '/^registry: / {selected=($2==url)} selected && /pubkey \(b64\):/ {print $3}')"
  if printf '%s\n' "$listing" | awk -v url="${REGISTRY%/}" '/^registry: / {selected=($2==url)} selected && /\[retired / {found=1} END {exit !found}'; then
    fail "Registry has retired keys. Review rotation manually."
  fi
  if [ -n "$existing" ]; then
    [ "$existing" = "$registry_b64" ] || fail "Registry already has another key or a rotation set. Review it manually."
  else
    HOME="$staged_home" "$SKILLCTL_BIN" trust add --registry "$REGISTRY" --pubkey "$REGISTRY_KEY"
  fi
  if output="$(HOME="$staged_home" "$SKILLCTL_BIN" trust add-author --registry "$REGISTRY" --identity "$AUTHOR_ID" --pubkey "$AUTHOR_KEY" --pin "$PIN" 2>&1)"; then
    printf '%s\n' "$output"
  else
    [ "$output" = "trust-roots: author $AUTHOR_ID is already pinned with this exact key" ] || fail "$output"
    note "author already pinned with this exact key"
  fi
  fi
  if [ -n "$PEER_REGISTRY" ]; then
    peer_name="${AUTHOR_ID#id:}"
    listing="$(HOME="$staged_home" "$SKILLCTL_BIN" peer ls)" || fail "Cannot read existing peers"
    existing="$(printf '%s\n' "$listing" | awk -v name="$peer_name" -v locator="$PEER_REGISTRY" '
      $NF ~ /^sha256:/ {
        line=substr($0,length($1)+1)
        sub(/^[ \t]+/,"",line)
        sub(/[ \t]+(green|yellow)[ \t]+sha256:[[:xdigit:]]+$/, "", line)
        sub(/[ \t]+$/, "", line)
        if ($1==name || line==locator) printf "%s\n%s\n%s\n%s\n",$1,line,$(NF-1),$NF
      }')"
    if [ -n "$existing" ]; then
      [ "$existing" = "$(printf '%s\n%s\n%s\n%s' "$peer_name" "$PEER_REGISTRY" green "$REGISTRY_PIN")" ] || fail "Peer name or locator already has another pin or policy. Review it manually."
      note "existing peer preserved, including its reviewer policy"
    else
      HOME="$staged_home" "$SKILLCTL_BIN" peer add "$peer_name" "$PEER_REGISTRY" --pubkey "$registry_b64" --pin "$REGISTRY_PIN"
    fi
  fi
  if [ "$DRY" -eq 1 ]; then
    note "dry run: pins validated in a temporary profile; actual profile unchanged"
  else
    mkdir -p "$HOME/.claude"
    for existing in skill-trust-roots.yaml skill-peers.yaml; do
      if [ -f "$staged_home/.claude/$existing" ]; then
        # Publish each validated file atomically. The pair is not a transaction.
        local target
        target="$(mktemp "$HOME/.claude/.team-pin-XXXXXX")" || fail "Cannot stage pin file"
        cp "$staged_home/.claude/$existing" "$target"
        chmod 600 "$target"
        mv "$target" "$HOME/.claude/$existing"
      fi
    done
  fi
  rm -rf "$stage"
  trap - EXIT
  [ -n "$PEER_REGISTRY" ] || note "No registry peer configured. Shared-registry pulls are not ready."
  say "role: member"
  make_workspace
  finish
}

do_check() {
  say "workspace: $WORKSPACE"
  [ -d "$WORKSPACE" ] && ok "workspace exists" || miss "workspace does not exist"
  [ -f "$WORKSPACE/CLAUDE.md" ] && ok "CLAUDE.md" || miss "CLAUDE.md"
  if [ -d "$WORKSPACE/contexts" ]; then
    local n; n=$(find "$WORKSPACE/contexts" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
    [ "$n" -gt 0 ] && ok "contexts: $n" || miss "no context directories"
    local ctx part
    for ctx in "$WORKSPACE"/contexts/*; do
      [ ! -L "$ctx" ] || { miss "symlink context: $ctx"; continue; }
      [ -d "$ctx" ] || continue
      for part in inbox wlog reports reflections; do
        check_path "$ctx/$part"
        [ -d "$ctx/$part" ] || miss "$ctx/$part"
      done
    done
  else
    miss "contexts/"
  fi
  [ -f "$WORKSPACE/keys/author.priv" ] && ok "author keypair present (author role)" \
                                       || note "no author keypair (expected for a member)"
  find_skillctl
  if [ -z "$SKILLCTL_BIN" ]; then
    miss "skillctl not on PATH"
    return 1
  fi
  validate_existing_pair
  ok "skillctl: $SKILLCTL_BIN ($("$SKILLCTL_BIN" version 2>/dev/null | head -1))"
  say ""
  say "skillctl doctor says:"
  "$SKILLCTL_BIN" doctor || return 1
  [ "$MISSING" -eq 0 ]
}

finish() {
  say ""
  find_skillctl
  if [ -n "$SKILLCTL_BIN" ] && [ "$DRY" -eq 0 ]; then
    say "skillctl doctor says:"
    "$SKILLCTL_BIN" doctor || return 1
  fi
  say ""
  if [ "$DRY" -eq 1 ]; then
    say "Dry run complete. Actual workspace and pins were not changed."
    return
  fi
  say "Workspace ready: $WORKSPACE"
  say "Next for the person who works here: open it and write today's wlog entry."
}

case "$ROLE" in author|member|check) ;; *) usage_error "unknown role: $ROLE" ;; esac
[ "$PEER_ONLY" -eq 0 ] || [ "$ROLE" = member ] || usage_error "--peer-only is available only for member"
validate_paths
if [ "$ROLE" = author ]; then
  [ -n "$IDENTITY" ] || usage_error "author requires --id"
  find_skillctl
  [ -n "$SKILLCTL_BIN" ] || fail "skillctl not found; install it before setup"
  validate_existing_pair
fi

case "$ROLE" in
  author) setup_author ;;
  member) setup_member ;;
  check)  do_check ;;
  *) echo "unknown role: $ROLE (expected author, member or check)" >&2; exit 2 ;;
esac

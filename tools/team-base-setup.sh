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
#   --contexts a,b,c  the work contexts to create (default: one named "allgemein")
#   --peer-registry P local:// path (or git URL) of the shared skill registry.
#                     When given, the member is ALSO pinned as a peer, which is
#                     what `skillctl pull` needs. The two pins are separate on
#                     purpose: `trust add-author` serves the file-by-hand path
#                     (`verify --bundle`, `install --bundle`), `peer add` serves
#                     the registry path (`pull`). They read different files.
#   --registry URL    the registry NAME the author publishes under. On the
#                     offline bundle path it is a LABEL and is never called,
#                     but it is validated as a URL, so it has to look like one
#                     (default: https://author.example/api/skills)
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
PEER_REGISTRY=""
PIN=""
SKILLCTL_BIN="${SKILLCTL:-}"
DRY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --workspace)  WORKSPACE="${2:?--workspace needs a directory}"; shift 2 ;;
    --contexts)   CONTEXTS="${2:?--contexts needs a comma-separated list}"; shift 2 ;;
    --registry)   REGISTRY="${2:?--registry needs a name}"; shift 2 ;;
    --id)         IDENTITY="${2:?--id needs an identity id}"; shift 2 ;;
    --author-id)  AUTHOR_ID="${2:?--author-id needs an identity id}"; shift 2 ;;
    --author-key) AUTHOR_KEY="${2:?--author-key needs a path}"; shift 2 ;;
    --registry-key) REGISTRY_KEY="${2:?--registry-key needs a path}"; shift 2 ;;
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
miss() { printf '  MISSING %s\n' "$*"; }
run()  { if [ "$DRY" -eq 1 ]; then printf '  would   %s\n' "$*"; else "$@"; fi; }

# `peer add` wants the RAW 32 ed25519 bytes in base64, while the .pub file is a
# PEM SPKI. The last 32 bytes of the DER encoding are the key. Verified on
# 2026-09-16: sha256 of those bytes is the same value `trust fingerprint`
# prints, so ONE fingerprint serves both pins and nobody reads two numbers
# aloud on the same call.
peer_b64_from_pub() {
  command -v openssl >/dev/null 2>&1 || return 0
  openssl pkey -pubin -in "$1" -outform DER 2>/dev/null | tail -c 32 | base64 | tr -d '\n'
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
    ctx="$(printf '%s' "$ctx" | tr -d '[:space:]')"
    [ -n "$ctx" ] || continue
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
    ok ".gitignore (keys and bundles never reach a remote by accident)"
  fi
}

write_context_readme() {
  cat <<CTX_EOF
# Kontext: $1

Vier Ordner, vier Stationen. Wer einen ueberspringt, merkt es erst, wenn der
Skill fehlt, der daraus haette entstehen sollen.

| Ordner | Was hier hineingehoert | Wer schreibt |
|---|---|---|
| \`inbox/\` | Rohmaterial: Transkripte, Notizen, Mails, Exporte | Mensch |
| \`wlog/\` | ein Arbeitslog je Tag, \`JJJJ-MM-TT.md\` | Mensch und Agent |
| \`reports/\` | die Aggregate: Wochenbericht, Blockerliste | Agent |
| \`reflections/\` | was ueber die ARBEITSWEISE gelernt wurde | Mensch und Agent |

## Die Rubriken heissen so und nicht anders

Ein Bericht traegt die vier Woerter woertlich, als Ueberschrift:

\`\`\`
## Progress
## Plans
## Problems
## Proposals
\`\`\`

Der Grund ist nicht Formalismus. Ein System, das die Rubrik raten muss,
interpretiert; ein System, das sie liest, extrahiert. Wer die Woerter
weglaesst, zwingt die Maschine zur Spekulation und nennt das Ergebnis
spaeter Halluzination.

## Der Takt

Traegt dieser Kontext einen festen Takt (woechentlich, zweiwoechentlich,
monatlich), dann steht er hier, zusammen mit dem Wochentag und dem Kanal,
ueber den die Erinnerung kommt. Ein Takt ohne Erinnerung ist eine Hoffnung.

Takt: (noch nicht festgelegt)
Erinnerung: (noch nicht festgelegt)
CTX_EOF
}

write_workspace_claude_md() {
  cat <<'MD_EOF'
# Arbeitsraum eines Mensch-Agent-Teams

Dieser Ordner ist der Arbeitsplatz einer Person, nicht ein Projekt. Was hier
liegt, ist das Gedaechtnis dieser Person ueber ihre eigene Arbeitsweise.

## Die drei Ebenen, getrennt gehalten

| Farbe | Was es ist | Wo es liegt |
|---|---|---|
| rot | der fachliche Inhalt, oft vertraulich | ausserhalb dieses Ordners |
| grau | die Arbeitsweise, der Doku-Flow | `contexts/*/reflections/` |
| blau | die Pruefung: wurde der Zweck erreicht | `contexts/*/reports/` |

Die Trennung ist der Grund, warum die Methodik weitergegeben werden darf,
waehrend der Inhalt es nicht darf. Wer beides vermischt, kann keines von
beidem uebergeben.

## Was am Tagesende passiert

1. Was habe ich heute getan: in `wlog/JJJJ-MM-TT.md`, mit den vier Rubriken.
2. Mit wem habe ich worueber geredet, und was wollte ich davon wissen.
3. Was habe ich ueber die ARBEITSWEISE gelernt: nach `reflections/`.

Punkt 3 ist der, den alle auslassen, und der einzige, aus dem spaeter ein
Skill wird. Ohne ihn bleibt der Arbeitslog ein Tagebuch.

## Regeln fuer den Agent in diesem Raum

- Rubriken woertlich lesen, nie raten. Fehlt eine, sag es, erfinde sie nicht.
- Beim Aggregieren jede Aussage an die Datei binden, aus der sie stammt.
- Nichts nach aussen senden. Dieser Raum ist lokal.
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
    note "a new key would orphan every bundle already signed with the old one"
  else
    find_skillctl
    if [ -z "$SKILLCTL_BIN" ]; then
      miss "skillctl not found; skipping keygen. Install it, then re-run."
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
  say "role: member"
  make_workspace
  find_skillctl
  if [ -z "$AUTHOR_ID" ] || [ -z "$AUTHOR_KEY" ] || [ -z "$PIN" ]; then
    miss "author key NOT pinned: --author-id, --author-key and --pin are all required"
    note "the pin is the fingerprint, confirmed on a CALL, not the one that came"
    note "with the key. A key that carries its own fingerprint proves nothing."
    note "The author prints it with: skillctl trust fingerprint <key.pub>"
    finish
    return
  fi
  [ -f "$AUTHOR_KEY" ] || { echo "no such key file: $AUTHOR_KEY" >&2; exit 1; }
  if [ -z "$SKILLCTL_BIN" ]; then
    miss "skillctl not found; cannot pin the author key. Install it, then re-run."
    finish
    return
  fi
  # Step 1 of 2: the registry name needs a key before an author can hang under
  # it. With no registry server, the author signs for their own name.
  [ -n "$REGISTRY_KEY" ] || REGISTRY_KEY="$AUTHOR_KEY"
  if ! run "$SKILLCTL_BIN" trust add --registry "$REGISTRY" --pubkey "$REGISTRY_KEY"; then
    miss "could not pin the registry name $REGISTRY"
    exit 1
  fi
  ok "registry name $REGISTRY pinned (key: $REGISTRY_KEY)"
  # Step 2 of 2: the author identity, and this one insists on the fingerprint.
  if ! run "$SKILLCTL_BIN" trust add-author \
      --registry "$REGISTRY" --identity "$AUTHOR_ID" \
      --pubkey "$AUTHOR_KEY" --pin "$PIN"; then
    miss "pinning refused. The two usual causes: the pin does not match the key"
    note "(then it is the WRONG key, stop and call the author), or --registry is"
    note "not shaped like a URL. It is only a label here, but it is parsed as a URL."
    exit 1
  fi
  ok "author $AUTHOR_ID pinned under registry name $REGISTRY"

  # The registry path is a SECOND pin against a DIFFERENT file. `pull` does not
  # read the author pin above, and `install --bundle` does not read this one.
  # Measured on 2026-09-16: `trust add-author` writes ~/.claude/skill-trust-roots.yaml,
  # `peer add` writes ~/.claude/skill-peers.yaml, and `pull` with neither of them
  # asks for a third name, ~/.claude/trust-roots.yaml.
  if [ -n "$PEER_REGISTRY" ]; then
    local b64
    b64="$(peer_b64_from_pub "$AUTHOR_KEY")"
    if [ -z "$b64" ]; then
      miss "could not read the raw ed25519 bytes out of $AUTHOR_KEY (openssl missing?)"
      note "the peer pin was skipped; the file-by-hand path above still works"
    elif ! run "$SKILLCTL_BIN" peer add "${AUTHOR_ID#id:}" "$PEER_REGISTRY" \
              --pubkey "$b64" --pin "$PIN"; then
      miss "peer pin refused for $PEER_REGISTRY"
      exit 1
    else
      ok "peer pinned: pull works against $PEER_REGISTRY"
    fi
  else
    note "no --peer-registry given: this machine can install a handed-over .skb,"
    note "but `skillctl pull` from a shared registry is not set up yet."
  fi
  finish
}

do_check() {
  say "workspace: $WORKSPACE"
  [ -d "$WORKSPACE" ] && ok "workspace exists" || miss "workspace does not exist"
  [ -f "$WORKSPACE/CLAUDE.md" ] && ok "CLAUDE.md" || miss "CLAUDE.md"
  if [ -d "$WORKSPACE/contexts" ]; then
    local n; n=$(find "$WORKSPACE/contexts" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
    ok "contexts: $n"
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
  ok "skillctl: $SKILLCTL_BIN ($("$SKILLCTL_BIN" version 2>/dev/null | head -1))"
  say ""
  say "skillctl doctor says:"
  "$SKILLCTL_BIN" doctor
}

finish() {
  say ""
  find_skillctl
  if [ -n "$SKILLCTL_BIN" ] && [ "$DRY" -eq 0 ]; then
    say "skillctl doctor says:"
    "$SKILLCTL_BIN" doctor || true
  fi
  say ""
  say "Workspace ready: $WORKSPACE"
  say "Next for the person who works here: open it and write today's wlog entry."
}

case "$ROLE" in
  author) setup_author ;;
  member) setup_member ;;
  check)  do_check ;;
  *) echo "unknown role: $ROLE (expected author, member or check)" >&2; exit 2 ;;
esac

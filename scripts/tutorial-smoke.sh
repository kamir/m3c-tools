#!/usr/bin/env bash
# tutorial-smoke.sh: run the chain the German scenario tutorials describe, and
# assert every step, so a tutorial cannot go stale without CI noticing.
#
#   docs/tutorial-szenario-01-eigene-skills-mehrere-maschinen.de.md
#   docs/tutorial-szenario-02-erster-signierter-skill.de.md
#
# FR-0118, SPEC-0407 AC-11. Two modes, one script:
#
#   (default)  hermetic, non-interactive, assert-only. This is the CI gate.
#   --walk     the same chain, one step at a time, with the WHY printed and a
#              pause between steps. This is the tutorial, run by a human.
#
# Everything happens in a throwaway workspace with a throwaway HOME, against a
# bare local:// git registry. No network, no server, no admin rights, and your
# real ~/.claude is never touched.
#
# The two NEGATIVE cases are the point, not decoration. A smoke test that only
# walks the happy path stays green in exactly the situation that matters: when a
# gate stops gating. Step 8 proves an unpinned reviewer is refused, step 9 proves
# a tampered bundle is refused.
#
# Exit: 0 all steps behaved as documented; 1 a step drifted (the failure names it).

set -uo pipefail

# ---------------------------------------------------------------- options ----
WALK=0
KEEP=0
SKILLCTL=""
WS=""

usage() {
  cat >&2 <<'USAGE'
Usage: scripts/tutorial-smoke.sh [--walk] [--keep] [--skillctl <path>] [--workspace <dir>]

  --walk              step through the chain with explanations and a pause
                      between steps (the tutorial, for a human).
  --keep              do not delete the workspace at the end; print its path.
  --skillctl <path>   binary to drive. Default: ./build/skillctl, then $PATH.
  --workspace <dir>   where to build the sandbox. Default: a mktemp dir.
  -h, --help          this text.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --walk) WALK=1; shift ;;
    --keep) KEEP=1; shift ;;
    --skillctl) SKILLCTL="${2:-}"; shift 2 ;;
    --workspace) WS="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "tutorial-smoke: unknown flag $1" >&2; usage; exit 2 ;;
  esac
done

# ------------------------------------------------------------------ setup ----
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ -z "$SKILLCTL" ]; then
  if [ -x "$REPO_ROOT/build/skillctl" ]; then
    SKILLCTL="$REPO_ROOT/build/skillctl"
  elif command -v skillctl >/dev/null 2>&1; then
    SKILLCTL="$(command -v skillctl)"
  else
    echo "tutorial-smoke: no skillctl found. Build one with 'make build-skillctl'," >&2
    echo "                or pass --skillctl <path>." >&2
    exit 1
  fi
fi

if [ -z "$WS" ]; then
  WS="$(mktemp -d "${TMPDIR:-/tmp}/tutorial-smoke.XXXXXX")"
else
  mkdir -p "$WS"
fi
CONSUMER_HOME="$WS/consumer"

cleanup() {
  if [ "$KEEP" -eq 1 ]; then
    echo ""
    echo "workspace kept: $WS"
  else
    rm -rf "$WS"
  fi
}
trap cleanup EXIT

# ------------------------------------------------------------------ output ---
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; D='\033[2m'; B='\033[1m'; N='\033[0m'
else
  G=''; R=''; Y=''; D=''; B=''; N=''
fi

STEP=0
FAILURES=0
LOG="$WS/full.log"

step() {
  STEP=$((STEP + 1))
  echo ""
  printf "${B}%s. %s${N}\n" "$STEP" "$1"
}

# why <text...>: the explanation. Printed only in --walk; CI does not need prose.
why() {
  [ "$WALK" -eq 1 ] || return 0
  echo ""
  printf "${D}%s${N}\n" "$1"
}

pause() {
  [ "$WALK" -eq 1 ] || return 0
  echo ""
  printf "${D}   [Enter] weiter${N}"
  read -r _ </dev/tty 2>/dev/null || true
  echo ""
}

# sha256_of <file>: shasum on macOS, sha256sum on most Linux images.
sha256_of() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else sha256sum "$1" | awk '{print $1}'
  fi
}

ok()   { printf "   ${G}ok${N}    %s\n" "$1"; }
bad()  { printf "   ${R}DRIFT${N} %s\n" "$1"; FAILURES=$((FAILURES + 1)); }
note() { printf "   ${D}%s${N}\n" "$1"; }

# run <label> <expected-exit> <cmd...>: run it, compare the exit code, keep going.
# Deliberately NOT fail-fast: one drifted step should not hide the next.
run() {
  local label="$1" want="$2"; shift 2
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  printf '%s\n' "=== $label (want exit $want, got $rc)" "$out" >> "$LOG"
  if [ "$rc" -eq "$want" ]; then
    ok "$label (exit $rc)"
  else
    bad "$label: expected exit $want, got $rc"
    printf '%s\n' "$out" | sed 's/^/         /' | head -12
  fi
  LAST_OUT="$out"
  return 0
}

# expect_in <label> <needle>: assert the last output carried a documented string.
# The tutorials quote these lines, so a changed message is drift even at exit 0.
expect_in() {
  if printf '%s' "$LAST_OUT" | grep -q -- "$2"; then
    ok "$1"
  else
    bad "$1: expected output to contain '$2'"
    printf '%s\n' "$LAST_OUT" | sed 's/^/         /' | head -12
  fi
}

echo ""
printf "${B}skillctl tutorial smoke${N}\n"
note "binary:    $SKILLCTL"
note "version:   $("$SKILLCTL" version 2>&1 | head -1)"
note "workspace: $WS"
note "the chain from docs/tutorial-szenario-02-erster-signierter-skill.de.md"

# ------------------------------------------------------- 1. the skill source --
step "Ein winziger Skill"
why "Ein Skill braucht mindestens eine SKILL.md. Mehr ist fuer die Kette nicht
   noetig: was wir hier pruefen, ist die Provenienz, nicht die Klugheit des Skills."

mkdir -p "$WS/keys" "$WS/src/hello-kup/scripts" "$CONSUMER_HOME/.claude"
cat > "$WS/src/hello-kup/SKILL.md" <<'MD'
---
name: hello-kup
version: 0.1.0
description: Minimaler Uebungsskill fuer die Publisher-Kette, schreibt eine Datei nach ./out.
---

# hello-kup

Schreibt einen Gruss nach ./out/hello.txt. Kein Netzwerk, keine Secrets.
MD
cat > "$WS/src/hello-kup/scripts/hello.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
mkdir -p ./out
echo "hello from hello-kup" > ./out/hello.txt
cat ./out/hello.txt
SH
chmod +x "$WS/src/hello-kup/scripts/hello.sh"
ok "SKILL.md + scripts/hello.sh angelegt"
pause

# ------------------------------------------------------------- 2. die Schluessel
step "Drei Schluessel fuer drei Rollen"
why "Der Autor versiegelt, der Herausgeber nimmt auf, der Reviewer urteilt.
   Drei Rollen, drei Schluessel. Genau daran haengt spaeter Schritt 8: der
   Konsument zaehlt das Urteil nur, weil es von einem Schluessel kommt, den er
   selbst gepinnt hat."

run "keygen (Autor)"       0 "$SKILLCTL" keygen --out "$WS/keys/mitarbeiter"
run "keygen (Herausgeber)" 0 "$SKILLCTL" keygen --out "$WS/keys/eric-herausgeber"
run "keygen (Reviewer)"    0 "$SKILLCTL" keygen --out "$WS/keys/eric-reviewer"

if [ "$(stat -f '%Lp' "$WS/keys/mitarbeiter.priv" 2>/dev/null || stat -c '%a' "$WS/keys/mitarbeiter.priv" 2>/dev/null)" = "600" ]; then
  ok "der private Schluessel hat Modus 0600"
else
  bad "der private Schluessel hat NICHT Modus 0600 (sign faellt darauf fail-closed)"
fi
pause

# ------------------------------------------------------------- 3. pack + sign
step "Packen, signieren, und die Digest-Falle"
why "pack meldet einen bundle_digest, sign meldet einen digest, und die beiden
   sind VERSCHIEDEN. Massgeblich ist der von sign: er steht im Signaturdateinamen
   und gehoert in attest, publish --digest und revoke --digest. Der von pack ist
   der Manifest-Digest. (BUG-0213 will genau das in der Ausgabe klarstellen.)"

cd "$WS"
run "pack" 0 "$SKILLCTL" pack \
  --skill "$WS/src/hello-kup" -o "$WS/hello-kup@0.1.0.skb" \
  --name hello-kup --version 0.1.0 --summary "Uebungsskill" \
  --author-intent green --author-intent-rationale "kein Netzwerk; schreibt nur ./out"
expect_in "pack nennt einen bundle_digest" "bundle_digest:"
expect_in "pack sagt, dass es NICHT der Digest fuer attest ist" "manifest digest"
PACK_DIGEST="$(printf '%s' "$LAST_OUT" | awk '/^bundle_digest:/ {print $2}')"

run "sign" 0 "$SKILLCTL" sign \
  --key "$WS/keys/mitarbeiter.priv" --identity-id id:mitarbeiter@kup \
  "$WS/hello-kup@0.1.0.skb"
expect_in "sign nennt einen digest" "digest:"
# BUG-0213: die Ausgabe muss selbst sagen, welcher der beiden Digests gilt. Genau
# das ist die Zusage, die das Tutorial an dieser Stelle macht.
expect_in "sign sagt, wofuer der Digest gilt" "use this for"
DIGEST_HEX="$(printf '%s' "$LAST_OUT" | awk '/^digest:/ {print $2}')"
DIGEST="sha256:$DIGEST_HEX"
note "pack: $PACK_DIGEST"
note "sign: $DIGEST   <- dieser gilt"

if [ -n "$DIGEST_HEX" ] && [ "$PACK_DIGEST" != "$DIGEST" ]; then
  ok "die beiden Digests sind verschieden, wie im Tutorial beschrieben"
else
  bad "die Digest-Falle aus dem Tutorial trifft nicht mehr zu: pack=$PACK_DIGEST sign=$DIGEST"
fi
pause

# --------------------------------------------------------- 4. Determinismus --
step "Zweimal packen muss byteidentisch sein"
why "Ist es das nicht, enthaelt der Skill etwas Zeitabhaengiges, und dann ist
   keine Signatur eine Aussage ueber den Inhalt."

run "pack (zweiter Lauf)" 0 "$SKILLCTL" pack \
  --skill "$WS/src/hello-kup" -o "$WS/probe.skb" \
  --name hello-kup --version 0.1.0 --summary "Uebungsskill" \
  --author-intent green --author-intent-rationale "kein Netzwerk; schreibt nur ./out"
A="$(sha256_of "$WS/hello-kup@0.1.0.skb")"
Bv="$(sha256_of "$WS/probe.skb")"
if [ "$A" = "$Bv" ]; then ok "beide Bundles sind byteidentisch"; else bad "pack ist nicht deterministisch"; fi
rm -f "$WS/probe.skb"
pause

# ------------------------------------------------------------ 5. verify-sig --
step "Der Autor prueft sich selbst"
why "Exit 0 heisst: diese Bytes hat dieser Schluessel versiegelt. Mehr nicht.
   Es heisst NICHT, dass der Inhalt harmlos ist."
run "verify-sig" 0 "$SKILLCTL" verify-sig --pubkey "$WS/keys/mitarbeiter.pub" "$WS/hello-kup@0.1.0.skb"
expect_in "verify-sig bestaetigt die Signatur" "signature verified"
pause

# -------------------------------------------------------- 6. das Registry ----
step "Ein Registry auf der Platte"
why "registry init legt ein bares git-Repo an. Es ist derselbe Code-Pfad wie
   github:// oder gitlab://, nur ohne Remote. Spaeter schiebt ein
   'git push --mirror' dasselbe Repo auf den Server."
run "registry init" 0 "$SKILLCTL" registry init --registry "local://$WS/registry.git"
pause

# ------------------------------------------------- 7. admit + attest + list --
step "Aufnehmen und attestieren, mit ZWEI verschiedenen Schluesseln"
why "Der Herausgeber nimmt auf, der Reviewer urteilt. Ohne die Attestierung
   bleibt der Skill fuer jeden Konsumenten unter der Governance-Schwelle: die
   Autorenabsicht aus Schritt 3 ist nur ein Hinweis, den der Verifier ignoriert."

run "publish (Admit)" 0 "$SKILLCTL" publish "hello-kup@0.1.0" \
  --bundle "$WS/hello-kup@0.1.0.skb" --version 0.1.0 \
  --registry "local://$WS/registry.git" \
  --key "$WS/keys/eric-herausgeber.priv" --identity id:eric@kup --yes
expect_in "der Admit meldet den git-Transport" "transport=git"

run "publish --attest (Reviewer)" 0 "$SKILLCTL" publish --attest "hello-kup@0.1.0" \
  --digest "$DIGEST" --level green --rationale "geprueft im tutorial-smoke" \
  --registry "local://$WS/registry.git" \
  --identity id:eric-reviewer@kup --key "$WS/keys/eric-reviewer.priv" --yes

run "registry ls" 0 "$SKILLCTL" registry ls --registry "local://$WS/registry.git"
expect_in "das Registry zeigt den Skill als green/ok" "green"
pause

# --------------------------------------------------------- 8. der Konsument --
step "Der Konsument pinnt und zieht"
why "In der trust-roots.yaml steht der Herausgeberschluessel als Registry-Pin UND
   der Reviewer-Schluessel unter signers. Der signers-Block ist der Grund, warum
   die Gewaltenteilung hier kryptografisch ist und nicht bloss organisatorisch."

b64_raw() { if base64 --help 2>&1 | grep -q -- "-w"; then base64 -w0; else base64; fi; }
PUB_B64="$(openssl pkey -pubin -in "$WS/keys/eric-herausgeber.pub" -outform DER | tail -c 32 | b64_raw)"
PUB_FP="$(openssl pkey -pubin -in "$WS/keys/eric-herausgeber.pub" -outform DER | tail -c 32 > "$WS/.fp.bin" && sha256_of "$WS/.fp.bin")"
REV_B64="$(openssl pkey -pubin -in "$WS/keys/eric-reviewer.pub" -outform DER | tail -c 32 | b64_raw)"

write_trust_roots() {  # $1 = with-signers | without-signers
  {
    echo "registry: local://$WS/registry.git"
    echo "pubkey_b64: $PUB_B64"
    echo "fingerprint: sha256:$PUB_FP"
    echo "governance_minimum: green"
    if [ "$1" = "with-signers" ]; then
      echo "governance_quorum: 1"
      echo "signers:"
      echo "  - reviewer_id: id:eric-reviewer@kup"
      echo "    pubkey_b64: $REV_B64"
    fi
  } > "$CONSUMER_HOME/.claude/trust-roots.yaml"
}

write_trust_roots with-signers
ok "trust-roots.yaml geschrieben (mit signers)"

run "pull --dry-run-install" 0 env HOME="$CONSUMER_HOME" "$SKILLCTL" pull \
  --registry "local://$WS/registry.git" --skill hello-kup \
  --install --trust-mode --dry-run-install --no-checkpoint
expect_in "der Pull staged das Bundle als green" "gov=green"
expect_in "der Pull gibt ein G-23-Token aus" "dry-run-install token"

TOKEN="$(printf '%s' "$LAST_OUT" | awk '/dry-run-install token/ {print $NF}')"
run "pull --confirm-install" 0 env HOME="$CONSUMER_HOME" "$SKILLCTL" pull \
  --registry "local://$WS/registry.git" --skill hello-kup \
  --install --trust-mode --confirm-install --dry-run-install-token "$TOKEN" --no-checkpoint

for f in SKILL.md .m3c-provenance.json .skillctl-attest.json; do
  if [ -e "$CONSUMER_HOME/.claude/skills/hello-kup/$f" ]; then
    ok "installiert: $f"
  else
    bad "nach dem Install fehlt $f"
  fi
done
pause

# ------------------------------------------------ 9. Negativprobe A: signers --
step "NEGATIVPROBE A: derselbe Pull ohne den gepinnten Reviewer"
why "Die Attestierung liegt weiter im Repository, sie ist gueltig, und sie zaehlt
   trotzdem nicht. Vertrauen entsteht beim Empfaenger, nicht beim Sender.
   Erwartet: gate 4 und Prozess-Exit 1."

write_trust_roots without-signers
rm -rf "$CONSUMER_HOME/.claude/skills/hello-kup"
run "pull ohne signers" 1 env HOME="$CONSUMER_HOME" "$SKILLCTL" pull \
  --registry "local://$WS/registry.git" --skill hello-kup \
  --install --trust-mode --dry-run-install --no-checkpoint
expect_in "die Ablehnung nennt das Governance-Tor" "gate 4"
write_trust_roots with-signers
pause

# ----------------------------------------------- 10. Negativprobe B: tamper --
step "NEGATIVPROBE B: ein veraendertes Bundle mit umbenannter Signatur"
why "Zuerst der Unfall: Bytes veraendert, Signatur unter altem Namen. Das ergibt
   Exit 1, 'signature file not found', denn der Dateiname traegt den Digest.
   Dann der Angriff: die Signatur wird auf den neuen Digest umbenannt, damit sie
   dazuzugehoeren scheint. Jetzt greift die Kryptografie, Exit 11."

cp "$WS/hello-kup@0.1.0.skb" "$WS/kaputt.skb"
printf '\xff' | dd of="$WS/kaputt.skb" bs=1 seek=200 count=1 conv=notrunc 2>/dev/null
run "verify-sig auf veraenderten Bytes (ohne passende Signatur)" 1 \
  "$SKILLCTL" verify-sig --pubkey "$WS/keys/mitarbeiter.pub" "$WS/kaputt.skb"
expect_in "die Meldung sagt, dass es zu diesen Bytes keine Signatur gibt" "signature file not found"

cp "$WS/hello-kup@0.1.0.skb" "$WS/boese.skb"
SIZE="$(wc -c < "$WS/boese.skb" | tr -d ' ')"
printf '\xff' | dd of="$WS/boese.skb" bs=1 seek=$((SIZE / 2)) count=1 conv=notrunc 2>/dev/null
BOESE_DIGEST="$(sha256_of "$WS/boese.skb")"
cp "$WS/hello-kup@0.1.0.skb.${DIGEST_HEX}.author.sig" "$WS/boese.skb.${BOESE_DIGEST}.author.sig"
run "verify-sig auf der luegenden Signatur" 11 \
  "$SKILLCTL" verify-sig --pubkey "$WS/keys/mitarbeiter.pub" "$WS/boese.skb"
expect_in "die Meldung sagt, dass die Signatur ungueltig ist" "signature is invalid"
pause

# ----------------------------------------------------------------- Bericht ---
echo ""
echo "─────────────────────────────"
if [ "$FAILURES" -eq 0 ]; then
  printf "${G}PASS${N}: %s Schritte, jede Zusage der Tutorials gehalten.\n" "$STEP"
  [ "$WALK" -eq 1 ] && echo "Der ganze Lauf lag unter $WS und hat dein ~/.claude nie angefasst."
  exit 0
else
  printf "${R}FAIL${N}: %s Abweichung(en). Die Tutorials versprechen etwas, das der Code nicht mehr tut.\n" "$FAILURES"
  echo "Volles Protokoll: $LOG (mit --keep bleibt es liegen)"
  exit 1
fi

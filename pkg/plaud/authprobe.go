package plaud

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// plaudTokenCandidatesJS enumerates EVERY plausible bearer token in a plaud.ai
// tab's localStorage AND sessionStorage, returning them as a JSON
// {"candidates":[{"v":<token>,"src":<label>}]} list: quote-stripped, deduped,
// JWT-shaped candidates first. Plaud has renamed/reshaped its token key
// repeatedly and ALSO stores a user-identity JWT (claims email/id/name) under a
// token-named key, so any single "first match" heuristic can grab the wrong
// value; the caller probes each candidate against the API and keeps the one that
// authenticates. `src` is a fixed, secret-safe label (store + match-kind), never
// a raw key name. A Plaud key name can itself embed a JWT. Both stores are
// origin-scoped to plaud.ai, so every candidate legitimately belongs to Plaud.
// Single-line so it embeds cleanly in the JXA osascript path too.
const plaudTokenCandidatesJS = `(function(){try{var seen={},out=[];function strip(v){return v.replace(/^\s*["']|["']\s*$/g,"");}function scan(store,label){if(!store)return;for(var i=0;i<store.length;i++){var k=store.key(i);if(!k)continue;var v=store.getItem(k);if(!v)continue;var uv=strip(v);if(uv.length<=10)continue;var isJwt=/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\./.test(uv);var nameHit=/token|jwt|auth|bearer|session/i.test(k);if(!isJwt&&!(nameHit&&uv.length>20))continue;if(seen[uv])continue;seen[uv]=1;out.push({v:uv,src:label+(isJwt?":jwt":":name"),j:isJwt?0:1});}}scan(localStorage,"LS");scan(sessionStorage,"SS");out.sort(function(a,b){return a.j-b.j;});for(var m=0;m<out.length;m++){delete out[m].j;}return JSON.stringify({candidates:out});}catch(e){return JSON.stringify({candidates:[]});}})()`

// maxTokenProbes caps how many candidates we send to the API, so a tab with many
// token-named localStorage keys can never fan out into an unbounded probe storm.
const maxTokenProbes = 8

// maxCandidateLen bounds a single candidate value. No legitimate Plaud bearer
// comes close; the cap prevents a hostile tab from padding localStorage into
// large probe headers / memory, and avoids a truncated harvest being probed.
const maxCandidateLen = 8192

// allowedSrcLabels is the closed set of provenance labels the harvester may
// emit. Anything else is coerced to "unknown" so a page that shadows
// JSON.stringify/localStorage cannot inject arbitrary text (ANSI escapes,
// forged log lines, newlines) into stderr/error strings via the src field.
var allowedSrcLabels = map[string]bool{
	"LS:jwt": true, "LS:name": true, "SS:jwt": true, "SS:name": true,
}

// hasControlChars reports whether s contains a C0 control byte or DEL. Such a
// value could not be a real bearer and would only either poison an HTTP header
// or, worse, error the transport on the FIRST probe and be misread as
// "API unreachable": causing the poisoned value to be persisted as a fallback.
func hasControlChars(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0
}

// candidate is a harvested token value plus a secret-safe provenance label.
type candidate struct {
	Value string `json:"v"`
	Src   string `json:"src"`
}

// errProbeUnreachable signals that the Plaud API could not be reached to
// validate any candidate (network/transport failure), as opposed to the API
// being reached and rejecting every candidate. Callers may fall back to an
// offline best-guess when the API is merely unreachable.
var errProbeUnreachable = errors.New("plaud: could not reach API to validate token")

// parsePlaudCandidates parses the plaudTokenCandidatesJS payload into sanitized,
// plausibility-filtered candidates, preserving order (JWT-shaped first) and
// dropping duplicates and implausibly short values.
func parsePlaudCandidates(raw string) []candidate {
	var res struct {
		Candidates []candidate `json:"candidates"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(raw)), &res) != nil {
		return nil
	}
	seen := make(map[string]bool, len(res.Candidates))
	out := make([]candidate, 0, len(res.Candidates))
	for _, c := range res.Candidates {
		v := sanitizePlaudToken(c.Value)
		if len(v) <= 10 || len(v) > maxCandidateLen || v == "null" || seen[v] || hasControlChars(v) {
			continue
		}
		seen[v] = true
		src := c.Src
		if !allowedSrcLabels[src] {
			src = "unknown"
		}
		out = append(out, candidate{Value: v, Src: src})
	}
	return out
}

// selectValidatedToken probes each candidate against the Plaud API and returns
// the first the server accepts (status==0), along with its secret-safe source
// label. If the API is reachable but rejects every candidate, it returns a
// secret-safe error (counts + provenance labels only). If the API is unreachable
// on the very first probe, it returns errProbeUnreachable so the caller can fall
// back to an offline best-guess.
func selectValidatedToken(cfg *Config, cands []candidate) (token, src string, err error) {
	if len(cands) == 0 {
		return "", "", fmt.Errorf("plaud: no token candidates found in browser storage")
	}
	reached := false
	tried := make([]string, 0, len(cands))
	for i, c := range cands {
		if i >= maxTokenProbes {
			break
		}
		ok, perr := NewClient(cfg, c.Value).TokenAuthenticates()
		if perr != nil {
			if !reached {
				// Never reached the API: treat as unreachable, not "rejected".
				return "", "", fmt.Errorf("%w: %v", errProbeUnreachable, perr)
			}
			continue // transient error mid-run; try the next candidate
		}
		reached = true
		tried = append(tried, c.Src)
		if ok {
			return c.Value, c.Src, nil
		}
	}
	return "", "", fmt.Errorf("plaud: extracted %d candidate(s) [%s] but the API accepted none "+
		"(invalid auth header): the bearer may live outside localStorage/sessionStorage; "+
		"re-run with M3C_PLAUD_DEBUG=1 to inspect", len(cands), strings.Join(tried, ", "))
}

// finishTokenSelection turns a harvested candidate list into a single validated
// token. On success it logs (secret-safe) which source won. If the API is
// unreachable it falls back to the strongest heuristic candidate (JWT-shaped
// first) so offline extraction still yields a token; a genuine "API rejected
// everything" error is propagated so the user gets an actionable message instead
// of a silently-wrong token.
func finishTokenSelection(cands []candidate) (string, error) {
	if len(cands) == 0 {
		return "", fmt.Errorf("no token candidates found in Chrome localStorage/sessionStorage")
	}
	cfg := LoadConfig()
	// Defense in depth: never fan harvested tokens at a non-plaud.ai base, even if
	// a future caller hands us a hand-built Config that bypassed LoadConfig's guard.
	if !isAllowedPlaudDomain(cfg.APIURL) {
		return "", fmt.Errorf("plaud: refusing to probe tokens: API base is not an https *.plaud.ai host")
	}
	tok, src, err := selectValidatedToken(cfg, cands)
	if err == nil {
		fmt.Fprintf(os.Stderr, "  [plaud] token validated via %s (probed Plaud API; self-calibrated past renamed keys)\n", src)
		return tok, nil
	}
	if errors.Is(err, errProbeUnreachable) {
		fmt.Fprintf(os.Stderr, "  [plaud] could not reach Plaud API to validate token (%v); "+
			"using best-guess candidate %s: a later API call will surface any auth problem\n", err, cands[0].Src)
		return cands[0].Value, nil
	}
	return "", err
}

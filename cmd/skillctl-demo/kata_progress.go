package main

// kata_progress.go — the local-first mastery store for Kata training mode.
//
// This file is the PURE, unit-testable core of the Kata coach: the beat model,
// the distinct-rep counter, the N/3 → sitzt progression, the rust stall-window
// state machine, the exit-code → obstacle mapping, and the per-rep signature.
// It mirrors the CEW SPEC-0303 three-state machine (rot / gelb / grün) and the
// SPEC-0121 skillprofile mastery ladder, kept local for now (a later bridge —
// out of scope here — posts beats to cew_kata_events + the skillprofile ladder).
//
// Honesty rule (non-negotiable): a Beat is only ever recorded for a REAL
// skillctl run whose observed exit code matched the Kata's target. Nothing in
// this file can invent a pass — Record simply refuses to count anything else.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// KataState is the three-state mastery colour, identical to `cew` (SPEC-0303).
type KataState string

const (
	StateRot   KataState = "rot"   // new — never practiced (0 distinct clean reps)
	StateGelb  KataState = "gelb"  // practicing — some reps, but not yet sitzt (or rusting)
	StateGruen KataState = "gruen" // sitzt — required distinct clean reps met and fresh
)

// DefaultStallDays is the rust window when KATA_STALL_DAYS is unset (SPEC-0303).
const DefaultStallDays = 5

// Beat is one recorded, target-matching skillctl run toward mastery of a Kata.
// Signature de-duplicates identical artifacts so a learner cannot spam the same
// run: only distinct signatures advance the N/required count.
type Beat struct {
	Kata      string    `json:"kata"`
	Signature string    `json:"signature"`
	Observed  int       `json:"observed"` // the REAL exit code (or per-skill verdict) observed
	Target    int       `json:"target"`   // the Kata's target condition code
	At        time.Time `json:"at"`
}

// OK reports whether the beat's observed result met the Kata target. Record
// only accepts OK beats — this is the honesty gate in data form.
func (b Beat) OK() bool { return b.Observed == b.Target }

// kataRecord is the persisted per-Kata state: every distinct clean beat plus the
// last time the Kata was practiced (drives the rust window).
type kataRecord struct {
	Kata          string    `json:"kata"`
	Beats         []Beat    `json:"beats"`
	LastPracticed time.Time `json:"last_practiced"`
}

// diskModel is the on-disk JSON envelope (versioned for forward-compat).
type diskModel struct {
	Version int                    `json:"version"`
	Katas   map[string]*kataRecord `json:"katas"`
}

// KataStore is the JSON-backed, mutex-guarded progress store. Persisted to
// ~/.skillctl-demo/kata-progress.json (override Path in tests).
type KataStore struct {
	mu      sync.Mutex
	Path    string
	records map[string]*kataRecord
}

// NewKataStore returns an empty in-memory store bound to path. Call Load to read
// any prior progress from disk.
func NewKataStore(path string) *KataStore {
	return &KataStore{Path: path, records: make(map[string]*kataRecord)}
}

// DefaultProgressPath is ~/.skillctl-demo/kata-progress.json. Falls back to a
// relative path when the home dir cannot be resolved (never panics).
func DefaultProgressPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".skillctl-demo", "kata-progress.json")
	}
	return filepath.Join(home, ".skillctl-demo", "kata-progress.json")
}

// StallDays reads KATA_STALL_DAYS (SPEC-0303); default DefaultStallDays. A
// non-positive or unparsable value falls back to the default.
func StallDays() int {
	v := os.Getenv("KATA_STALL_DAYS")
	if v == "" {
		return DefaultStallDays
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return DefaultStallDays
	}
	return n
}

// Load reads the progress file into memory. A missing file is not an error (a
// fresh machine starts with every Kata rot).
func (s *KataStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var m diskModel
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	if m.Katas != nil {
		s.records = m.Katas
	}
	return nil
}

// Save writes the store atomically (temp file + rename) with 0600 perms.
func (s *KataStore) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *KataStore) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return err
	}
	m := diskModel{Version: 1, Katas: s.records}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

// Record files a Beat toward its Kata's mastery. It is the single "record a
// beat" entry point required to be callable without stdin. It:
//   - REFUSES any beat whose observed result did not match the target (honesty);
//   - always refreshes LastPracticed (a repeated rep still counts as practice,
//     resetting the rust clock);
//   - only APPENDS (advancing the distinct count) when the signature is new, so
//     re-running the identical artifact cannot inflate progress.
//
// Returns added=true only when a genuinely new distinct clean rep was counted.
func (s *KataStore) Record(b Beat) (added bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !b.OK() {
		return false // not a beat: never count a non-matching run as progress
	}
	if b.At.IsZero() {
		b.At = time.Now()
	}
	rec := s.records[b.Kata]
	if rec == nil {
		rec = &kataRecord{Kata: b.Kata}
		s.records[b.Kata] = rec
	}
	if b.At.After(rec.LastPracticed) {
		rec.LastPracticed = b.At
	}
	for _, e := range rec.Beats {
		if e.Signature == b.Signature {
			return false // duplicate artifact — practiced, but no new distinct rep
		}
	}
	rec.Beats = append(rec.Beats, b)
	return true
}

// Distinct returns the number of distinct clean reps recorded for a Kata.
func (s *KataStore) Distinct(kata string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return distinctLocked(s.records[kata])
}

func distinctLocked(rec *kataRecord) int {
	if rec == nil {
		return 0
	}
	seen := make(map[string]struct{}, len(rec.Beats))
	for _, b := range rec.Beats {
		seen[b.Signature] = struct{}{}
	}
	return len(seen)
}

// LastPracticed returns the most recent practice time for a Kata (zero if none).
func (s *KataStore) LastPracticed(kata string) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec := s.records[kata]; rec != nil {
		return rec.LastPracticed
	}
	return time.Time{}
}

// State computes the current mastery colour for a Kata at time now.
func (s *KataStore) State(kata string, required, stallDays int, now time.Time) (KataState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.records[kata]
	return computeKataState(distinctLocked(rec), required, recLast(rec), now, stallDays)
}

func recLast(rec *kataRecord) time.Time {
	if rec == nil {
		return time.Time{}
	}
	return rec.LastPracticed
}

// computeKataState is the PURE 3-state machine (no IO). Given the number of
// distinct clean reps, the required count, the last-practiced time, "now" and
// the stall window (days), it returns the colour and whether a met Kata has
// rusted:
//
//   - distinct == 0                       → rot (new, never practiced)
//   - 0 < distinct < required             → gelb (practicing)
//   - distinct >= required && fresh       → grün (sitzt)
//   - distinct >= required && stale       → gelb, rusted=true (sitzt but rusting)
//
// A Kata rusts when now-last exceeds stallDays; rust demotes a met Kata to gelb
// rather than all the way to rot (the reps are banked, the freshness lapsed).
func computeKataState(distinct, required int, last, now time.Time, stallDays int) (KataState, bool) {
	if distinct <= 0 {
		return StateRot, false
	}
	met := required > 0 && distinct >= required
	rusted := false
	if !last.IsZero() && stallDays > 0 {
		if now.Sub(last) > time.Duration(stallDays)*24*time.Hour {
			rusted = true
		}
	}
	switch {
	case met && !rusted:
		return StateGruen, false
	case met && rusted:
		return StateGelb, true // banked reps, but freshness lapsed → rusting
	default:
		return StateGelb, false // practicing toward the target
	}
}

// repSignature is the PURE per-rep signature: a short digest over the Kata id, a
// per-rep nonce, and an artifact fingerprint (e.g. the bundle digest for K1/K5,
// or the nonce-bearing tamper/drift marker for K2/K3). Distinct artifacts →
// distinct signatures, so identical re-runs are de-duplicated by Record.
func repSignature(kataID, nonce, artifact string) string {
	sum := sha256.Sum256([]byte(kataID + "\x00" + nonce + "\x00" + artifact))
	return hex.EncodeToString(sum[:8])
}

// obstacleForExit maps a REAL skillctl exit code (or per-skill verdict) to a
// plain-language obstacle, per SPEC-0188 §11. This is the "What blocked you?"
// coaching step, kept pure so it is unit-testable and never depends on a run.
func obstacleForExit(code int) string {
	switch code {
	case 0:
		return "clean — the target condition is met (nothing blocked you)"
	case 1:
		return "generic error — a precondition wasn't ready (e.g. no signed admission envelope / sidecar)"
	case 2:
		return "usage / precondition refusal — a wrong flag, or a G-23 two-step confirm that RE-CHECKED the live set and refused on drift (no --force)"
	case 10:
		return "digest mismatch — the bytes changed after signing (tamper); the signature no longer covers them"
	case 11:
		return "author signature invalid — not signed by a key pinned in trust-roots (unsigned, or the wrong author key)"
	case 12:
		return "registry not in trust-roots — the registry that admitted this bundle isn't pinned (or its key doesn't match)"
	case 13:
		return "governance below minimum — the attested level is under the trust-root's floor"
	case 14:
		return "depends_on unsatisfied — a required dependency isn't admitted"
	case 15:
		return "blob missing — the bundle payload the meta points at isn't present"
	case 17:
		return "revoked — a signed revocation list covers this digest; it fails closed offline"
	case 22:
		return "stale + high-risk — the freshness snapshot is too old for a high-risk action, so it fails closed"
	case 32:
		return "runtime envelope violation — an out-of-envelope egress was attempted (roadmap surface, not run here)"
	case -1:
		return "exec failure — skillctl could not be run at all (binary missing / sandbox error)"
	default:
		return "unexpected exit " + strconv.Itoa(code) + " — see `skillctl <cmd> --help` for the numbered codes"
	}
}

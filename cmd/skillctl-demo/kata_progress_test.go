package main

// Pure, offline unit tests for the Kata mastery core: the N/required → sitzt
// progression, the rust stall transition, distinct-rep counting + de-dup, the
// exit-code → obstacle mapping, and the store's honesty gate + persistence.
// No stdin, no network, no skillctl.

import (
	"path/filepath"
	"testing"
	"time"
)

func TestComputeKataState_Progression(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name     string
		distinct int
		required int
		last     time.Time
		stall    int
		want     KataState
		rusted   bool
	}{
		{"new/never-practiced", 0, 3, time.Time{}, 5, StateRot, false},
		{"practicing-1of3", 1, 3, now, 5, StateGelb, false},
		{"practicing-2of3", 2, 3, now, 5, StateGelb, false},
		{"sitzt-fresh", 3, 3, now, 5, StateGruen, false},
		{"sitzt-over", 4, 3, now, 5, StateGruen, false},
		{"single-rep-kata", 1, 1, now, 5, StateGruen, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, rusted := computeKataState(c.distinct, c.required, c.last, now, c.stall)
			if st != c.want || rusted != c.rusted {
				t.Fatalf("computeKataState(%d,%d) = (%s,%v); want (%s,%v)",
					c.distinct, c.required, st, rusted, c.want, c.rusted)
			}
		})
	}
}

func TestComputeKataState_RustStallTransition(t *testing.T) {
	now := time.Now()
	// Met (3/3) but last practiced 6 days ago, stall window 5 → rusting → gelb.
	last := now.Add(-6 * 24 * time.Hour)
	st, rusted := computeKataState(3, 3, last, now, 5)
	if st != StateGelb || !rusted {
		t.Fatalf("stale met Kata = (%s,%v); want (gelb,true)", st, rusted)
	}
	// Same reps, but practiced 4 days ago → still fresh → grün.
	fresh := now.Add(-4 * 24 * time.Hour)
	st, rusted = computeKataState(3, 3, fresh, now, 5)
	if st != StateGruen || rusted {
		t.Fatalf("fresh met Kata = (%s,%v); want (gruen,false)", st, rusted)
	}
	// A never-met Kata does not "rust" — it stays practicing (gelb), never rot.
	st, rusted = computeKataState(1, 3, last, now, 5)
	if st != StateGelb || rusted {
		t.Fatalf("stale unmet Kata = (%s,%v); want (gelb,false)", st, rusted)
	}
}

func TestStore_DistinctRepCountingAndHonesty(t *testing.T) {
	store := NewKataStore(filepath.Join(t.TempDir(), "p.json"))
	now := time.Now()

	// A non-matching run is NOT a beat (honesty gate): observed != target.
	if added := store.Record(Beat{Kata: "K1", Signature: "s0", Observed: 11, Target: 0, At: now}); added {
		t.Fatal("Record accepted a non-matching run as a beat")
	}
	if d := store.Distinct("K1"); d != 0 {
		t.Fatalf("distinct after rejected beat = %d; want 0", d)
	}

	// First clean rep: counts.
	if added := store.Record(Beat{Kata: "K1", Signature: "s1", Observed: 0, Target: 0, At: now}); !added {
		t.Fatal("first clean rep was not counted")
	}
	// Identical artifact (same signature): practiced, but NOT a new distinct rep.
	if added := store.Record(Beat{Kata: "K1", Signature: "s1", Observed: 0, Target: 0, At: now}); added {
		t.Fatal("duplicate signature counted as a new distinct rep")
	}
	if d := store.Distinct("K1"); d != 1 {
		t.Fatalf("distinct after dup = %d; want 1", d)
	}
	// A genuinely distinct artifact advances the count.
	if added := store.Record(Beat{Kata: "K1", Signature: "s2", Observed: 0, Target: 0, At: now}); !added {
		t.Fatal("distinct signature not counted")
	}
	if d := store.Distinct("K1"); d != 2 {
		t.Fatalf("distinct after 2 unique = %d; want 2", d)
	}
}

func TestStore_ProgressionToSitzt(t *testing.T) {
	store := NewKataStore(filepath.Join(t.TempDir(), "p.json"))
	now := time.Now()
	required := 3
	for i, sig := range []string{"a", "b", "c"} {
		store.Record(Beat{Kata: "K2", Signature: sig, Observed: 10, Target: 10, At: now})
		st, _ := store.State("K2", required, 5, now)
		wantGruen := i == 2
		if wantGruen && st != StateGruen {
			t.Fatalf("after %d reps state=%s; want gruen", i+1, st)
		}
		if !wantGruen && st != StateGelb {
			t.Fatalf("after %d reps state=%s; want gelb", i+1, st)
		}
	}
}

func TestStore_SaveLoadRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.json")
	s1 := NewKataStore(path)
	now := time.Now()
	s1.Record(Beat{Kata: "K3", Signature: "x", Observed: 2, Target: 2, At: now})
	s1.Record(Beat{Kata: "K3", Signature: "y", Observed: 2, Target: 2, At: now})
	if err := s1.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	s2 := NewKataStore(path)
	if err := s2.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if d := s2.Distinct("K3"); d != 2 {
		t.Fatalf("reloaded distinct = %d; want 2", d)
	}
}

func TestObstacleForExit_Mapping(t *testing.T) {
	// Every mapped code returns a distinct, non-empty, keyword-bearing message.
	cases := map[int]string{
		0:   "clean",
		1:   "precondition",
		2:   "refus",
		10:  "digest",
		11:  "author",
		12:  "registry",
		13:  "governance",
		17:  "revoked",
		22:  "fails closed",
		-1:  "exec failure",
		999: "unexpected exit 999",
	}
	seen := map[string]bool{}
	for code, want := range cases {
		got := obstacleForExit(code)
		if got == "" {
			t.Fatalf("obstacleForExit(%d) empty", code)
		}
		if !containsFold(got, want) {
			t.Errorf("obstacleForExit(%d) = %q; want substring %q", code, got, want)
		}
		if code >= 0 && code != 999 {
			if seen[got] {
				t.Errorf("obstacleForExit(%d) is not distinct: %q", code, got)
			}
			seen[got] = true
		}
	}
}

func TestRepSignature_DistinctByNonceAndArtifact(t *testing.T) {
	a := repSignature("K1", "nonce1", "digestA")
	b := repSignature("K1", "nonce2", "digestA") // different nonce
	c := repSignature("K1", "nonce1", "digestB") // different artifact
	d := repSignature("K1", "nonce1", "digestA") // identical → same signature
	if a == b || a == c {
		t.Fatalf("signatures should differ by nonce/artifact: a=%s b=%s c=%s", a, b, c)
	}
	if a != d {
		t.Fatalf("identical inputs should yield identical signature: a=%s d=%s", a, d)
	}
}

func TestStallDays_Env(t *testing.T) {
	t.Setenv("KATA_STALL_DAYS", "")
	if got := StallDays(); got != DefaultStallDays {
		t.Fatalf("unset StallDays = %d; want %d", got, DefaultStallDays)
	}
	t.Setenv("KATA_STALL_DAYS", "3")
	if got := StallDays(); got != 3 {
		t.Fatalf("StallDays = %d; want 3", got)
	}
	t.Setenv("KATA_STALL_DAYS", "garbage")
	if got := StallDays(); got != DefaultStallDays {
		t.Fatalf("bad StallDays = %d; want default %d", got, DefaultStallDays)
	}
}

// containsFold is a tiny case-insensitive substring check (avoids importing
// strings just for the test's assertion helper).
func containsFold(s, sub string) bool {
	return len(sub) == 0 || indexFold(s, sub) >= 0
}

func indexFold(s, sub string) int {
	ls, lsub := lower(s), lower(sub)
	for i := 0; i+len(lsub) <= len(ls); i++ {
		if ls[i:i+len(lsub)] == lsub {
			return i
		}
	}
	return -1
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

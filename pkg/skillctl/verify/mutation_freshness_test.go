package verify

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

func mutationFixture(t *testing.T) (MutationFreshnessOpts, ed25519.PrivateKey) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("M3C_TOKEN_STORE", "file")
	t.Setenv("M3C_TEST_KEYCHAIN", "0")
	t.Setenv("M3C_ER1_KEYCHAIN", "off")
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("m", ed25519.SeedSize)))
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	opts := MutationFreshnessOpts{
		Action: MutationInstall, ExpectedRegistry: "https://registry.invalid/skills",
		SubjectDigest: "sha256:" + strings.Repeat("a", 64),
		Root: &TrustRoot{RegistryURL: "https://registry.invalid/skills", MinRevocationEpoch: 3,
			RegistryKeys: []RegistryKey{{Pubkey: key.Public().(ed25519.PublicKey)}}},
		MinimumEpoch: 5, Clock: MutationClockState{Now: now, LastObservedAt: now.Add(-time.Minute)},
	}
	opts.Revocations = mutationList(t, opts, key, now.Add(-time.Hour), nil)
	return opts, key
}

func mutationList(t *testing.T, opts MutationFreshnessOpts, key ed25519.PrivateKey, issued time.Time, revoked []string) *RevocationList {
	t.Helper()
	list, err := NewSignedRevocationList(opts.ExpectedRegistry, issued.Format(time.RFC3339Nano), 7, revoked, key)
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func TestMutationFreshnessSignedBoundaries(t *testing.T) {
	for _, action := range []MutationAction{MutationInstall, MutationAdmit, MutationAttest} {
		for _, age := range []time.Duration{0, 24 * time.Hour, 24*time.Hour + time.Nanosecond, -time.Nanosecond} {
			t.Run(string(action)+"/"+age.String(), func(t *testing.T) {
				opts, key := mutationFixture(t)
				opts.Action = action
				opts.Revocations = mutationList(t, opts, key, opts.Clock.Now.Add(-age), nil)
				dec, err := EvaluateMutationFreshness(opts)
				want := age >= 0 && age <= 24*time.Hour
				if dec.Allowed != want || (err == nil) != want {
					t.Fatalf("age=%v decision=%+v error=%v", age, dec, err)
				}
				if dec.Age != age || !dec.AgeKnown || dec.MaxAge != 24*time.Hour || dec.EvidenceSource != "signed_revocation_list" || dec.Epoch != 7 {
					t.Fatalf("lost authenticated decision detail: %+v", dec)
				}
				if !want && !errors.Is(err, ErrRevocationStale) {
					t.Fatalf("missing stale classification: %v", err)
				}
			})
		}
	}
}

func TestMutationFreshnessRejectsInvalidInputs(t *testing.T) {
	cases := []struct {
		name, reason string
		change       func(*MutationFreshnessOpts)
		cause        error
	}{
		{"action", "invalid_action", func(o *MutationFreshnessOpts) { o.Action = "execute" }, nil},
		{"empty_action", "invalid_action", func(o *MutationFreshnessOpts) { o.Action = "" }, nil},
		{"empty_digest", "invalid_subject_digest", func(o *MutationFreshnessOpts) { o.SubjectDigest = "" }, nil},
		{"digest", "invalid_subject_digest", func(o *MutationFreshnessOpts) { o.SubjectDigest = "sha256:bad" }, nil},
		{"missing_root", "missing_authority", func(o *MutationFreshnessOpts) { o.Root = nil }, ErrRegistryNotTrusted},
		{"missing_list", "missing_authority", func(o *MutationFreshnessOpts) { o.Revocations = nil }, ErrRegistryNotTrusted},
		{"empty_registry", "registry_mismatch", func(o *MutationFreshnessOpts) { o.ExpectedRegistry = "" }, ErrRegistryNotTrusted},
		{"root_registry", "registry_mismatch", func(o *MutationFreshnessOpts) { o.Root.RegistryURL += "/different" }, ErrRegistryNotTrusted},
		{"expected_registry", "registry_mismatch", func(o *MutationFreshnessOpts) { o.ExpectedRegistry += "/different" }, ErrRegistryNotTrusted},
		{"floor_negative", "invalid_or_unversioned_epoch", func(o *MutationFreshnessOpts) { o.MinimumEpoch = -1 }, ErrRegistryNotTrusted},
		{"root_floor_negative", "invalid_or_unversioned_epoch", func(o *MutationFreshnessOpts) { o.Root.MinRevocationEpoch = -1 }, ErrRegistryNotTrusted},
		{"unversioned", "invalid_or_unversioned_epoch", func(o *MutationFreshnessOpts) { o.Revocations.Epoch = 0 }, ErrRegistryNotTrusted},
		{"negative_epoch", "invalid_or_unversioned_epoch", func(o *MutationFreshnessOpts) { o.Revocations.Epoch = -1 }, ErrRegistryNotTrusted},
		{"adopted_rollback", "untrusted_revocation_list", func(o *MutationFreshnessOpts) { o.MinimumEpoch = 8 }, ErrRegistryNotTrusted},
		{"root_rollback", "untrusted_revocation_list", func(o *MutationFreshnessOpts) { o.Root.MinRevocationEpoch = 8 }, ErrRegistryNotTrusted},
		{"unsigned", "untrusted_revocation_list", func(o *MutationFreshnessOpts) { o.Revocations.SignatureB64 = "" }, ErrRegistryNotTrusted},
		{"forged", "untrusted_revocation_list", func(o *MutationFreshnessOpts) { o.Revocations.SignatureB64 = strings.Repeat("A", 88) }, ErrRegistryNotTrusted},
		{"retired_key", "untrusted_revocation_list", func(o *MutationFreshnessOpts) { o.Root.RegistryKeys[0].Retired = "2026-10-22" }, ErrRegistryNotTrusted},
		{"wrong_key", "untrusted_revocation_list", func(o *MutationFreshnessOpts) {
			key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("n", ed25519.SeedSize)))
			o.Root.RegistryKeys[0].Pubkey = key.Public().(ed25519.PublicKey)
		}, ErrRegistryNotTrusted},
		{"no_keys", "untrusted_revocation_list", func(o *MutationFreshnessOpts) { o.Root.RegistryKeys = nil }, ErrRegistryNotTrusted},
		{"mutated_time", "untrusted_revocation_list", func(o *MutationFreshnessOpts) { o.Revocations.IssuedAt = o.Clock.Now.Format(time.RFC3339) }, ErrRegistryNotTrusted},
		{"mutated_epoch", "untrusted_revocation_list", func(o *MutationFreshnessOpts) { o.Revocations.Epoch++ }, ErrRegistryNotTrusted},
		{"mutated_set", "untrusted_revocation_list", func(o *MutationFreshnessOpts) { o.Revocations.RevokedDigests = []string{o.SubjectDigest} }, ErrRegistryNotTrusted},
		{"missing_now", "missing_clock_history", func(o *MutationFreshnessOpts) { o.Clock.Now = time.Time{} }, ErrRevocationStale},
		{"missing_history", "missing_clock_history", func(o *MutationFreshnessOpts) { o.Clock.LastObservedAt = time.Time{} }, ErrRevocationStale},
		{"clock_rollback", "clock_rollback", func(o *MutationFreshnessOpts) { o.Clock.LastObservedAt = o.Clock.Now.Add(time.Nanosecond) }, ErrRevocationStale},
		{"bad_policy", "invalid_root_freshness_policy", func(o *MutationFreshnessOpts) { o.Root.MaxStaleness = "nonsense" }, ErrRevocationStale},
		{"negative_policy", "invalid_root_freshness_policy", func(o *MutationFreshnessOpts) { o.Root.MaxStaleness = "-1h" }, ErrRevocationStale},
		{"bad_fail_policy", "invalid_root_freshness_policy", func(o *MutationFreshnessOpts) { o.Root.FailPolicy = "unknown" }, ErrRevocationStale},
		{"high_fail_open", "invalid_root_freshness_policy", func(o *MutationFreshnessOpts) { o.Root.FailPolicyByRisk = map[string]string{"high": "open"} }, ErrRevocationStale},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts, _ := mutationFixture(t)
			tc.change(&opts)
			dec, err := EvaluateMutationFreshness(opts)
			if err == nil || dec.Allowed || dec.Reason != tc.reason || (tc.cause != nil && !errors.Is(err, tc.cause)) {
				t.Fatalf("decision=%+v error=%v; want %s, %v", dec, err, tc.reason, tc.cause)
			}
			if errors.Is(err, ErrRegistryNotTrusted) && dec.EvidenceSource != "" {
				t.Fatalf("untrusted input claimed authenticated source: %+v", dec)
			}
		})
	}
}

func TestMutationFreshnessRegistryKeyReuse(t *testing.T) {
	for _, foreign := range []string{"https://registry.invalid/other", "https://registry.invalid/skills/../other", "https://other.invalid/skills", "http://registry.invalid/skills"} {
		t.Run(foreign, func(t *testing.T) {
			opts, key := mutationFixture(t)
			list, err := NewSignedRevocationList(foreign, opts.Revocations.IssuedAt, 7, nil, key)
			if err != nil {
				t.Fatal(err)
			}
			opts.Revocations = list
			// A valid shared-key signature does not authorize a foreign registry.
			canonical, err := CanonicalRevocationBytes(list.RegistryURL, list.IssuedAt, list.Epoch, list.RevokedDigests)
			if err != nil {
				t.Fatal(err)
			}
			signature, err := decodeSignatureB64(list.SignatureB64)
			if err != nil || !ed25519.Verify(key.Public().(ed25519.PublicKey), canonical, signature) {
				t.Fatal("fixture does not carry a valid shared-key signature")
			}
			if _, err := VerifyRevocationList(list, opts.Root, 5); !errors.Is(err, ErrRegistryNotTrusted) {
				t.Fatalf("foreign registry accepted by revocation verifier: %v", err)
			}
			dec, err := EvaluateMutationFreshness(opts)
			if dec.Allowed || !errors.Is(err, ErrRegistryNotTrusted) || dec.Reason != "registry_mismatch" {
				t.Fatalf("foreign registry accepted: %+v %v", dec, err)
			}
		})
	}
	t.Run("canonical_trimming", func(t *testing.T) {
		opts, _ := mutationFixture(t)
		opts.ExpectedRegistry = " " + opts.ExpectedRegistry + "/ "
		opts.Root.RegistryURL += "/"
		if dec, err := EvaluateMutationFreshness(opts); err != nil || !dec.Allowed {
			t.Fatalf("existing identity convention rejected: %+v %v", dec, err)
		}
	})
}

func TestMutationFreshnessPolicyCannotOpen(t *testing.T) {
	for _, maximum := range []string{"", "0", "48h", "12h"} {
		t.Run(maximum, func(t *testing.T) {
			opts, key := mutationFixture(t)
			opts.Root.MaxStaleness = maximum
			opts.Root.FailPolicy = "open"
			opts.Root.FailPolicyByRisk = map[string]string{"low": "open"}
			limit := 24 * time.Hour
			if maximum == "12h" {
				limit = 12 * time.Hour
			}
			for _, age := range []time.Duration{limit, limit + time.Nanosecond} {
				opts.Revocations = mutationList(t, opts, key, opts.Clock.Now.Add(-age), nil)
				dec, err := EvaluateMutationFreshness(opts)
				if dec.MaxAge != limit || dec.Allowed != (age == limit) || (err == nil) != (age == limit) {
					t.Fatalf("profile bypass: %+v %v", dec, err)
				}
			}
			policy, err := opts.Root.Freshness()
			if err != nil {
				t.Fatal(err)
			}
			legacy, err := EvaluateFreshness(7, opts.Revocations.IssuedAt, policy, RiskLow, opts.Clock.Now)
			if err != nil || !legacy.Allowed {
				t.Fatalf("existing execution profile changed: %+v %v", legacy, err)
			}
		})
	}
}

func TestMutationFreshnessSignedInvalidTimesAndRevocation(t *testing.T) {
	for _, issued := range []string{"", "not-a-time", "SYNTHETIC_PRIVATE_TIMESTAMP", "0001-01-01T00:00:00Z"} {
		t.Run("time/"+issued, func(t *testing.T) {
			opts, key := mutationFixture(t)
			list, err := NewSignedRevocationList(opts.ExpectedRegistry, issued, 7, nil, key)
			if err != nil {
				t.Fatal(err)
			}
			opts.Revocations = list
			dec, err := EvaluateMutationFreshness(opts)
			if dec.Allowed || dec.Reason != "invalid_issued_at" || !errors.Is(err, ErrRevocationStale) || dec.EvidenceSource == "" {
				t.Fatalf("signed invalid time accepted: %+v %v", dec, err)
			}
			if issued != "" && strings.Contains(err.Error(), issued) {
				t.Fatalf("signed timestamp reflected: %v", err)
			}
		})
	}
	t.Run("revoked_case", func(t *testing.T) {
		opts, key := mutationFixture(t)
		opts.Revocations = mutationList(t, opts, key, opts.Clock.Now, []string{opts.SubjectDigest})
		opts.SubjectDigest = strings.ToUpper(opts.SubjectDigest)
		dec, err := EvaluateMutationFreshness(opts)
		if dec.Allowed || dec.Reason != "subject_revoked" || !errors.Is(err, ErrBlobMissing) || dec.EvidenceSource == "" {
			t.Fatalf("revoked subject accepted: %+v %v", dec, err)
		}
	})
}

func TestMutationFreshnessDiagnosticsDoNotReflectInputs(t *testing.T) {
	const hostile = "SYNTHETIC_PRIVATE_VALUE"
	for _, change := range []func(*MutationFreshnessOpts){
		func(o *MutationFreshnessOpts) { o.Action = hostile },
		func(o *MutationFreshnessOpts) { o.SubjectDigest = hostile },
		func(o *MutationFreshnessOpts) {
			o.ExpectedRegistry = "https://user:" + hostile + "@registry.invalid/skills"
		},
		func(o *MutationFreshnessOpts) { o.Revocations.SignatureB64 = hostile },
		func(o *MutationFreshnessOpts) { o.Revocations.RevokedDigests = []string{hostile} },
		func(o *MutationFreshnessOpts) { o.Root.MaxStaleness = hostile },
	} {
		opts, _ := mutationFixture(t)
		change(&opts)
		_, err := EvaluateMutationFreshness(opts)
		if err == nil || strings.Contains(err.Error(), hostile) {
			t.Fatalf("untrusted diagnostic reflected or succeeded: %v", err)
		}
	}
}

func TestMutationFreshnessSignedEpochFloor(t *testing.T) {
	for _, epoch := range []int{-1, 0, 4, 5, 7} {
		t.Run(time.Duration(epoch).String(), func(t *testing.T) {
			opts, key := mutationFixture(t)
			list, err := NewSignedRevocationList(opts.ExpectedRegistry, opts.Revocations.IssuedAt, epoch, nil, key)
			if err != nil {
				t.Fatal(err)
			}
			opts.Revocations = list
			dec, err := EvaluateMutationFreshness(opts)
			want := epoch >= opts.MinimumEpoch
			if dec.Allowed != want || (err == nil) != want {
				t.Fatalf("signed epoch %d: %+v %v", epoch, dec, err)
			}
			if !want && !errors.Is(err, ErrRegistryNotTrusted) {
				t.Fatalf("missing epoch rejection cause: %v", err)
			}
		})
	}
}

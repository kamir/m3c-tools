package seal

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// TestVerifyClockSkewDefaultApprovedAt: a signer whose clock runs a few
// minutes ahead of the verifier's must not fail (SPEC-0470 section 4.6). The
// policy here names no tolerance, so DefaultMaxClockSkew applies. The clock is
// injected; the boundary is checked just inside, exactly at and just outside.
func TestVerifyClockSkewDefaultApprovedAt(t *testing.T) {
	b := newBaseline(t, nil) // approved_at is approveTime
	cases := []struct {
		name  string
		now   time.Time
		wantK bool // want OK
	}{
		{"four-minutes-ahead", approveTime.Add(-4 * time.Minute), true},
		{"exactly-at-the-tolerance", approveTime.Add(-5 * time.Minute), true},
		{"one-nanosecond-past-the-tolerance", approveTime.Add(-5*time.Minute - time.Nanosecond), false},
		{"a-day-ahead", approveTime.AddDate(0, 0, -1), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := testPolicy(b.signer)
			p.Now = trustfreeze.FixedClock{T: tc.now}
			res := Verify(t.Context(), b.dir, p)
			if tc.wantK {
				requireOK(t, res)
				return
			}
			requireExactReasons(t, res, ReasonApprovedInFuture)
		})
	}
}

// TestVerifyExpirySkewDefaultIsZero: the expiry side has a tolerance of its
// own, max_expiry_skew, and its default is zero (R-T2, SPEC-0470 section 4.6).
// A signer clock that runs ahead is an accident; an expiry is a promise to the
// verifier, so an expired baseline is expired. The approval tolerance does not
// reach this check.
func TestVerifyExpirySkewDefaultIsZero(t *testing.T) {
	expires := approveTime.Add(24 * time.Hour)
	b := newBaseline(t, func(r *SealRequest) { r.Approval.ExpiresAt = expires })
	cases := []struct {
		name  string
		now   time.Time
		wantK bool
	}{
		{"one-nanosecond-before-expiry", expires.Add(-time.Nanosecond), true},
		{"exactly-at-expiry", expires, true},
		{"one-nanosecond-after-expiry", expires.Add(time.Nanosecond), false},
		{"one-minute-after-expiry", expires.Add(time.Minute), false},
		{"a-day-after-expiry", expires.AddDate(0, 0, 1), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := testPolicy(b.signer)
			p.Now = trustfreeze.FixedClock{T: tc.now}
			res := Verify(t.Context(), b.dir, p)
			if tc.wantK {
				requireOK(t, res)
				return
			}
			requireExactReasons(t, res, ReasonExpired)
		})
	}
	if DefaultMaxExpirySkew != 0 {
		t.Fatalf("the documented default expiry tolerance is 0s, the code says %s", DefaultMaxExpirySkew)
	}
}

// TestVerifyExpirySkewConfigured: an operator who wants the old symmetry asks
// for it. max_expiry_skew moves only the expiry boundary; max_clock_skew keeps
// the approval one, and the two do not borrow from each other.
func TestVerifyExpirySkewConfigured(t *testing.T) {
	const expirySkew = 30 * time.Second
	expires := approveTime.Add(24 * time.Hour)
	b := newBaseline(t, func(r *SealRequest) { r.Approval.ExpiresAt = expires })
	cases := []struct {
		name  string
		now   time.Time
		want  Reason
		empty bool
	}{
		{name: "expired-just-inside", now: expires.Add(expirySkew - time.Nanosecond), empty: true},
		{name: "expired-exactly-at", now: expires.Add(expirySkew), empty: true},
		{name: "expired-just-outside", now: expires.Add(expirySkew + time.Nanosecond), want: ReasonExpired},
		// The approval tolerance stays at five minutes and is unaffected.
		{name: "approved-inside-the-approval-tolerance", now: approveTime.Add(-4 * time.Minute), empty: true},
		{name: "approved-outside-the-approval-tolerance", now: approveTime.Add(-6 * time.Minute), want: ReasonApprovedInFuture},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := testPolicy(b.signer)
			p.Now = trustfreeze.FixedClock{T: tc.now}
			p.MaxExpirySkew = ClockSkew(expirySkew)
			res := Verify(t.Context(), b.dir, p)
			if tc.empty {
				requireOK(t, res)
				return
			}
			requireExactReasons(t, res, tc.want)
		})
	}
}

// TestParseTrustPolicyMaxExpirySkew: max_expiry_skew is a setting of the trust
// policy file like max_clock_skew, in JSON and YAML, and survives a round trip.
// A policy that names neither keeps both documented defaults.
func TestParseTrustPolicyMaxExpirySkew(t *testing.T) {
	for _, doc := range []string{
		"schema_version: trust-freeze/trust-policy/v1\nmax_expiry_skew: 90s\n",
		`{"schema_version":"trust-freeze/trust-policy/v1","max_expiry_skew":"90s","trusted_keys":[]}`,
	} {
		p, err := ParseTrustPolicy([]byte(doc))
		if err != nil {
			t.Fatalf("%s: %v", doc, err)
		}
		if got := p.EffectiveMaxExpirySkew(); got != 90*time.Second {
			t.Fatalf("%s: expiry tolerance %s, want 90s", doc, got)
		}
		if got := p.EffectiveMaxClockSkew(); got != DefaultMaxClockSkew {
			t.Fatalf("%s: approval tolerance %s, want the default %s", doc, got, DefaultMaxClockSkew)
		}
		out, err := MarshalTrustPolicy(p)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(out), `"max_expiry_skew": "1m30s"`) {
			t.Fatalf("MarshalTrustPolicy dropped the expiry tolerance:\n%s", out)
		}
		back, err := ParseTrustPolicy(out)
		if err != nil {
			t.Fatal(err)
		}
		if back.EffectiveMaxExpirySkew() != p.EffectiveMaxExpirySkew() {
			t.Fatalf("round trip changed the expiry tolerance: %s to %s", p.EffectiveMaxExpirySkew(), back.EffectiveMaxExpirySkew())
		}
	}
	p, err := ParseTrustPolicy([]byte("schema_version: trust-freeze/trust-policy/v1\ntrusted_keys: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.EffectiveMaxExpirySkew(); got != DefaultMaxExpirySkew {
		t.Fatalf("policy file without max_expiry_skew: %s, want %s", got, DefaultMaxExpirySkew)
	}
	for _, tc := range []struct {
		name string
		p    TrustPolicy
	}{{"zero value", TrustPolicy{}}, {"DefaultTrustPolicy", DefaultTrustPolicy()}, {"testPolicy", testPolicy()}} {
		if got := tc.p.EffectiveMaxExpirySkew(); got != DefaultMaxExpirySkew {
			t.Errorf("%s: expiry tolerance %s, want the default %s", tc.name, got, DefaultMaxExpirySkew)
		}
	}
}

// TestTrustPolicyMaxExpirySkewRefusesNegative: a negative expiry tolerance
// would expire a baseline before its stated instant.
func TestTrustPolicyMaxExpirySkewRefusesNegative(t *testing.T) {
	if err := (TrustPolicy{MaxExpirySkew: ClockSkew(-time.Second)}).Validate(); !errors.Is(err, ErrTrustPolicyInvalid) {
		t.Fatalf("negative expiry tolerance accepted: %v", err)
	}
	for _, doc := range []string{
		"schema_version: trust-freeze/trust-policy/v1\nmax_expiry_skew: -1s\n",
		"schema_version: trust-freeze/trust-policy/v1\nmax_expiry_skew: never\n",
	} {
		if _, err := ParseTrustPolicy([]byte(doc)); !errors.Is(err, ErrTrustPolicyInvalid) {
			t.Fatalf("%q accepted: %v", doc, err)
		}
	}
}

// TestVerifyClockSkewConfigured: a policy that names a tolerance uses it, at
// both ends and at the same three boundary positions.
func TestVerifyClockSkewConfigured(t *testing.T) {
	const skew = 30 * time.Second
	expires := approveTime.Add(24 * time.Hour)
	b := newBaseline(t, func(r *SealRequest) { r.Approval.ExpiresAt = expires })
	cases := []struct {
		name  string
		now   time.Time
		want  Reason
		empty bool
	}{
		{name: "approved-just-inside", now: approveTime.Add(-skew + time.Nanosecond), empty: true},
		{name: "approved-exactly-at", now: approveTime.Add(-skew), empty: true},
		{name: "approved-just-outside", now: approveTime.Add(-skew - time.Nanosecond), want: ReasonApprovedInFuture},
		// max_clock_skew does not reach the expiry check: that boundary is
		// max_expiry_skew, and its default is zero (R-T2).
		{name: "expired-exactly-at", now: expires, empty: true},
		{name: "expired-just-outside", now: expires.Add(time.Nanosecond), want: ReasonExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := testPolicy(b.signer)
			p.Now = trustfreeze.FixedClock{T: tc.now}
			p.MaxClockSkew = ClockSkew(skew)
			res := Verify(t.Context(), b.dir, p)
			if tc.empty {
				requireOK(t, res)
				return
			}
			requireExactReasons(t, res, tc.want)
		})
	}
}

// TestVerifyClockSkewZeroDisables: ClockSkew(0) is the documented way to
// switch the tolerance off; the comparison is then exact to the nanosecond.
func TestVerifyClockSkewZeroDisables(t *testing.T) {
	b := newBaseline(t, nil)
	p := testPolicy(b.signer)
	p.MaxClockSkew = ClockSkew(0)
	p.Now = trustfreeze.FixedClock{T: approveTime}
	requireOK(t, Verify(t.Context(), b.dir, p))
	p.Now = trustfreeze.FixedClock{T: approveTime.Add(-time.Nanosecond)}
	requireExactReasons(t, Verify(t.Context(), b.dir, p), ReasonApprovedInFuture)
}

// TestTrustPolicyMaxClockSkewDefaultApplies: a policy that names no tolerance
// applies DefaultMaxClockSkew, whether it was built in Go or read from a file.
// The Go zero value must not read as "disabled", which is why the field is a
// pointer.
func TestTrustPolicyMaxClockSkewDefaultApplies(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    TrustPolicy
	}{
		{"zero value", TrustPolicy{}},
		{"DefaultTrustPolicy", DefaultTrustPolicy()},
		{"testPolicy", testPolicy()},
	} {
		if got := tc.p.EffectiveMaxClockSkew(); got != DefaultMaxClockSkew {
			t.Errorf("%s: tolerance %s, want the default %s", tc.name, got, DefaultMaxClockSkew)
		}
	}
	p, err := ParseTrustPolicy([]byte("schema_version: trust-freeze/trust-policy/v1\ntrusted_keys: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.EffectiveMaxClockSkew(); got != DefaultMaxClockSkew {
		t.Fatalf("policy file without max_clock_skew: tolerance %s, want %s", got, DefaultMaxClockSkew)
	}
	if DefaultMaxClockSkew != 5*time.Minute {
		t.Fatalf("the documented default is 5m, the code says %s", DefaultMaxClockSkew)
	}
}

// TestParseTrustPolicyMaxClockSkew: the tolerance is configurable in the trust
// policy file (schema trust-freeze/trust-policy/v1), in JSON and in YAML, and
// survives a round trip through MarshalTrustPolicy.
func TestParseTrustPolicyMaxClockSkew(t *testing.T) {
	for _, doc := range []string{
		"schema_version: trust-freeze/trust-policy/v1\nmax_clock_skew: 30s\n",
		`{"schema_version":"trust-freeze/trust-policy/v1","max_clock_skew":"30s","trusted_keys":[]}`,
	} {
		p, err := ParseTrustPolicy([]byte(doc))
		if err != nil {
			t.Fatalf("%s: %v", doc, err)
		}
		if got := p.EffectiveMaxClockSkew(); got != 30*time.Second {
			t.Fatalf("%s: tolerance %s, want 30s", doc, got)
		}
		b, err := MarshalTrustPolicy(p)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), `"max_clock_skew": "30s"`) {
			t.Fatalf("MarshalTrustPolicy dropped the tolerance:\n%s", b)
		}
		back, err := ParseTrustPolicy(b)
		if err != nil {
			t.Fatal(err)
		}
		if back.EffectiveMaxClockSkew() != p.EffectiveMaxClockSkew() {
			t.Fatalf("round trip changed the tolerance: %s to %s", p.EffectiveMaxClockSkew(), back.EffectiveMaxClockSkew())
		}
	}
	// Zero is written and read back as the disabled tolerance.
	b, err := MarshalTrustPolicy(TrustPolicy{MaxClockSkew: ClockSkew(0)})
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseTrustPolicy(b)
	if err != nil {
		t.Fatal(err)
	}
	if back.EffectiveMaxClockSkew() != 0 {
		t.Fatalf("a disabled tolerance came back as %s:\n%s", back.EffectiveMaxClockSkew(), b)
	}
}

// TestTrustPolicyMaxClockSkewRefusesNegative: a negative tolerance would make
// a sound baseline fail before its own approval time, so it is refused.
func TestTrustPolicyMaxClockSkewRefusesNegative(t *testing.T) {
	if err := (TrustPolicy{MaxClockSkew: ClockSkew(-time.Second)}).Validate(); !errors.Is(err, ErrTrustPolicyInvalid) {
		t.Fatalf("negative tolerance accepted: %v", err)
	}
	for _, doc := range []string{
		"schema_version: trust-freeze/trust-policy/v1\nmax_clock_skew: -1s\n",
		"schema_version: trust-freeze/trust-policy/v1\nmax_clock_skew: tomorrow\n",
		"schema_version: trust-freeze/trust-policy/v1\nmax_clock_skew: 300\n",
	} {
		if _, err := ParseTrustPolicy([]byte(doc)); !errors.Is(err, ErrTrustPolicyInvalid) {
			t.Fatalf("%q accepted: %v", doc, err)
		}
	}
	// An invalid policy fails verification before anything else is read.
	b := newBaseline(t, nil)
	p := testPolicy(b.signer)
	p.MaxClockSkew = ClockSkew(-time.Second)
	requireExactReasons(t, Verify(t.Context(), b.dir, p), ReasonTrustPolicyInvalid)
}

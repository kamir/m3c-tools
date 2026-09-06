package artifactauth

import (
	"runtime"
	"strings"
	"testing"
)

// The service and env names live in one place. This pins the pairs the docs and
// the ops routine promise, so a rename has to change them here too.
func TestServiceForNames(t *testing.T) {
	for _, tc := range []struct {
		backend         string
		tier            Tier
		service, envVar string
	}{
		{"gitlab", TierWrite, "m3c-skillctl-gitlab", "M3C_GITLAB_TOKEN"},
		{"gitlab", TierRead, "m3c-skillctl-gitlab-ro", "M3C_GITLAB_RO_TOKEN"},
		{"registry", TierWrite, "m3c-skillctl-registry", "M3C_REGISTRY_TOKEN"},
		{"registry", TierRead, "m3c-skillctl-registry-ro", "M3C_REGISTRY_RO_TOKEN"},
	} {
		svc, env, ok := ServiceFor(tc.backend, tc.tier)
		if !ok {
			t.Fatalf("%s/%s: unknown backend", tc.backend, tc.tier)
		}
		if svc != tc.service || env != tc.envVar {
			t.Errorf("%s/%s = (%q, %q), want (%q, %q)", tc.backend, tc.tier, svc, env, tc.service, tc.envVar)
		}
	}
	if _, _, ok := ServiceFor("nonesuch", TierRead); ok {
		t.Error("an unknown backend must not resolve")
	}
}

// Store refuses instead of falling back to something weaker. A silent fallback
// would be the worst outcome: the operator believes the token is protected
// because the command said nothing.
func TestStoreRefusesBadInput(t *testing.T) {
	for _, tc := range []struct{ backend, host, secret, want string }{
		{"nonesuch", "h", "s", "unknown backend"},
		{"gitlab", "", "s", "a host is required"},
		{"gitlab", "h", "", "refusing to store an empty token"},
	} {
		err := Store(tc.backend, TierWrite, tc.host, tc.secret)
		if err == nil {
			t.Fatalf("%+v: expected a refusal", tc)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: err = %v, want it to mention %q", tc, err, tc.want)
		}
	}
}

// On a platform without a protected store, Store must say so and name the
// environment variable, rather than writing the token somewhere unprotected.
func TestStoreOnPlatformWithoutAStore(t *testing.T) {
	if HasProtectedStore() {
		t.Skipf("%s has a protected store; this case is for the others", runtime.GOOS)
	}
	err := Store("gitlab", TierWrite, "h", "s")
	if err == nil || !strings.Contains(err.Error(), "M3C_GITLAB_TOKEN") {
		t.Errorf("the refusal must name the env var, got %v", err)
	}
}

// Provisioned reports the SOURCE and never the secret, and the env override wins,
// exactly as the resolver orders it. An operator whose stored token seems ignored
// needs to see that a stale export is the reason.
func TestProvisionedReportsEnvFirstAndNeverTheSecret(t *testing.T) {
	t.Setenv("M3C_REGISTRY_TOKEN", "top-secret")
	got := Provisioned("registry", TierWrite, "reg.example")
	if got != "env M3C_REGISTRY_TOKEN" {
		t.Errorf("Provisioned = %q, want the env source", got)
	}
	if strings.Contains(got, "top-secret") {
		t.Error("the secret leaked into the source description")
	}

	t.Setenv("M3C_REGISTRY_TOKEN", "")
	if got := Provisioned("registry", TierWrite, "no-such-host.invalid"); got != "" {
		t.Errorf("nothing provisioned must be empty, got %q", got)
	}
}

func TestBackendsIsSorted(t *testing.T) {
	b := Backends()
	if len(b) < 3 {
		t.Fatalf("expected at least gitlab, github, registry; got %v", b)
	}
	for i := 1; i < len(b); i++ {
		if b[i-1] > b[i] {
			t.Fatalf("Backends() is not sorted: %v", b)
		}
	}
}

// A host that could be read as an option is refused, and that is the case worth
// pinning: `security` would have taken a leading dash as a flag and acted on the
// wrong item, without saying so.
func TestValidHostRejectsWhatWouldBeMisread(t *testing.T) {
	for _, tc := range []struct{ host, want string }{
		{"", "a host is required"},
		{"-S", "leading dash"},
		{"host with space", "whitespace or a control character"},
		{"host\ttab", "whitespace or a control character"},
		{"host\x00null", "whitespace or a control character"},
	} {
		if err := validHost(tc.host); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("validHost(%q) = %v, want it to mention %q", tc.host, err, tc.want)
		}
	}
	for _, ok := range []string{"git.kieback-peter.de", "192.168.0.135:8929", "localhost"} {
		if err := validHost(ok); err != nil {
			t.Errorf("validHost(%q) = %v, want nil", ok, err)
		}
	}
}

// Delete validates the same way Store does. A delete that acts on the wrong item
// is quieter than a write that does, and therefore worse.
func TestDeleteValidatesToo(t *testing.T) {
	if err := Delete("nonesuch", TierWrite, "h"); err == nil || !strings.Contains(err.Error(), "unknown backend") {
		t.Errorf("unknown backend: %v", err)
	}
	if err := Delete("gitlab", TierWrite, "-S"); err == nil || !strings.Contains(err.Error(), "leading dash") {
		t.Errorf("a host that reads as an option must be refused: %v", err)
	}
}

// The store has a name a human can read, whatever the platform.
func TestProtectedStoreNameIsNotEmpty(t *testing.T) {
	if ProtectedStoreName() == "" {
		t.Error("the store needs a name for the message that tells an operator where the token went")
	}
}

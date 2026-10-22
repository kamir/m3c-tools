package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

func TestVerifyBundleRegistryBindingSharedKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("M3C_TOKEN_STORE", "file")
	t.Setenv("M3C_TEST_KEYCHAIN", "0")
	t.Setenv("M3C_ER1_KEYCHAIN", "off")
	fixture := buildBundleFixture(t)
	for _, tc := range []struct {
		name            string
		foreign, revoke bool
		want            int
	}{
		{"own-revoked", false, true, exitBundleRevoked},
		{"foreign-same-key", true, false, verify.ExitRegistryNotTrusted},
		{"own-not-revoked", false, false, exitOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registryURL := fixture.regURL
			if tc.foreign {
				registryURL += "/foreign-registry"
			}
			var revoked []string
			if tc.revoke {
				revoked = []string{fixture.digest}
			}
			list, err := verify.NewSignedRevocationList(registryURL, time.Now().UTC().Format(time.RFC3339), 7, revoked, fixture.regPriv)
			if err != nil {
				t.Fatal(err)
			}
			path := writeRevocations(t, fixture.dir, list)
			var out, diagnostic bytes.Buffer
			code := runVerify([]string{"--bundle", fixture.skbPath, "--trust-roots", fixture.trPath, "--revocations", path}, &out, &diagnostic)
			if code != tc.want {
				t.Fatalf("registry binding exit=%d want=%d: %s", code, tc.want, diagnostic.String())
			}
		})
	}
}

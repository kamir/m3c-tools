package report

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// SPEC-0469 section 4.7: report projects approval.json as it is and decides
// nothing about it, but it never projects bytes it cannot read as one approval
// object of the right schema with integer numbers only. Each case is a
// baseline whose manifest covers the malformed file, so integrity holds and
// only the projection can refuse it.
func TestBaselineReportRefusesMalformedApproval(t *testing.T) {
	cases := map[string]string{
		"trailing data":    `{"schema_version":"trust-freeze/approval/v1"} {}`,
		"not an object":    `null`,
		"an array":         `[1, 2]`,
		"wrong schema":     `{"schema_version":"trust-freeze/approval/v0"}`,
		"float number":     `{"schema_version":"trust-freeze/approval/v1","n":1.5}`,
		"nested float":     `{"schema_version":"trust-freeze/approval/v1","l":[{"n":2e3}]}`,
		"not JSON at all":  `approved`,
		"missing a schema": `{"reviewer":"id:charlie@example"}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			b := writeCapture(t, t.TempDir(), "baseline", trustfreeze.KindBaseline, testTime, "24.04", 0)
			if err := os.WriteFile(filepath.Join(b.Dir, trustfreeze.ApprovalFile), []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			created, err := trustfreeze.ParseTime(b.Manifest.CreatedAt)
			if err != nil {
				t.Fatal(err)
			}
			m, err := trustfreeze.BuildManifest(b.Dir, trustfreeze.ManifestHeader{Kind: b.Manifest.Kind, BundleID: b.Manifest.BundleID, CreatedAt: created, Subject: b.Manifest.Subject})
			if err != nil {
				t.Fatal(err)
			}
			mb, err := trustfreeze.MarshalFile(m)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(b.Dir, trustfreeze.ManifestFile), mb, 0o600); err != nil {
				t.Fatal(err)
			}
			rb, err := trustfreeze.ReadBundle(b.Dir)
			if err != nil {
				t.Fatalf("fixture error: the rebuilt baseline must pass integrity: %v", err)
			}
			if _, err := FromBundle(rb); !errors.Is(err, ErrUnsupportedInput) {
				t.Fatalf("FromBundle = %v, want ErrUnsupportedInput", err)
			}
		})
	}
}

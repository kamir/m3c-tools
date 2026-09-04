package registry_test

import (
	"os"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/er1"
	"github.com/kamir/m3c-tools/pkg/skillctl/artifact/conformance"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

// TestER1BackendConformance runs the SAME SPEC-0356 backend conformance suite
// (pkg/skillctl/artifact/conformance) against a LIVE ER1 self-tenant context:
// proving ER1 and GitLab honor the same artifact.Backend contract, tested by
// identical code. Gated on M3C_TEST_ER1_URL + M3C_TEST_ER1_KEY + M3C_TEST_ER1_CTX;
// the suite PUBLISHES + REVOKES, so point it at a THROWAWAY context, never the
// real self-registry. External test package to avoid the registry↔conformance
// import cycle.
func TestER1BackendConformance(t *testing.T) {
	url := os.Getenv("M3C_TEST_ER1_URL")
	key := os.Getenv("M3C_TEST_ER1_KEY")
	ctxID := os.Getenv("M3C_TEST_ER1_CTX")
	if url == "" || key == "" || ctxID == "" {
		t.Skip("set M3C_TEST_ER1_URL + M3C_TEST_ER1_KEY + M3C_TEST_ER1_CTX (a THROWAWAY context) to run")
	}
	cfg := er1.LoadConfig()
	cfg.APIURL = url
	cfg.APIKey = key
	cfg.VerifySSL = !strings.HasPrefix(url, "http://") && os.Getenv("M3C_TEST_ER1_INSECURE") != "1"
	conformance.Run(t, registry.NewER1Backend(cfg, ctxID))
}

package httpsafe

import (
	"net/http"
	"testing"
)

// TestNoCrossHostRedirectMax_CapsChain verifies the caller-chosen cap used by
// the skillctl registry client (AUDIT-0001 Befund 1.3): 5 hops refuse, 4 pass.
func TestNoCrossHostRedirectMax_CapsChain(t *testing.T) {
	check := NoCrossHostRedirectMax(5)
	req, err := http.NewRequest(http.MethodGet, "https://h.example/a", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	via := make([]*http.Request, 5)
	for i := range via {
		via[i] = req
	}
	if err := check(req, via); err == nil {
		t.Error("expected the cap of 5 to refuse the 6th hop")
	}
	if err := check(req, via[:4]); err != nil {
		t.Errorf("4 prior hops should pass a cap of 5, got %v", err)
	}
}

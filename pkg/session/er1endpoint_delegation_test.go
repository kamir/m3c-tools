package session

import "testing"

// BUG-0444: ER1Endpoint delegiert jetzt an er1.ResolveTarget. Geprueft wird
// hier die Delegation, nicht die Regel selbst.
func TestER1Endpoint_DelegiertUndUmgehungenSindZu(t *testing.T) {
	t.Setenv("ER1_API_URL", "")
	faelle := []struct {
		target     string
		wantVerify bool
	}{
		{"https://localhost.angreifer.example/", true},
		{"https://127.0.0.1.angreifer.example/", true},
		{"https://angreifer.example/?h=127.0.0.1", true},
		{"https://angreifer.example/localhost", true},
		{"https://[::1]:8081", false},
		{"local", false},
		{"prod", true},
	}
	for _, f := range faelle {
		_, verify := ER1Endpoint(f.target)
		if verify != f.wantVerify {
			t.Errorf("ER1Endpoint(%q) verifySSL = %v, erwartet %v", f.target, verify, f.wantVerify)
		}
	}
}

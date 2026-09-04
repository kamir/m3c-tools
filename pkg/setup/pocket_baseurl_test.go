package setup

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestValidatePocketKey_RefusesForeignHost is the go/request-forgery guard:
// baseURL arrives from a JSON body on the loopback config-editor API, and the
// request built from it carries the user's Pocket key in an Authorization
// header. A host outside the allow-list must never see that header.
func TestValidatePocketKey_RefusesForeignHost(t *testing.T) {
	var reached bool
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer attacker.Close()

	// The attacker server is on loopback (httptest gives us nothing else), so
	// point at a name that resolves nowhere but is clearly not Pocket. The
	// verdict must come from the allow-list, before any dial happens.
	for _, base := range []string{
		"https://evil.example.com",
		"https://public.heypocketai.com.evil.example.com",
		"https://heypocketai.com.evil.example.com/api/v1",
		"http://169.254.169.254/latest/meta-data", // cloud metadata service
		"file:///etc/passwd",
		"gopher://evil.example.com",
		"://not a url",
	} {
		v := ValidatePocketKey(attacker.Client(), base, "pk_secret")
		if v.State != "unreachable" {
			t.Errorf("base %q: state = %q, want %q", base, v.State, "unreachable")
		}
		if !strings.Contains(v.HumanMessage, "Refusing") && !strings.Contains(v.HumanMessage, "not a valid URL") &&
			!strings.Contains(v.HumanMessage, "must be an http(s) URL") {
			t.Errorf("base %q: message %q does not explain the refusal", base, v.HumanMessage)
		}
	}
	if reached {
		t.Error("a request was actually sent; the allow-list must refuse before dialling")
	}
}

// TestValidatePocketKey_RefusesPlainHTTPToPublicHost: even an allow-listed host
// must not receive the key over cleartext.
func TestValidatePocketKey_RefusesPlainHTTPToPublicHost(t *testing.T) {
	v := ValidatePocketKey(nil, "http://public.heypocketai.com/api/v1", "pk_secret")
	if v.State != "unreachable" || !strings.Contains(v.HumanMessage, "plain http") {
		t.Errorf("plain http to the public host must be refused; got state=%q msg=%q", v.State, v.HumanMessage)
	}
}

// TestValidatePocketKey_AllowsLoopback keeps the local mock server and the rest
// of this package's tests working: a request to your own machine cannot
// exfiltrate the credential.
func TestValidatePocketKey_AllowsLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"pagination":{"total":3}}`))
	}))
	defer srv.Close()

	v := ValidatePocketKey(srv.Client(), srv.URL, "pk_x")
	if v.State != "valid" || v.RecordingCount != 3 {
		t.Fatalf("loopback must stay allowed; got state=%q count=%d", v.State, v.RecordingCount)
	}
}

// TestAllowedPocketHost covers the host matcher directly, including the
// suffix trap ("evil.com/?x=heypocketai.com" style names).
func TestAllowedPocketHost(t *testing.T) {
	ok := []string{
		"public.heypocketai.com", "public.heypocketai.com:443",
		"app.heypocket.com", "heypocketai.com",
		"api.heypocketai.com", "127.0.0.1:9999", "localhost:1", "[::1]:8080",
	}
	for _, h := range ok {
		if !allowedPocketHost(h) {
			t.Errorf("allowedPocketHost(%q) = false, want true", h)
		}
	}
	bad := []string{
		"evil.com", "heypocketai.com.evil.com", "notheypocketai.com.attacker.net",
		"169.254.169.254", "10.0.0.1", "example.org:443", "",
	}
	for _, h := range bad {
		if allowedPocketHost(h) {
			t.Errorf("allowedPocketHost(%q) = true, want false", h)
		}
	}
}

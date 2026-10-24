package importer

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kamir/m3c-tools/pkg/httpsafe"
	"github.com/kamir/m3c-tools/pkg/skillctl/model"
)

func testCredential(origin, secret string) httpsafe.DeferredSecret {
	return httpsafe.DeferredSecret{Binding: httpsafe.CredentialBinding{Version: 1, Kind: httpsafe.CredentialAPIKey, Origin: origin, Source: "test-operator-assignment"}, Read: func() ([]byte, error) { return []byte(secret), nil }}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func TestNewClientRejectsBeforeSecretRead(t *testing.T) {
	for _, tc := range []struct {
		target, pin string
		allow       bool
	}{
		{"https://b.example", "https://a.example", false},
		{"https://a.example", "", false},
		{"https://a.example:444", "https://a.example", false},
		{"http://remote.example", "http://remote.example", true},
		{"http://127.0.0.1", "http://127.0.0.1", false},
		{"https://user:synthetic@a.example", "https://a.example", false},
	} {
		reads := 0
		selected := testCredential(tc.pin, "synthetic-key")
		selected.Read = func() ([]byte, error) { reads++; return nil, errors.New("must not read") }
		client, err := NewClient(tc.target, tc.allow, selected, "")
		if err == nil || client != nil || reads != 0 {
			t.Fatalf("invalid connection accepted: reads=%d error=%v", reads, err)
		}
	}
}

func TestClientSnapshotsCredentialAndTarget(t *testing.T) {
	for _, kind := range []httpsafe.CredentialKind{httpsafe.CredentialAPIKey, httpsafe.CredentialDeviceBearer} {
		t.Run(string(kind), func(t *testing.T) {
			reads := 0
			secret := []byte("synthetic-key")
			selected := testCredential("https://a.example", "unused")
			selected.Binding.Kind = kind
			selected.Read = func() ([]byte, error) { reads++; return secret, nil }
			client, err := NewClient("https://A.example/prefix/", false, selected, "synthetic-user")
			if err != nil {
				t.Fatal(err)
			}
			// Neither mutation of the original bytes/metadata nor ambient credentials
			// can change the snapshot used for health and import.
			copy(secret, []byte("different-key"))
			selected.Binding.Origin = "https://b.example"
			t.Setenv("ER1_DEVICE_TOKEN", "foreign-bearer")
			t.Setenv("M3C_API_KEY", "foreign-key")
			calls := 0
			client.HTTPClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.URL.Host != "a.example:443" || !strings.HasPrefix(req.URL.Path, "/prefix/") {
					t.Error("target/prefix changed")
				}
				if kind == httpsafe.CredentialAPIKey {
					if req.Header.Get("X-API-KEY") != "synthetic-key" || req.Header.Get("Authorization") != "" {
						t.Error("API key reselected from ambient source")
					}
				} else if req.Header.Get("Authorization") != "Bearer synthetic-key" || req.Header.Get("X-API-KEY") != "" {
					t.Error("Bearer snapshot changed")
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"imported":1,"message":"safe"}`))}, nil
			})
			if err = client.HealthCheck(); err != nil {
				t.Fatal(err)
			}
			if _, err = client.Import(&model.Inventory{}); err != nil {
				t.Fatal(err)
			}
			if reads != 1 || calls != 2 {
				t.Fatalf("reads=%d calls=%d", reads, calls)
			}
		})
	}
}

func TestClientErrorsDoNotReflectCredential(t *testing.T) {
	for _, phase := range []string{"health_status", "import_status", "transport", "success_message", "escaped_success_message", "invalid_json"} {
		t.Run(phase, func(t *testing.T) {
			client, err := NewClient("https://a.example", false, testCredential("https://a.example", "synthetic-key"), "")
			if err != nil {
				t.Fatal(err)
			}
			client.HTTPClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if phase == "transport" {
					return nil, errors.New("reflected synthetic-key")
				}
				status := 200
				body := `{"message":"safe"}`
				switch phase {
				case "health_status", "import_status":
					status = 401
					body = "synthetic-key raw failure body"
				case "success_message":
					body = `{"message":"prefix synthetic-key suffix"}`
				case "escaped_success_message":
					body = `{"message":"prefix synthetic\u002dkey suffix"}`
				case "invalid_json":
					body = "synthetic-key"
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			if phase == "health_status" {
				err = client.HealthCheck()
			} else {
				_, err = client.Import(&model.Inventory{})
			}
			if err == nil || strings.Contains(err.Error(), "synthetic-key") || strings.Contains(err.Error(), "raw failure body") {
				t.Fatalf("unsafe or missing diagnostic: %v", err)
			}
		})
	}
}

func TestClientCanonicalizesCredentialBeforeSending(t *testing.T) {
	for _, kind := range []httpsafe.CredentialKind{httpsafe.CredentialAPIKey, httpsafe.CredentialDeviceBearer} {
		t.Run(string(kind), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				if kind == httpsafe.CredentialAPIKey {
					if req.Header.Get("X-API-KEY") != "synthetic-key" || req.Header.Get("Authorization") != "" {
						t.Error("incorrect canonical API-key header")
					}
				} else if req.Header.Get("Authorization") != "Bearer synthetic-key" || req.Header.Get("X-API-KEY") != "" {
					t.Error("incorrect canonical Bearer header")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"message":"reflected synthetic-key"}`)
			}))
			defer server.Close()
			selected := testCredential(server.URL, " \tsynthetic-key \t")
			selected.Binding.Kind = kind
			client, err := NewClient(server.URL, true, selected, "")
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.Import(&model.Inventory{})
			if err == nil || result != nil || strings.Contains(err.Error(), "synthetic-key") || calls.Load() != 1 {
				t.Fatalf("credential reflection not safely blocked: result=%v error=%v calls=%d", result, err, calls.Load())
			}
		})
	}
}

func TestDryRunNeedsNoCredential(t *testing.T) {
	base, err := httpsafe.ParseAPIBase("https://a.example/prefix", false)
	if err != nil {
		t.Fatal(err)
	}
	out := DryRun(base, &model.Inventory{})
	if !strings.Contains(out, "https://a.example:443/prefix/api/v2/skills/profile/import") || !strings.Contains(out, "No data was sent") {
		t.Fatal(out)
	}
}

package auth

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type readOnlyProbeStore struct {
	token *DeviceToken
	err   error
	calls int
}

func (s *readOnlyProbeStore) Name() string { panic("unexpected Name") }
func (s *readOnlyProbeStore) Load(deviceID, userID string) (*DeviceToken, error) {
	s.calls++
	if deviceID != "synthetic-device" || userID != "synthetic-user" {
		panic("wrong identity hint")
	}
	return s.token, s.err
}
func (s *readOnlyProbeStore) Save(*DeviceToken) error { panic("read-only Save") }
func (s *readOnlyProbeStore) Clear() error            { panic("read-only Clear") }
func (s *readOnlyProbeStore) Has() bool               { panic("read-only Has") }

func TestPersistedBearerReadOnlyNoMigration(t *testing.T) {
	hard := errors.New("synthetic unavailable cause")
	for _, tc := range []struct {
		name                    string
		primary, fallback       *DeviceToken
		primaryErr, fallbackErr error
		want                    string
		wantFallback            bool
		wantErr                 error
		deny                    bool
	}{
		{name: "primary", primary: &DeviceToken{Token: "synthetic-primary"}, want: "synthetic-primary"},
		{name: "empty primary uses file without migration", fallback: &DeviceToken{Token: "synthetic-file"}, want: "synthetic-file", wantFallback: true},
		{name: "unavailable primary uses file", primaryErr: ErrUnavailable, fallback: &DeviceToken{Token: "synthetic-file"}, want: "synthetic-file", wantFallback: true},
		{name: "hard primary no fallback", primaryErr: hard, fallback: &DeviceToken{Token: "synthetic-file"}, deny: true, wantErr: hard},
		{name: "file error preserved", fallbackErr: hard, wantFallback: true, deny: true, wantErr: hard},
		{name: "missing", wantFallback: true, deny: true},
		{name: "expired primary no fallback", primary: &DeviceToken{Token: "synthetic-expired", ExpiresAt: "2000-01-01T00:00:00Z"}, fallback: &DeviceToken{Token: "synthetic-file"}, deny: true},
		{name: "invalid expiry", primary: &DeviceToken{Token: "synthetic-expired", ExpiresAt: "not-a-time"}, deny: true},
		{name: "empty selected", primary: &DeviceToken{}, deny: true},
		{name: "blank selected", primary: &DeviceToken{Token: " \t"}, deny: true},
		{name: "header injection selected", primary: &DeviceToken{Token: "synthetic\r\nheader"}, deny: true},
		{name: "trim once", primary: &DeviceToken{Token: " \tsynthetic-key \t"}, want: "synthetic-key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &readOnlyProbeStore{token: tc.primary, err: tc.primaryErr}
			f := &readOnlyProbeStore{token: tc.fallback, err: tc.fallbackErr}
			got, err := persistedBearerReadOnly(p, f, "synthetic-device", "synthetic-user")
			if (err != nil) != tc.deny || got != tc.want {
				t.Fatalf("value/denial mismatch (error=%v)", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatal("lost error identity")
			}
			if p.calls != 1 || (f.calls == 1) != tc.wantFallback {
				t.Fatalf("load counts primary=%d fallback=%d", p.calls, f.calls)
			}
		})
	}
}

func TestReadOnlyMissingFileDoesNotCreateDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	value, err := (fileStore{}).Load("synthetic-device", "synthetic-user")
	if err != nil || value != nil {
		t.Fatal("missing file did not remain absent")
	}
	if _, err := os.Stat(filepath.Join(home, ".m3c-tools")); !os.IsNotExist(err) {
		t.Fatal("read-only missing file created directory")
	}
}

package auth

import (
	"errors"
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
	for _, tc := range []struct {
		name  string
		token *DeviceToken
		err   error
		want  string
		deny  bool
	}{
		{name: "native", token: &DeviceToken{Token: "synthetic-native"}, want: "synthetic-native"},
		{name: "unavailable", err: ErrUnavailable, deny: true},
		{name: "unsupported", err: ErrStorePolicy, deny: true},
		{name: "missing", deny: true},
		{name: "expired", token: &DeviceToken{Token: "synthetic", ExpiresAt: "2000-01-01T00:00:00Z"}, deny: true},
		{name: "invalid expiry", token: &DeviceToken{Token: "synthetic", ExpiresAt: "invalid"}, deny: true},
		{name: "empty", token: &DeviceToken{}, deny: true},
		{name: "blank", token: &DeviceToken{Token: " \t"}, deny: true},
		{name: "header injection", token: &DeviceToken{Token: "synthetic\r\nheader"}, deny: true},
		{name: "null injection", token: &DeviceToken{Token: "synthetic\x00tail"}, deny: true},
		{name: "trim once", token: &DeviceToken{Token: " \tsynthetic \t"}, want: "synthetic"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := &readOnlyProbeStore{token: tc.token, err: tc.err}
			got, err := persistedBearerReadOnly(probe, "synthetic-device", "synthetic-user")
			if (err != nil) != tc.deny || got != tc.want || probe.calls != 1 {
				t.Fatal("read-only native result mismatch")
			}
			if tc.err != nil && !errors.Is(err, tc.err) {
				t.Fatal("classified error identity lost")
			}
		})
	}
}

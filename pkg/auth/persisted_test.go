package auth

import (
	"testing"
	"time"
)

func TestPersistedBearerNative(t *testing.T) {
	for _, tc := range []struct {
		name, expiry string
		empty        bool
		want         string
		expired      bool
	}{
		{name: "valid", want: "synthetic-native-bearer"},
		{name: "expired", expiry: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), expired: true},
		{name: "invalid-expiry", expiry: "not-a-date", expired: true},
		{name: "empty", empty: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolate(t)
			path, data := legacyCanary(t)
			if !tc.empty {
				if err := Save(&DeviceToken{Token: "synthetic-native-bearer", ExpiresAt: tc.expiry}); err != nil {
					t.Fatal(err)
				}
			}
			got, expired := PersistedBearer("compatibility-hint")
			if got != tc.want || expired != tc.expired {
				t.Fatal("persisted native bearer classification mismatch")
			}
			assertCanary(t, path, data)
		})
	}
}

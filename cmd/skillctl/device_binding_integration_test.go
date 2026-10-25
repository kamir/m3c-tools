package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/auth"
	keyring "github.com/zalando/go-keyring"
)

func TestSyncNativeRecordBindingAtEntryPoint(t *testing.T) {
	for _, name := range []string{"matching", "legacy", "foreign"} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			keyring.MockInit()
			t.Setenv("M3C_TOKEN_STORE", "keychain")
			t.Setenv("ER1_DEVICE_TOKEN", "")
			t.Setenv("ER1_DEVICE_TOKEN_ORIGIN", "https://a.example")
			t.Setenv("M3C_INGEST_ENDPOINT", "")
			t.Setenv("SKILLCTL_AUDIT_BACKEND", "")
			binding, err := auth.NewLoginBinding("https://a.example")
			if err != nil {
				t.Fatal(err)
			}
			if name == "foreign" {
				binding.Origin = "https://b.example:443"
			}
			if name == "legacy" {
				binding = nil
			}
			record := &auth.DeviceToken{Token: "synthetic-native-secret", Binding: binding}
			if err := auth.Save(record); err != nil {
				t.Fatal(err)
			}
			before, err := keyring.Get("m3c-tools", "device-token")
			if err != nil {
				t.Fatal(err)
			}
			var out, errb bytes.Buffer
			code := runSync([]string{"--once", "--backend", "er1", "--endpoint", "https://a.example"}, &out, &errb)
			if (code == 0) != (name == "matching") {
				t.Fatalf("exit=%d stderr=%q", code, errb.String())
			}
			if strings.Contains(out.String()+errb.String(), record.Token) {
				t.Fatal("secret in diagnostics")
			}
			after, err := keyring.Get("m3c-tools", "device-token")
			if err != nil || after != before {
				t.Fatal("selected record changed")
			}
			if name != "matching" {
				entries, err := os.ReadDir(home)
				if err != nil || len(entries) != 0 {
					t.Fatal("denied credential opened local state")
				}
			}
		})
	}
}

func TestOwnerContextDoesNotBorrowStoredIdentity(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	keyring.MockInit()
	t.Setenv("M3C_TOKEN_STORE", "keychain")
	t.Setenv("ER1_USER_ID", "")
	t.Setenv("ER1_CONTEXT_ID", "")
	raw, err := json.Marshal(&auth.DeviceToken{UserID: "foreign-owner", Token: "synthetic-foreign"})
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.Set("m3c-tools", "device-token", string(raw)); err != nil {
		t.Fatal(err)
	}
	if got := ownerPrefixedContext("skills"); got != "skills" {
		t.Fatalf("borrowed foreign owner: %q", got)
	}
}

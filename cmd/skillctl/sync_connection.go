package main

import (
	"errors"
	"os"
	"strings"

	"github.com/kamir/m3c-tools/pkg/auth"
	"github.com/kamir/m3c-tools/pkg/httpsafe"
)

// syncBearerSource defers both environment and stored-token reads until the
// independent origin binding passes. This is operator intent, not issuer proof.
func syncBearerSource(getenv func(string) string, readStored httpsafe.SecretReader) httpsafe.DeferredSecret {
	return httpsafe.DeferredSecret{
		Binding: httpsafe.CredentialBinding{Version: httpsafe.CredentialBindingVersion,
			Kind: httpsafe.CredentialDeviceBearer, Origin: getenv("ER1_DEVICE_TOKEN_ORIGIN"), Source: "sync-operator-assignment"},
		Read: func() ([]byte, error) {
			selected := getenv("ER1_DEVICE_TOKEN")
			if selected == "" {
				if readStored == nil {
					return nil, errors.New("sync stored bearer reader unavailable")
				}
				value, err := readStored()
				if err != nil {
					return nil, err
				}
				selected = string(value)
			}
			selected = strings.TrimSpace(selected)
			if selected == "" || strings.ContainsAny(selected, "\r\n\x00") {
				return nil, errors.New("invalid sync bearer format")
			}
			return []byte(selected), nil
		},
	}
}

func readSyncStoredBearer(origin string) ([]byte, error) {
	userID := strings.TrimSpace(os.Getenv("ER1_USER_ID"))
	if userID == "" {
		userID = strings.SplitN(os.Getenv("ER1_CONTEXT_ID"), "___", 2)[0]
	}
	token, err := auth.BoundBearerReadOnly(origin, userID)
	return []byte(token), err
}

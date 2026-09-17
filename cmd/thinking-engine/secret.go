package main

import (
	"fmt"
	"os"
)

func hmacSecretFromEnv(envName string, allowDevFallback bool, ctxHashHex string) ([]byte, error) {
	secret := []byte(os.Getenv(envName))
	if len(secret) > 0 {
		return secret, nil
	}
	if allowDevFallback {
		return []byte("dev-" + ctxHashHex), nil
	}
	return nil, fmt.Errorf("%s is required (pass --dev for a local fallback)", envName)
}

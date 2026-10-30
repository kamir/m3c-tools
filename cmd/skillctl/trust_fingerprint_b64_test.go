package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
)

func TestTrustFingerprintPrintsPinAndRawKey(t *testing.T) {
	base := filepath.Join(t.TempDir(), "k")
	var keyOut, keyErr bytes.Buffer
	if code := runKeygen([]string{"--out", base}, &keyOut, &keyErr); code != exitOK {
		t.Fatalf("keygen exit %d: %s", code, keyErr.String())
	}
	pub, err := signing.LoadPublicKey(base + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := runTrustFingerprint([]string{base + ".pub"}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	sum := sha256.Sum256(pub)
	if got, want := strings.TrimSpace(out.String()), "sha256:"+hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("pin = %q, want %q", got, want)
	}
	out.Reset()
	if code := runTrustFingerprint([]string{"--b64", base + ".pub"}, &out, &errb); code != exitOK {
		t.Fatalf("--b64 exit %d: %s", code, errb.String())
	}
	if got, want := strings.TrimSpace(out.String()), base64.StdEncoding.EncodeToString(pub); got != want {
		t.Fatalf("--b64 = %q, want %q", got, want)
	}
}

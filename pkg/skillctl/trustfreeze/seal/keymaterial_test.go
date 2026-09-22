package seal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// secretNeedles returns every textual and binary form in which the private
// key of seed could leak.
func secretNeedles(t *testing.T, seed []byte) (text []string, binary [][]byte) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(seed)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	derB64 := base64.StdEncoding.EncodeToString(der)
	text = []string{
		"PRIVATE KEY",
		hex.EncodeToString(seed), strings.ToUpper(hex.EncodeToString(seed)),
		base64.StdEncoding.EncodeToString(seed), base64.RawStdEncoding.EncodeToString(seed),
		base64.URLEncoding.EncodeToString(seed), base64.RawURLEncoding.EncodeToString(seed),
		hex.EncodeToString(priv), base64.StdEncoding.EncodeToString(priv), base64.RawURLEncoding.EncodeToString(priv),
		derB64,
		// A PEM body is wrapped at 64 columns; the first line alone must not
		// appear either.
		derB64[:min(len(derB64), 64)],
	}
	return text, [][]byte{seed, priv}
}

func scanForSecrets(t *testing.T, where string, b []byte, text []string, binary [][]byte) {
	t.Helper()
	for _, n := range text {
		if bytes.Contains(b, []byte(n)) {
			t.Fatalf("%s contains private key material (%d-byte needle)", where, len(n))
		}
	}
	for _, n := range binary {
		if bytes.Contains(b, n) {
			t.Fatalf("%s contains raw private key bytes", where)
		}
	}
}

// TF05-R8: after seal and verify, no produced file, no JSON output, no
// error string and no formatted signer contains a PEM private-key block or
// the private key in raw, hex or base64 form. Only the key file itself (the
// input, outside the bundle directories) holds it.
func TestNoKeyMaterialInOutputs(t *testing.T) {
	root := t.TempDir()
	keyDir := filepath.Join(root, "keys")
	work := filepath.Join(root, "work")
	privPath, pubPath := writeKeyFiles(t, keyDir, "reviewer", seedTrusted)
	text, binary := secretNeedles(t, seedTrusted)

	// Sanity: the needles do find the key in the key file.
	keyFile, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(keyFile, []byte("PRIVATE KEY")) {
		t.Fatal("setup: the key file does not look like a PEM private key")
	}

	signer, err := NewFileSigner(privPath)
	if err != nil {
		t.Fatal(err)
	}
	capDir, _ := newCapture(t, work, "capture", defaultFixture())
	out := filepath.Join(work, "baseline")
	sres, err := Seal(t.Context(), defaultRequest(capDir, out, signer))
	if err != nil {
		t.Fatal(err)
	}
	tk, err := LoadTrustedKeyPEM(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	p := testPolicy()
	p.TrustedKeys = []TrustedKey{tk}
	ok := Verify(t.Context(), out, p)
	requireOK(t, ok)

	// A failing verification and failing seals add their outputs too.
	bad := filepath.Join(work, "baseline-tampered")
	if _, err := Seal(t.Context(), defaultRequest(capDir, bad, signer)); err != nil {
		t.Fatal(err)
	}
	writeRaw(t, bad, "evidence/common.identity/extra", []byte("x"))
	failed := Verify(t.Context(), bad, testPolicy())
	if failed.OK {
		t.Fatal("setup: tampered baseline verified")
	}

	var errs []error
	req := defaultRequest(capDir, filepath.Join(work, "never"), signer)
	req.Approval.Reviewer = ""
	_, e := Seal(t.Context(), req)
	errs = append(errs, e)
	req = defaultRequest(capDir, filepath.Join(work, "never"), signer)
	req.SelfApproval = SelfApprovalBlock
	req.Approval.Reviewer = "alice"
	_, e = Seal(t.Context(), req)
	errs = append(errs, e)
	_, e = Seal(t.Context(), defaultRequest(capDir, out, signer)) // target not empty
	errs = append(errs, e)
	_, e = Seal(t.Context(), defaultRequest(capDir, filepath.Join(work, "never"), garbageSigner{signer}))
	errs = append(errs, e)
	_, e = NewFileSigner(pubPath)
	errs = append(errs, e)
	loose := filepath.Join(keyDir, "loose.priv")
	if err := os.WriteFile(loose, keyFile, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o644); err != nil {
		t.Fatal(err)
	}
	_, e = NewFileSigner(loose)
	errs = append(errs, e)
	a := sres.Approval
	a.Reason = ""
	_, e = SignStatement(signer, BuildStatement(a.CaptureDigest, sres.ContentDigest, a))
	errs = append(errs, e)
	for i, e := range errs {
		if e == nil {
			continue
		}
		scanForSecrets(t, fmt.Sprintf("error %d", i), []byte(e.Error()), text, binary)
	}
	for _, f := range failed.Failures {
		scanForSecrets(t, "failure detail", []byte(f.Detail), text, binary)
	}

	// JSON outputs.
	for name, v := range map[string]any{"seal result": sres, "verify ok": ok, "verify failed": failed} {
		b, err := trustfreeze.MarshalFile(v)
		if err != nil {
			t.Fatal(err)
		}
		scanForSecrets(t, name+" JSON", b, text, binary)
	}

	// Signers never print or marshal key material.
	seed := seedSigner(t, seedTrusted)
	req = defaultRequest(capDir, out, signer)
	for name, v := range map[string]any{"file signer": signer, "file signer value": *signer, "seed signer": seed, "request": req, "request ptr": &req} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%X", "%q", "%d"} {
			scanForSecrets(t, name+" "+verb, []byte(fmt.Sprintf(verb, v)), text, binary)
		}
		j, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		scanForSecrets(t, name+" JSON", j, text, binary)
	}

	// Every file the run produced.
	files := 0
	err = filepath.Walk(work, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		files++
		rel, _ := filepath.Rel(work, p)
		scanForSecrets(t, filepath.ToSlash(rel), b, text, binary)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 10 {
		t.Fatalf("scanned only %d files", files)
	}
	t.Logf("scanned %d produced files, %d error strings, 3 JSON outputs, 5 formatted values", files, len(errs))
}

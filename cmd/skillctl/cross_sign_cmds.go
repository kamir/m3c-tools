package main

// `skillctl cross-sign`: SPEC-0359 D3(i) producer side. A GOVERNANCE ROOT key
// signs a member reviewer's key, admitting them as an N-of-M co-attestation
// signer for anyone who pins that root. Output is a signed JSON record dropped
// into a peer's/trust-root's cross_sign_path.
//
//	skillctl cross-sign --member-id id:alice@org --member-pubkey <b64> \
//	  --key <gov-root-priv.pem> --not-after 8760h [--locator gitlab://…] [--out alice.json]

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
)

func runCrossSign(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cross-sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	memberID := fs.String("member-id", "", "Member reviewer identity id (e.g. id:alice@org). Required.")
	memberPub := fs.String("member-pubkey", "", "Member ed25519 public key, base64. Required.")
	keyPath := fs.String("key", "", "GOVERNANCE ROOT private key (PEM PKCS#8 ed25519). Required.")
	notAfter := fs.String("not-after", "", "Hard expiry: RFC3339, YYYY-MM-DD, or a duration like 8760h. Required.")
	locator := fs.String("locator", "", "Optional member registry locator.")
	out := fs.String("out", "", "Output file (default: stdout).")
	if err := fs.Parse(reorderFlagArgs(fs, args)); err != nil {
		return 2
	}
	if *memberID == "" || *memberPub == "" || *keyPath == "" || *notAfter == "" {
		fmt.Fprintln(stderr, "cross-sign: --member-id, --member-pubkey, --key and --not-after are all required")
		return 2
	}
	na, err := parseExpiresAt(*notAfter, time.Now())
	if err != nil || na == nil {
		fmt.Fprintf(stderr, "cross-sign: --not-after: %v\n", err)
		return 2
	}
	priv, err := signing.LoadPrivateKey(*keyPath)
	if err != nil {
		fmt.Fprintf(stderr, "cross-sign: load governance root key: %v\n", err)
		return 1
	}
	defer wipe(priv)

	rootFP := ""
	if pub, ok := priv.Public().(ed25519.PublicKey); ok {
		d := sha256.Sum256(pub)
		rootFP = "sha256:" + hex.EncodeToString(d[:])
	}
	ev, err := registry.BuildMemberCrossSignature(registry.CrossSignInput{
		GovernanceRootFingerprint: rootFP,
		MemberReviewerID:          *memberID,
		MemberPubKeyB64:           *memberPub,
		MemberRegistryLocator:     *locator,
		IssuedAt:                  time.Now().UTC(),
		NotAfter:                  *na,
	})
	if err != nil {
		fmt.Fprintf(stderr, "cross-sign: build record: %v\n", err)
		return 1
	}
	if _, err := registry.SignEnvelopeSignature(priv, ev); err != nil {
		fmt.Fprintf(stderr, "cross-sign: sign: %v\n", err)
		return 1
	}
	data, _ := json.MarshalIndent(ev, "", "  ")
	if *out == "" {
		fmt.Fprintln(stdout, string(data))
		return 0
	}
	if err := os.WriteFile(*out, append(data, '\n'), 0o600); err != nil {
		fmt.Fprintf(stderr, "cross-sign: write %s: %v\n", *out, err)
		return 1
	}
	fmt.Fprintf(stdout, "cross-signed %s (root fp=%s, expires %s) → %s\n", *memberID, rootFP, na.UTC().Format(time.RFC3339), *out)
	return 0
}

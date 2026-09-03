package registry

// Native Go fuzz target for the SPEC-0190 event envelope canonicalisation +
// signature verification. Event JSON is the untrusted item body on the ER1/bus
// transport. The two invariants: neither CanonicalEventBytes nor
// VerifyEnvelopeSignature ever panics on arbitrary JSON, and verification never
// fails OPEN — a pubkey the fuzzer cannot have signed for must never accept a
// forged/non-matching signature.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// FuzzEventEnvelope feeds raw JSON → map[string]any → CanonicalEventBytes +
// VerifyEnvelopeSignature against a fixed, deterministic pubkey. Oracles: never
// panics; if VerifyEnvelopeSignature returns nil, the signature MUST actually
// verify against that key (re-checked independently) — otherwise it is a
// fail-open bug.
func FuzzEventEnvelope(f *testing.F) {
	// Deterministic, valid ed25519 key. The fuzzer cannot produce a signature
	// that verifies against it, so a nil verify error is either a genuine (and
	// astronomically unlikely) forgery or a fail-open bug — both are t.Fatal.
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	validDigest := "sha256:" + strings.Repeat("a", 64)
	sig64 := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	f.Add([]byte(`{"schema_version":"1.0.0","name":"x","version":"1.0.0"}`))
	f.Add([]byte(`{"envelope_signature":"AAAA","bundle_digest":"` + validDigest + `"}`))
	f.Add([]byte(`{"envelope_signature":123}`))
	f.Add([]byte(`{"a":{"b":[1,2,3]},"envelope_signature":"not-base64-!!!"}`))
	f.Add([]byte(`{"envelope_signature":"` + sig64 + `","x":"y"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`not json`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var ev map[string]any
		if err := json.Unmarshal(data, &ev); err != nil || ev == nil {
			return // only well-formed JSON objects reach the functions
		}

		canon, cerr := CanonicalEventBytes(ev) // must never panic
		verr := VerifyEnvelopeSignature(pub, ev) // must never panic
		if verr == nil {
			// Fail-open guard: an accepted event must carry a signature that
			// genuinely verifies against pub over the canonical bytes.
			if cerr != nil {
				t.Fatalf("VerifyEnvelopeSignature accepted the event but CanonicalEventBytes errored: %v", cerr)
			}
			raw, _ := ev[EnvelopeSignatureField].(string)
			sig, derr := base64.StdEncoding.DecodeString(raw)
			if derr != nil || !ed25519.Verify(pub, canon, sig) {
				t.Fatalf("VerifyEnvelopeSignature verified a non-matching/forged signature (fail-open): sig=%q", raw)
			}
		}
	})
}

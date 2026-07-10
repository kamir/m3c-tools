// Package translog implements the L1 transparency log for SPEC-0278:
// an RFC-6962 / Sigstore-Rekor-style append-only Merkle tree built from
// the Go standard library only (crypto/sha256, crypto/ed25519). No
// Trillian, no Rekor, no blockchain, no Kafka.
//
// # What L1 buys, and what it deliberately does NOT
//
// L1 makes equivocation, censorship and withholding DETECTABLE — it does
// NOT make them impossible. Concretely:
//
//   - An inclusion proof lets a verifier confirm offline that a specific
//     event is committed under a Signed Tree Head (STH) it trusts.
//   - A consistency proof lets a verifier confirm that a newer tree is a
//     pure append of an older one — i.e. nothing in history was rewritten
//     or dropped. A log that drops/rewrites an entry FAILS this check, so
//     a rewrite becomes DETECTABLE.
//   - Cross-witnessed STHs let two parties notice when a log operator
//     showed them different histories at the same tree size (a split
//     view). That equivocation becomes DETECTABLE.
//
// What L1 does NOT do: it cannot PREVENT a single log operator from
// equivocating, withholding, or censoring. Preventing that requires the
// deferred L2 (a no-single-operator BFT consortium ledger), where M-of-N
// consensus stops any one operator from rewriting or withholding. L2 and
// L3 (public-chain anchoring of tree heads) are buyer-gated per SPEC-0278
// §5/§6 and are NOT built here. The Kafka/SPEC-0190 gossip TRANSPORT is
// also deferred: this package implements the STH-comparison / witness
// LOGIC offline, not the wire transport.
//
// # Data stays off the log
//
// Per SPEC-0278 §5 (EU data sovereignty) NO artifact or personal data
// ever goes on the log. A leaf commits only the DIGEST of an
// already-signed event plus its type and timestamp (see LogEntry). The
// signed event itself stays off-log. The log adds ordering, freshness,
// non-equivocation and shared availability — and nothing more.
//
// # Domain separation (second-preimage resistance)
//
// RFC-6962 prefixes the data being hashed with a one-byte domain tag so a
// leaf hash can never collide with an internal-node hash:
//
//	leaf hash  = SHA-256( 0x00 || leaf_bytes )
//	node hash  = SHA-256( 0x01 || left_hash || right_hash )
//
// Without the prefixes an attacker who controls a leaf value could feed
// in the concatenation of two child hashes and have the verifier treat an
// internal node as a leaf (or vice versa) — the classic Merkle
// second-preimage / leaf-vs-node confusion. The prefixes (LeafPrefix /
// NodePrefix below) close that.
//
// The STH carries its OWN distinct domain separator ("skillctl-sth-v1",
// see sth.go) so an ed25519 signature produced over an STH can never be
// replayed as an attestation, a revocation, or any other envelope in the
// spine — and vice versa.
package translog

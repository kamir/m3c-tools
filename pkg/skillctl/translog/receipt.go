package translog

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// Receipt is a portable, self-contained inclusion receipt: everything a
// verifier needs to confirm OFFLINE that one event is committed under a
// signed tree head — the event, its leaf position, the inclusion proof, and
// the STH. It is the JSON artifact the CLI `prove` verb emits and the
// `verify` verb consumes, and the "log receipt" that can ride alongside a
// signed bundle.
//
// The proof hashes are hex-encoded for JSON portability. NO event data
// beyond the LogEntry (which is itself just a digest + type + timestamp +
// subject) is carried — data stays off the log (SPEC-0278 §5).
type Receipt struct {
	// Entry is the logged event. Its leaf hash is RECOMPUTED on verify —
	// the receipt never carries a trusted leaf hash.
	Entry LogEntry `json:"entry"`

	// Index is the leaf position the proof claims.
	Index int `json:"index"`

	// TreeSize is the size the proof was produced against (and that the
	// STH must commit).
	TreeSize int `json:"tree_size"`

	// ProofHex is the inclusion (audit) path, each node hex-encoded.
	ProofHex []string `json:"proof"`

	// STH is the signed tree head the proof verifies against.
	STH STH `json:"sth"`
}

// ErrReceiptInvalid — a receipt failed structural validation (bad proof
// hex, size/STH mismatch, etc.).
var ErrReceiptInvalid = errors.New("translog: invalid inclusion receipt")

// NewReceipt assembles a receipt from raw proof hashes and an STH.
func NewReceipt(entry LogEntry, index, treeSize int, proof [][HashSize]byte, sth STH) Receipt {
	hexes := make([]string, len(proof))
	for i, p := range proof {
		hexes[i] = hex.EncodeToString(p[:])
	}
	return Receipt{Entry: entry, Index: index, TreeSize: treeSize, ProofHex: hexes, STH: sth}
}

// MarshalJSON-friendly dump.
func (r Receipt) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// ParseReceipt decodes a receipt from JSON and validates its shape.
func ParseReceipt(data []byte) (Receipt, error) {
	var r Receipt
	if err := json.Unmarshal(data, &r); err != nil {
		return Receipt{}, fmt.Errorf("%w: %v", ErrReceiptInvalid, err)
	}
	if err := r.validate(); err != nil {
		return Receipt{}, err
	}
	return r, nil
}

// proofBytes decodes ProofHex into fixed-size node hashes, rejecting any
// element that is not exactly HashSize bytes of hex.
func (r Receipt) proofBytes() ([][HashSize]byte, error) {
	out := make([][HashSize]byte, len(r.ProofHex))
	for i, h := range r.ProofHex {
		raw, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("%w: proof[%d] not hex: %v", ErrReceiptInvalid, i, err)
		}
		if len(raw) != HashSize {
			return nil, fmt.Errorf("%w: proof[%d] is %d bytes, want %d", ErrReceiptInvalid, i, len(raw), HashSize)
		}
		copy(out[i][:], raw)
	}
	return out, nil
}

func (r Receipt) validate() error {
	if r.TreeSize < 1 {
		return fmt.Errorf("%w: tree_size must be >= 1", ErrReceiptInvalid)
	}
	if r.Index < 0 || r.Index >= r.TreeSize {
		return fmt.Errorf("%w: index %d out of range for tree_size %d", ErrReceiptInvalid, r.Index, r.TreeSize)
	}
	if r.STH.TreeSize != r.TreeSize {
		return fmt.Errorf("%w: STH tree_size %d != receipt tree_size %d", ErrReceiptInvalid, r.STH.TreeSize, r.TreeSize)
	}
	if _, err := r.Entry.Canonical(); err != nil {
		return fmt.Errorf("%w: %v", ErrReceiptInvalid, err)
	}
	if _, err := r.proofBytes(); err != nil {
		return err
	}
	return nil
}

// VerifyOffline checks the receipt end-to-end against a pinned log public
// key, with NO network access:
//
//  1. the STH signature verifies under logPub (so the head is authentic and
//     from the pinned log);
//  2. the event's leaf hash (RECOMPUTED from the entry) is included at
//     r.Index in a tree of r.TreeSize whose root is the STH's root.
//
// Returns nil on success; a wrapped sentinel on any failure. This is the
// single call the CLI `verify` verb makes — it is the offline inclusion
// check a cross-org verifier runs against a head it already trusts.
func (r Receipt) VerifyOffline(logPub []byte) error {
	if err := r.validate(); err != nil {
		return err
	}
	if err := VerifySTH(logPub, r.STH); err != nil {
		return err
	}
	root, err := r.STH.RootBytes()
	if err != nil {
		return err
	}
	leaf, err := r.Entry.LeafHash()
	if err != nil {
		return err
	}
	proof, err := r.proofBytes()
	if err != nil {
		return err
	}
	return VerifyInclusion(leaf, r.Index, r.TreeSize, proof, root)
}

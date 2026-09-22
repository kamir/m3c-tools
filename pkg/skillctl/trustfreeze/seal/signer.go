package seal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
)

// Signer signs Trust Freeze statements (SPEC-0470 TF05-R8). Like
// envreport.Signierer it hands out signatures, never the private key, so a
// device key or a hardware token can implement it without breaking its
// encapsulation. KeyID must equal KeyIDFor(PublicKey()).
type Signer interface {
	KeyID() string
	PublicKey() ed25519.PublicKey
	Sign(msg []byte) ([]byte, error)
}

// Key id convention (SPEC-0470 section 4.3).
//
// key_id = "ed25519:" + the first 16 lowercase hex characters of
// sha256(raw 32-byte public key).
//
// The digest and its length are those of pkg/skillctl/device, so for a
// device key the hex part equals the hex part of device.Key.KeyID(). The
// "device:" prefix is not reused: it asserts a device-key origin
// (SPEC-0202 D1, separate keys per blast radius), and a baseline is usually signed with
// a reviewer key. The trust-roots fallback id "key-<hex8>" is not used either:
// it is the first four raw key bytes, not a digest. The key id is only an
// index: Verify always checks the full public key and recomputes the id.
const KeyIDPrefix = "ed25519:"

const keyIDHexLen = 16

// KeyIDFor returns the key id of an ed25519 public key.
func KeyIDFor(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return KeyIDPrefix + hex.EncodeToString(sum[:])[:keyIDHexLen]
}

// ValidKeyID reports whether id has the key id form (it does not check which
// key it belongs to).
func ValidKeyID(id string) bool {
	h, ok := strings.CutPrefix(id, KeyIDPrefix)
	return ok && isLowerHex(h, keyIDHexLen)
}

// Signer errors.
var (
	ErrSignerClosed  = errors.New("seal: signer is closed")
	ErrSignerInvalid = errors.New("seal: signer is not usable")
)

// keyPair holds a private key in memory. It prints and marshals as its key id
// only, so a signer that ends up in a log line, a %+v dump or a JSON document
// never reveals key material (TF05-R8).
type keyPair struct {
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	keyID string
}

func newKeyPair(priv ed25519.PrivateKey) (keyPair, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return keyPair{}, fmt.Errorf("%w: private key has length %d, want %d", ErrSignerInvalid, len(priv), ed25519.PrivateKeySize)
	}
	// An ed25519 private key carries its public half; re-derive it from the
	// seed so a key file whose halves disagree is refused instead of producing
	// signatures that verify under no published key.
	seed := priv.Seed()
	defer clear(seed)
	derived := ed25519.NewKeyFromSeed(seed)
	defer clear(derived)
	if !bytes.Equal(derived, priv) {
		return keyPair{}, fmt.Errorf("%w: private key halves are inconsistent", ErrSignerInvalid)
	}
	own := make(ed25519.PrivateKey, len(priv))
	copy(own, priv)
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(pub, own[ed25519.SeedSize:])
	return keyPair{priv: own, pub: pub, keyID: KeyIDFor(pub)}, nil
}

// KeyID returns the key id (see KeyIDPrefix).
func (k keyPair) KeyID() string { return k.keyID }

// PublicKey returns a copy of the public key.
func (k keyPair) PublicKey() ed25519.PublicKey {
	out := make(ed25519.PublicKey, len(k.pub))
	copy(out, k.pub)
	return out
}

// Sign returns the ed25519 signature of msg.
func (k keyPair) Sign(msg []byte) ([]byte, error) {
	if len(k.priv) != ed25519.PrivateKeySize {
		return nil, ErrSignerClosed
	}
	return ed25519.Sign(k.priv, msg), nil
}

// Format prints only the key id, for every verb.
func (k keyPair) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprintf(f, "seal.Signer{key_id:%s}", k.keyID)
}

// MarshalJSON emits only the public part.
func (k keyPair) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		KeyID     string `json:"key_id"`
		PublicKey string `json:"public_key"`
	}{k.keyID, base64.StdEncoding.EncodeToString(k.pub)})
}

func (k *keyPair) close() {
	clear(k.priv)
	k.priv = nil
}

// FileSigner signs with a PEM/PKCS#8 ed25519 private key file loaded through
// signing.LoadPrivateKey, so the existing key file conventions apply
// unchanged: mode 0600 enforced on POSIX, one PEM block, ed25519 only.
type FileSigner struct {
	keyPair
}

// NewFileSigner loads the private key at path.
func NewFileSigner(path string) (*FileSigner, error) {
	priv, err := signing.LoadPrivateKey(path)
	if err != nil {
		return nil, fmt.Errorf("seal: signing key: %w", err)
	}
	defer clear(priv)
	kp, err := newKeyPair(priv)
	if err != nil {
		return nil, err
	}
	return &FileSigner{keyPair: kp}, nil
}

// Close wipes the in-memory private key (best effort); Sign fails afterwards.
// Close must not run concurrently with Sign.
func (s *FileSigner) Close() { s.close() }

// SeedSigner signs with a key derived from a fixed 32-byte seed. It exists
// for tests and fixtures: the seed must be synthetic and must never be a
// production key.
type SeedSigner struct {
	keyPair
}

// NewSeedSigner derives the key from seed (ed25519.NewKeyFromSeed).
func NewSeedSigner(seed []byte) (*SeedSigner, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: seed has length %d, want %d", ErrSignerInvalid, len(seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	defer clear(priv)
	kp, err := newKeyPair(priv)
	if err != nil {
		return nil, err
	}
	return &SeedSigner{keyPair: kp}, nil
}

// Close wipes the in-memory private key (best effort); Sign fails afterwards.
func (s *SeedSigner) Close() { s.close() }

// checkSigner verifies the Signer contract before anything is signed.
func checkSigner(s Signer) (ed25519.PublicKey, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: no signer", ErrSignerInvalid)
	}
	pub := s.PublicKey()
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: public key has length %d, want %d", ErrSignerInvalid, len(pub), ed25519.PublicKeySize)
	}
	if s.KeyID() != KeyIDFor(pub) {
		return nil, fmt.Errorf("%w: key id %q does not belong to the public key (want %q)", ErrSignerInvalid, s.KeyID(), KeyIDFor(pub))
	}
	return pub, nil
}

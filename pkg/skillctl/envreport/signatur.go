// signatur.go: der Bericht wird eine signierte Aussage (SPEC-0428 E1, E-I aus
// dem PO-Review vom 2026-09-13).
//
// Der Anlass ist ein Widerspruch, den erst die Pruefung gefunden hat: SPEC-0428
// E1 nennt den Bericht "eine signierte, datierte, unveraenderliche Aussage",
// und im ganzen Paket stand keine Signatur. Der `report-digest` lag als Marke
// NEBEN dem Posten, geschrieben von derselben Partei wie der Rumpf, und die
// Leseseite hat ihn nie dagegen geprueft. Eine Unveraenderlichkeit, die nur der
// Schreiber zusichert, ist eine Behauptung.
//
// Zwei Entscheidungen, beide gegen den naheliegenden Weg:
//
//  1. DIE SIGNATUR GEHOERT IN DEN BERICHT, nicht neben ihn. Eine Marke am
//     ER1-Posten schuetzt nichts: wer den Rumpf aendern kann, kann die Marke
//     aendern. Im Rumpf ist sie Teil dessen, was sie schuetzt.
//  2. KEIN ZWEITER SIGNIERMECHANISMUS. Kanonisierung und Umschlagfeld sind
//     dieselben wie in der Registry (`registry.CanonicalEventBytes`,
//     `envelope_signature`). SPEC-0404 hat genau diesen Fehler an SPEC-0402
//     und SPEC-0403 aufgedeckt; er wird hier nicht wiederholt.
package envreport

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

var (
	ErrSignaturFehlt            = errors.New("report: missing signature")
	ErrSignaturUngueltig        = errors.New("report: signature does not match the body")
	ErrEinwilligungNichtImRumpf = errors.New("report: no consent recorded in the body")
	// ErrSignaturUngeprueft ist KEIN Fehlschlag, sondern eine Einschraenkung der
	// Auskunft: der Digest stimmt, die Signatur wurde mangels Schluessel nicht
	// geprueft. Sie wird zurueckgegeben, damit ein Aufrufer die schwaechere
	// Aussage nicht fuer die staerkere haelt.
	ErrSignaturUngeprueft = errors.New("report: digest checked, signature NOT verified (no public key supplied)")
)

// alsUmschlag bildet den Bericht auf die Kartenform ab, die die kanonische
// Byte-Folge der Registry erwartet. Der Umweg ueber JSON ist Absicht: er
// garantiert, dass genau die Felder in die Signatur eingehen, die auch
// serialisiert werden, und kein Go-Feld, das `json:"-"` traegt.
func alsUmschlag(r Report) (map[string]any, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("canonicalize report: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("canonicalize report: %w", err)
	}
	return m, nil
}

// Signierer ist alles, was eine Byte-Folge unterschreiben kann.
//
// Die Schnittstelle statt eines rohen Schluessels, weil der Geraeteschluessel
// (pkg/skillctl/device) seinen privaten Teil bewusst NICHT herausgibt: er
// signiert, er wird nicht ausgehaendigt. Ein Paket, das den rohen Schluessel
// verlangt, zwingt jeden Aufrufer, diese Kapselung zu brechen.
type Signierer interface {
	Sign(msg []byte) []byte
}

// RohSchluessel macht einen nackten ed25519-Schluessel zum Signierer. Fuer
// Tests und fuer Aufrufer, die ihren Schluessel ohnehin schon in der Hand haben.
type RohSchluessel ed25519.PrivateKey

func (k RohSchluessel) Sign(msg []byte) []byte {
	return ed25519.Sign(ed25519.PrivateKey(k), msg)
}

// Signiere setzt die Signatur im Bericht. Sie deckt alles ab, was serialisiert
// wird, ausser sich selbst.
//
// Anders als Digest() deckt die Signatur AUCH `report_seq` und `taken_at` ab.
// Das ist kein Widerspruch, sondern die Arbeitsteilung: der Digest sagt "das
// ist derselbe Zustand" und muss ueber zwei Erhebungen gleich bleiben; die
// Signatur sagt "das ist genau dieser Posten" und muss sich unterscheiden.
func Signiere(signer Signierer, r *Report, signerID string) error {
	if r == nil {
		return errors.New("sign report: nil report")
	}
	if signer == nil {
		return errors.New("sign report: no signer")
	}
	if signerID == "" {
		return errors.New("sign report: signer id required")
	}
	r.SignerID = signerID
	r.Signatur = ""
	m, err := alsUmschlag(*r)
	if err != nil {
		return err
	}
	canon, err := registry.CanonicalEventBytes(m)
	if err != nil {
		return err
	}
	r.Signatur = base64.StdEncoding.EncodeToString(signer.Sign(canon))
	return nil
}

// PruefeSignatur prueft die Signatur gegen den Rumpf.
//
// Ein fehlendes Feld und eine falsche Signatur sind VERSCHIEDENE Fehler: das
// erste heisst "niemand hat unterschrieben", das zweite heisst "jemand hat
// danach etwas geaendert". Wer beide gleich nennt, kann auf keines reagieren.
func PruefeSignatur(pub ed25519.PublicKey, r Report) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("verify report: invalid ed25519 public key size %d", len(pub))
	}
	if r.Signatur == "" {
		return ErrSignaturFehlt
	}
	sig, err := base64.StdEncoding.DecodeString(r.Signatur)
	if err != nil {
		return fmt.Errorf("%w: not base64: %v", ErrSignaturUngueltig, err)
	}
	ohne := r
	ohne.Signatur = ""
	m, err := alsUmschlag(ohne)
	if err != nil {
		return err
	}
	canon, err := registry.CanonicalEventBytes(m)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, canon, sig) {
		return ErrSignaturUngueltig
	}
	return nil
}

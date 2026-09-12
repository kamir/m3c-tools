// report.go: der Skill-Env-Report aus SPEC-0428.
//
// Ein Bericht ist eine signierte, datierte, UNVERAENDERLICHE Aussage darueber,
// was EINE geregelte Umgebung zu EINEM Zeitpunkt hielt. Alles Weitere ist eine
// Rechnung darauf: Deckung, Konformitaet, Vergleich, Entwicklung.
//
// Die vierte Rechnung ist der ganze Grund fuer die Unveraenderlichkeit. Die
// Aufbewahrung ist das Merkmal, nicht die Erhebung: erheben kann `skillctl
// audit` seit langem, was fehlte, ist dass das Ergebnis BLEIBT. Genau daran
// scheitert die Entwicklungsauswertung heute, weil `skillprofile` nur den
// aktuellen Wert haelt und `recalculate-all` den Vorzustand ueberschreibt.
//
// Der Rumpf (Zeile) ist die posture.snapshot-Nutzlast aus SPEC-0351
// Abschnitt 5.1, WOERTLICH. Nach der Besitzregel aus SPEC-0404 gehoert die
// Ereignisdefinition SPEC-0351; dieses Paket besitzt Aufbewahrung,
// Adressierung und Personenbindung. Ein Feld, das dort nicht vorkommt, wird
// abgelehnt (AC-02): ein zweites Schema waere genau der Fehler, den SPEC-0404
// an SPEC-0402 und SPEC-0403 aufgedeckt hat, und zwar am selben Gegenstand.
package envreport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Posture ist die Gesamtlage einer Umgebung zum Erhebungszeitpunkt.
type Posture string

const (
	PostureOK           Posture = "ok"
	PostureDrift        Posture = "drift"
	PostureContaminated Posture = "contaminated"
)

var (
	ErrENVFehlt      = errors.New("Bericht ohne env")
	ErrTakenAtFehlt  = errors.New("Bericht ohne taken_at")
	ErrSeqFehlt      = errors.New("Bericht ohne report_seq")
	ErrFristFehlt    = errors.New("Bericht ohne Aufbewahrungsfrist")
	ErrPostureUnbek  = errors.New("Bericht mit unbekannter posture")
	ErrFremdesFeld   = errors.New("Rumpfzeile traegt ein Feld, das posture.snapshot nicht kennt")
	ErrZeileOhneName = errors.New("Rumpfzeile ohne skill.name")
)

// Trust ist der `trust`-Block aus SPEC-0351 Abschnitt 5.1.
type Trust struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// SkillRef ist der `skill`-Block aus SPEC-0351 Abschnitt 5.1.
type SkillRef struct {
	Name    string `json:"name"`
	Tier    string `json:"tier,omitempty"`
	Digest  string `json:"digest,omitempty"`
	Version string `json:"version,omitempty"`
}

// Conflict ist ein Eintrag in quality.conflicts (SPEC-0351 Abschnitt 5.1).
type Conflict struct {
	With    string  `json:"with"`
	Jaccard float64 `json:"jaccard"`
}

// Quality ist der `quality`-Block aus SPEC-0351 Abschnitt 5.1.
type Quality struct {
	Flags     []string   `json:"flags,omitempty"`
	Conflicts []Conflict `json:"conflicts,omitempty"`
}

// Policy ist der `policy`-Block aus SPEC-0351 Abschnitt 5.1.
type Policy struct {
	Mandated        bool   `json:"mandated"`
	ShadowedBy      string `json:"shadowed_by,omitempty"`
	GovernanceFloor string `json:"governance_floor,omitempty"`
}

// Zeile ist EINE Faehigkeit im Bericht: genau die Bloecke skill, trust,
// quality und policy aus SPEC-0351 Abschnitt 5.1, nicht mehr.
type Zeile struct {
	Skill   SkillRef `json:"skill"`
	Trust   Trust    `json:"trust"`
	Quality Quality  `json:"quality,omitempty"`
	Policy  Policy   `json:"policy,omitempty"`
}

// erlaubteZeilenfelder ist die Liste aus SPEC-0351 Abschnitt 5.1. Sie steht
// hier ausgeschrieben und wird NICHT aus dem Go-Typ abgeleitet: waechst der
// Typ, soll AC-02 fehlschlagen und einen Menschen fragen, statt die Erweiterung
// stillschweigend mitzumachen.
var erlaubteZeilenfelder = map[string]bool{
	"skill": true, "trust": true, "quality": true, "policy": true,
}

// Report ist der Bericht selbst. Envelope plus Zeilen.
type Report struct {
	ENV       string    `json:"env"`
	Principal string    `json:"principal"`
	Seq       int       `json:"report_seq"`
	TakenAt   time.Time `json:"taken_at"`
	Posture   Posture   `json:"posture"`
	// AufbewahrungBis ist ein PFLICHTFELD (SPEC-0428 AC-12). Kein Vorgabewert
	// ohne Ende: eine Aussage ueber das Arbeitsverhalten eines Menschen, die
	// nie verfaellt, ist keine Aufbewahrung, sondern ein Archiv ueber ihn.
	AufbewahrungBis time.Time `json:"aufbewahrung_bis"`
	Zeilen          []Zeile   `json:"zeilen"`
}

// Validate prueft die Pflichtfelder (AC-01, AC-12) und nennt das FEHLENDE
// Feld, nicht bloss "ungueltig". Eine Meldung, die nicht sagt was fehlt,
// zwingt den Aufrufer zum Raten.
func (r Report) Validate() error {
	if strings.TrimSpace(r.ENV) == "" {
		return ErrENVFehlt
	}
	if _, err := ParseENV(r.ENV); err != nil {
		return fmt.Errorf("env: %w", err)
	}
	if r.TakenAt.IsZero() {
		return ErrTakenAtFehlt
	}
	if r.Seq <= 0 {
		return ErrSeqFehlt
	}
	if r.AufbewahrungBis.IsZero() {
		return ErrFristFehlt
	}
	switch r.Posture {
	case PostureOK, PostureDrift, PostureContaminated:
	default:
		return fmt.Errorf("%w: %q", ErrPostureUnbek, r.Posture)
	}
	for i, z := range r.Zeilen {
		if strings.TrimSpace(z.Skill.Name) == "" {
			return fmt.Errorf("Zeile %d: %w", i, ErrZeileOhneName)
		}
	}
	return nil
}

// PruefeRumpf lehnt eine Rumpfzeile ab, die ein Feld traegt, das
// posture.snapshot nicht kennt (AC-02). Das ist die Sperre gegen ein
// zweites Schema.
func PruefeRumpf(rohZeile []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(rohZeile, &m); err != nil {
		return fmt.Errorf("Rumpfzeile ist kein Objekt: %w", err)
	}
	fremde := []string{}
	for k := range m {
		if !erlaubteZeilenfelder[k] {
			fremde = append(fremde, k)
		}
	}
	if len(fremde) > 0 {
		sort.Strings(fremde)
		return fmt.Errorf("%w: %s", ErrFremdesFeld, strings.Join(fremde, ", "))
	}
	return nil
}

// Digest ist die inhaltliche Kennung des Berichts: sie deckt die Zeilen und
// die ENV ab, aber WEDER report_seq NOCH taken_at.
//
// Das ist Absicht und der Kern von AC-04: zwei Laeufe ohne Aenderung an der
// Maschine muessen denselben Digest und verschiedene Seq ergeben. Gleicher
// Inhalt, zaehlbare Erhebung. Wuerde der Zeitpunkt eingehen, waere jeder Lauf
// verschieden und der Digest sagte nichts ueber den Zustand aus.
func (r Report) Digest() string {
	zeilen := make([]Zeile, len(r.Zeilen))
	copy(zeilen, r.Zeilen)
	sort.Slice(zeilen, func(i, j int) bool { return zeilen[i].Skill.Name < zeilen[j].Skill.Name })
	h := sha256.New()
	fmt.Fprintf(h, "env=%s\n", r.ENV)
	for _, z := range zeilen {
		b, _ := json.Marshal(z)
		h.Write(b)
		h.Write([]byte("\n"))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

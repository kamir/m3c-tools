// store.go: die Aufbewahrung (SPEC-0428 T-03).
//
// Ab hier entsteht ein PERSONENDATUM. Bis T-02 hat dieses Paket nur gerechnet;
// dieser Teil legt eine Aussage ueber das Arbeitsverhalten eines benannten
// Menschen dauerhaft ab. Die fuenf Grenzen aus SPEC-0428 Abschnitt "Die Grenze"
// werden deshalb hier zu Code und nicht zu Prosa:
//
//  1. Der Host ist gehasht        -> erzwungen im ENV-Typ (env.go), hier geprueft
//  2. Kein Quelltext off-box      -> pruefeKeinQuelltext, unten
//  3. Einwilligung                -> Pflichtfeld Consent, ohne sie kein Put
//  4. Aufbewahrungsfrist          -> Pflichtfeld, schon in Report.Validate
//  5. Personenvergleich gesondert -> der Store liest je ENV, nie ueber Personen
//
// Die Ablage ist ANHAENGEND. Ein zweiter Bericht derselben Umgebung
// ueberschreibt den ersten nicht (AC-06), denn genau die Aufbewahrung ist das
// Merkmal dieser SPEC. Ein Store, der ueberschreibt, ist ein Zustandsspeicher
// und keine Zeitreihe, und dann waere die Entwicklungsauswertung wieder
// unmoeglich, so wie sie es bei skillprofile heute ist.
package envreport

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

var (
	ErrEinwilligungFehlt = errors.New("store: missing consent for this principal")
	ErrSchonVorhanden    = errors.New("store: a report with this seq already exists for this env")
	ErrQuelltextImRumpf  = errors.New("store: report row carries skill source text; only digests and verdicts may leave the machine")
	ErrHostImKlartext    = errors.New("store: env address carries a plaintext host")
)

// Einwilligung belegt, dass die beobachtete Person weiss, dass sie beobachtet
// wird (SPEC-0391 E3, uebernommen von SPEC-0428). Eine Einsetzung durch eine
// Autoritaet zaehlt nur MIT Benachrichtigung; deshalb traegt der Typ beide
// Faelle und keinen davon als Vorgabewert.
type Einwilligung struct {
	// Principal ist die Person, um deren Umgebung es geht.
	Principal string
	// Erteilt ist der Zeitpunkt der Zustimmung ODER der Benachrichtigung.
	Erteilt time.Time
	// Art ist "selbst" (die Person hat zugestimmt) oder "eingesetzt"
	// (eine Autoritaet hat sie eingesetzt und sie wurde benachrichtigt).
	Art string
	// Beleg nennt, woran die Zustimmung oder Benachrichtigung haengt.
	// Ein leerer Beleg ist keine Einwilligung.
	Beleg string
}

// Gueltig prueft die Einwilligung gegen den Prinzipal des Berichts.
func (e Einwilligung) Gueltig(principal string, jetzt time.Time) error {
	if strings.TrimSpace(e.Principal) == "" || e.Principal != principal {
		return fmt.Errorf("%w: consent names %q, report names %q",
			ErrEinwilligungFehlt, e.Principal, principal)
	}
	if e.Erteilt.IsZero() || e.Erteilt.After(jetzt) {
		return fmt.Errorf("%w: consent has no valid timestamp", ErrEinwilligungFehlt)
	}
	switch e.Art {
	case "selbst", "eingesetzt":
	default:
		return fmt.Errorf("%w: unknown consent kind %q (want \"selbst\" or \"eingesetzt\")",
			ErrEinwilligungFehlt, e.Art)
	}
	if strings.TrimSpace(e.Beleg) == "" {
		return fmt.Errorf("%w: consent without evidence is not consent", ErrEinwilligungFehlt)
	}
	return nil
}

// Abgelegt beschreibt einen abgelegten Bericht, ohne ihn zu laden.
type Abgelegt struct {
	DocID   string
	ENV     string
	Seq     int
	Digest  string
	TakenAt time.Time
}

// Store ist die Ablage. Die Schnittstelle ist bewusst schmal: anlegen und je
// Umgebung auflisten. Es gibt KEINE Methode, die ueber Prinzipale hinweg liest.
// Der Personenvergleich ist eine eigene Freigabe (Grenze 5) und darf nicht als
// Nebenwirkung eines Lesezugriffs entstehen.
type Store interface {
	// Anker liefert (und legt bei Bedarf an) den Anker-Posten einer Umgebung.
	Anker(env string) (string, error)
	// Ablegen schreibt einen Bericht. Anhaengend: eine bereits vergebene
	// (env, seq) wird abgelehnt, nicht ueberschrieben.
	Ablegen(r Report, e Einwilligung) (Abgelegt, error)
	// Liste nennt die abgelegten Berichte EINER Umgebung, aufsteigend nach Seq.
	Liste(env string) ([]Abgelegt, error)
}

// Marken baut die acht Marken aus SPEC-0428 E3.
//
// Sie liegen bewusst NEBEN der bestehenden Markenfamilie und nicht in ihr:
// `skill-event:*` bleibt die Sendeseite (zugelassen, bescheinigt, widerrufen,
// und das per-Skill installed, das `pull --install` schon schreibt),
// `skill-env-report` ist die Umgebungsseite. Ein Umgebungsbericht ist etwas
// anderes als ein Installationsereignis: er ist periodisch statt ausgeloest,
// deckt die GANZE Umgebung statt einer Faehigkeit, und er wird aufbewahrt.
func Marken(r Report, ankerCtx, ankerID string) []string {
	t := []string{
		"skill-env-report",
		"env:" + strings.TrimPrefix(r.ENV, Prefix),
		"principal:" + r.Principal,
		fmt.Sprintf("report-seq:%d", r.Seq),
		"report-digest:" + r.Digest(),
		"taken-at:" + r.TakenAt.UTC().Format("2006-01-02"),
		"posture:" + string(r.Posture),
	}
	if ankerID != "" {
		t = append(t, fmt.Sprintf("link/parent/%s/%s", ankerCtx, ankerID))
	}
	sort.Strings(t)
	return t
}

// verdaechtigeFelder sind Rumpfschluessel, die auf Quelltext hindeuten.
// Grenze 2: nur Digests, Urteile und Marken verlassen die Maschine.
var verdaechtigeFelder = []string{"body", "content", "source", "text", "skill_md", "prompt"}

// PruefeAblage fuehrt alle Grenzen aus, bevor irgendetwas geschrieben wird.
// Sie ist exportiert, damit ein Aufrufer sie VOR dem Netzaufruf laufen lassen
// kann: eine Grenze, die erst der Server durchsetzt, ist keine.
func PruefeAblage(r Report, e Einwilligung, jetzt time.Time) error {
	if err := r.Validate(); err != nil {
		return err // deckt Grenze 4 (Aufbewahrungsfrist) mit ab
	}
	env, err := ParseENV(r.ENV)
	if err != nil {
		return err
	}
	// Grenze 1: der Host-Teil muss wie ein Hash aussehen, nicht wie ein Name.
	if !istHash(env.HostHash) {
		return fmt.Errorf("%w: %q", ErrHostImKlartext, env.HostHash)
	}
	// Grenze 3: Einwilligung.
	if err := e.Gueltig(r.Principal, jetzt); err != nil {
		return err
	}
	// Grenze 2: kein Quelltext.
	return pruefeKeinQuelltext(r)
}

func istHash(s string) bool {
	if len(s) != HostHashLen {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

func pruefeKeinQuelltext(r Report) error {
	for i, z := range r.Zeilen {
		// Der Zeilentyp kann Quelltext gar nicht tragen; geprueft wird der
		// Grund, aus dem er es koennte: ein ueberlanger Freitext.
		if len(z.Trust.Reason) > 512 {
			return fmt.Errorf("%w: row %d reason is %d bytes", ErrQuelltextImRumpf, i, len(z.Trust.Reason))
		}
		for _, f := range verdaechtigeFelder {
			if strings.Contains(strings.ToLower(z.Skill.Name), f+":") {
				return fmt.Errorf("%w: row %d name looks like a payload", ErrQuelltextImRumpf, i)
			}
		}
	}
	return nil
}

// MemStore ist eine Ablage im Speicher. Sie ist die Vorrichtung fuer die
// Abnahme: die Grenzen und das Anhaengen lassen sich damit pruefen, OHNE dass
// ein Personendatum das Testsystem verlaesst.
type MemStore struct {
	AnkerCtx string
	anker    map[string]string
	items    map[string][]Abgelegt
	n        int
}

func NewMemStore(ctx string) *MemStore {
	return &MemStore{AnkerCtx: ctx, anker: map[string]string{}, items: map[string][]Abgelegt{}}
}

func (m *MemStore) Anker(env string) (string, error) {
	if id, ok := m.anker[env]; ok {
		return id, nil
	}
	m.n++
	id := fmt.Sprintf("anker-%03d", m.n)
	m.anker[env] = id
	return id, nil
}

func (m *MemStore) Ablegen(r Report, e Einwilligung) (Abgelegt, error) {
	if err := PruefeAblage(r, e, time.Now().UTC()); err != nil {
		return Abgelegt{}, err
	}
	for _, a := range m.items[r.ENV] {
		if a.Seq == r.Seq {
			return Abgelegt{}, fmt.Errorf("%w: env %s seq %d", ErrSchonVorhanden, r.ENV, r.Seq)
		}
	}
	if _, err := m.Anker(r.ENV); err != nil {
		return Abgelegt{}, err
	}
	m.n++
	a := Abgelegt{
		DocID:   fmt.Sprintf("doc-%03d", m.n),
		ENV:     r.ENV,
		Seq:     r.Seq,
		Digest:  r.Digest(),
		TakenAt: r.TakenAt.UTC(),
	}
	m.items[r.ENV] = append(m.items[r.ENV], a)
	return a, nil
}

func (m *MemStore) Liste(env string) ([]Abgelegt, error) {
	out := append([]Abgelegt(nil), m.items[env]...)
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out, nil
}

// NaechsteSeq macht den MemStore zu einer SeqQuelle: die Nummer kommt aus der
// Ablage und nicht aus der Erhebung, damit eine Luecke etwas bedeutet.
func (m *MemStore) NaechsteSeq(env string) (int, error) {
	hoechste := 0
	for _, a := range m.items[env] {
		if a.Seq > hoechste {
			hoechste = a.Seq
		}
	}
	return hoechste + 1, nil
}

// Luecken nennt die fehlenden Nummern einer Umgebung (AC-07).
func Luecken(s Store, env string, geloescht map[int]bool) ([]int, error) {
	items, err := s.Liste(env)
	if err != nil {
		return nil, err
	}
	seqs := make([]int, 0, len(items))
	for _, a := range items {
		seqs = append(seqs, a.Seq)
	}
	return FehlendeSeq(seqs, geloescht), nil
}

// er1store.go: die ER1-Ablage (SPEC-0428 T-03, Teil 2).
//
// Der einzige Teil dieses Pakets, der etwas sendet. Er benutzt denselben
// Upload-Pfad wie die Registry (SPEC-0225) und erfindet keinen zweiten
// Transport; die Marken liegen NEBEN der Registry-Familie, nicht in ihr.
//
// Vor jedem Netzaufruf laeuft PruefeAblage. Eine Grenze, die erst der Server
// durchsetzt, ist keine Grenze der Maschine, und dieses Paket verspricht die
// der Maschine.
package envreport

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Uploader ist der Netzschreibpfad, herausgezogen, damit die Ablage ohne
// Netz und ohne Zugangsdaten pruefbar bleibt. Die Registry liefert die
// echte Umsetzung.
type Uploader interface {
	UploadText(body, filename, tags, contentType, contextID string) (string, error)
}

// Lister liest die vorhandenen Posten einer Umgebung zurueck. Getrennt vom
// Uploader, weil Lesen und Schreiben verschiedene Rechte sind.
type Lister interface {
	ListByTags(contextID string, tags []string) ([]RohPosten, error)
}

// RohPosten ist ein ER1-Posten, so weit dieses Paket ihn braucht.
type RohPosten struct {
	DocID string
	Tags  []string
}

// ER1Store legt Berichte als ER1-Posten ab.
type ER1Store struct {
	ContextID string
	Up        Uploader
	Ls        Lister
	// Jetzt ist injizierbar, damit die Einwilligungspruefung testbar bleibt.
	Jetzt func() time.Time
}

func (s *ER1Store) jetzt() time.Time {
	if s.Jetzt != nil {
		return s.Jetzt()
	}
	return time.Now().UTC()
}

// Anker liefert den Anker-Posten einer Umgebung und legt ihn bei Bedarf an.
// Der Anker traegt keine Messwerte, nur die Identitaet der Umgebung: er ist
// der Aufhaengepunkt, an dem die Zeitreihe haengt (SPEC-0199 link/parent).
func (s *ER1Store) Anker(env string) (string, error) {
	if s.ContextID == "" {
		return "", errors.New("ER1Store: ContextID required")
	}
	ankerTags := []string{"skill-env-anchor", "env:" + strings.TrimPrefix(env, Prefix)}
	if s.Ls != nil {
		vorhanden, err := s.Ls.ListByTags(s.ContextID, ankerTags)
		if err != nil {
			return "", fmt.Errorf("anchor lookup: %w", err)
		}
		if len(vorhanden) > 0 {
			return vorhanden[0].DocID, nil
		}
	}
	if s.Up == nil {
		return "", errors.New("ER1Store: Uploader required to create an anchor")
	}
	body := fmt.Sprintf("# Skill-Env-Anker\n\nUmgebung: %s\nAngelegt: %s\n\n"+
		"Dieser Posten traegt keine Messwerte. Er ist der Aufhaengepunkt der\n"+
		"Berichte dieser Umgebung (SPEC-0428 E3, SPEC-0199).\n",
		env, s.jetzt().Format(time.RFC3339))
	sort.Strings(ankerTags)
	return s.Up.UploadText(body, "skill-env-anchor.md", strings.Join(ankerTags, ","), "text/markdown", s.ContextID)
}

// Ablegen schreibt einen Bericht nach ER1. Anhaengend: existiert die (env, seq)
// schon, wird abgelehnt und NICHT ueberschrieben (AC-06).
func (s *ER1Store) Ablegen(r Report, e Einwilligung) (Abgelegt, error) {
	if s.ContextID == "" {
		return Abgelegt{}, errors.New("ER1Store: ContextID required")
	}
	if s.Up == nil {
		return Abgelegt{}, errors.New("ER1Store: Uploader required")
	}
	// Die Grenzen laufen VOR dem Netzaufruf.
	if err := PruefeAblage(r, e, s.jetzt()); err != nil {
		return Abgelegt{}, err
	}
	// Anhaengend: erst nachsehen, dann schreiben.
	vorhanden, err := s.Liste(r.ENV)
	if err != nil {
		return Abgelegt{}, err
	}
	for _, a := range vorhanden {
		if a.Seq == r.Seq {
			return Abgelegt{}, fmt.Errorf("%w: env %s seq %d (doc %s)",
				ErrSchonVorhanden, r.ENV, r.Seq, a.DocID)
		}
	}
	ankerID, err := s.Anker(r.ENV)
	if err != nil {
		return Abgelegt{}, err
	}
	rumpf, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return Abgelegt{}, fmt.Errorf("render report: %w", err)
	}
	tags := Marken(r, s.ContextID, ankerID)
	docID, err := s.Up.UploadText(string(rumpf),
		fmt.Sprintf("skill-env-report-%d.json", r.Seq),
		strings.Join(tags, ","), "application/json", s.ContextID)
	if err != nil {
		return Abgelegt{}, fmt.Errorf("upload report: %w", err)
	}
	return Abgelegt{DocID: docID, ENV: r.ENV, Seq: r.Seq, Digest: r.Digest(), TakenAt: r.TakenAt.UTC()}, nil
}

// Liste nennt die abgelegten Berichte EINER Umgebung. Ueber Umgebungen hinweg
// liest dieser Store nicht (Grenze 5).
func (s *ER1Store) Liste(env string) ([]Abgelegt, error) {
	if s.Ls == nil {
		return nil, nil
	}
	posten, err := s.Ls.ListByTags(s.ContextID, []string{
		"skill-env-report", "env:" + strings.TrimPrefix(env, Prefix),
	})
	if err != nil {
		return nil, err
	}
	out := make([]Abgelegt, 0, len(posten))
	for _, p := range posten {
		a := Abgelegt{DocID: p.DocID, ENV: env}
		for _, t := range p.Tags {
			switch {
			case strings.HasPrefix(t, "report-seq:"):
				// Eine unlesbare Nummer bleibt 0 und faellt damit als Luecke
				// auf, statt still als gueltige Nummer durchzugehen.
				if n, err := strconv.Atoi(strings.TrimPrefix(t, "report-seq:")); err == nil {
					a.Seq = n
				}
			case strings.HasPrefix(t, "report-digest:"):
				a.Digest = strings.TrimPrefix(t, "report-digest:")
			case strings.HasPrefix(t, "taken-at:"):
				if d, err := time.Parse("2006-01-02", strings.TrimPrefix(t, "taken-at:")); err == nil {
					a.TakenAt = d
				}
			}
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out, nil
}

// NaechsteSeq macht den ER1Store zur SeqQuelle.
func (s *ER1Store) NaechsteSeq(env string) (int, error) {
	vorhanden, err := s.Liste(env)
	if err != nil {
		return 0, err
	}
	hoechste := 0
	for _, a := range vorhanden {
		if a.Seq > hoechste {
			hoechste = a.Seq
		}
	}
	return hoechste + 1, nil
}

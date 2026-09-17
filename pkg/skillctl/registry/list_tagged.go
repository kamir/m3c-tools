// list_tagged.go: eine generische Tag-Abfrage ueber einen ER1-Kontext.
//
// Warum exportiert und warum hier: die Leseseite (searchByTagsRaw, itemTags,
// er1Get) liegt in diesem Paket und ist auf SPEC-0225 P5 abgestimmt, bis hin
// zum 64-MiB-Deckel und dem Fail-Open bei 404. Ein zweiter Leser anderswo
// waere eine zweite Wahrheit ueber dieselbe Schnittstelle.
//
// Der einzige Aufrufer heute ist die Ablage der Skill-Env-Reports
// (SPEC-0428 T-03), die eine Tag-Abfrage braucht, aber KEINE Buendelsemantik:
// ihre Posten sind keine `m3c-skill-bundle`-Ereignisse und haben weder Digest
// noch Version im Sinne der Registry.
package registry

import (
	"errors"
	"fmt"

	"github.com/kamir/m3c-tools/pkg/er1"
)

var errNoTags = errors.New("ListItemsByTags: at least one tag required; an unfiltered query over a personal-data context is almost always a mistake")

// TaggedItem ist ein ER1-Posten, reduziert auf das, was ein Aufrufer ohne
// Buendelsemantik braucht.
type TaggedItem struct {
	DocID string
	Tags  []string
}

// ListItemsByTags liefert die Posten eines Kontexts, die ALLE genannten Marken
// tragen. Die Filterung geschieht clientseitig (SPEC-0225 P5: prod ER1 hat
// keine tag-gefilterte Route, die X-API-KEY akzeptiert).
//
// Ein leeres tags-Argument wird abgelehnt statt als "alles" gedeutet: eine
// Abfrage ohne Filter ueber einen Kontext mit Personendaten ist fast immer ein
// Versehen, und die harmlose Deutung waere hier die gefaehrliche.
func ListItemsByTags(cfg *er1.Config, ctxID string, tags []string) ([]TaggedItem, error) {
	if len(tags) == 0 {
		return nil, errNoTags
	}
	raw, err := searchByTagsRaw(cfg, ctxID, tags)
	if err != nil {
		return nil, err
	}
	out := make([]TaggedItem, 0, len(raw))
	for _, it := range raw {
		id, _ := it["id"].(string)
		if id == "" {
			id, _ = it["doc_id"].(string)
		}
		if id == "" {
			continue
		}
		out = append(out, TaggedItem{DocID: id, Tags: itemTags(it)})
	}
	return out, nil
}

// UploadTextItem legt einen Textposten in einem ER1-Kontext ab.
//
// Duennes Gegenstueck zu ListItemsByTags und aus demselben Grund hier: der
// Upload-Pfad (uploadText) ist auf diesen Server abgestimmt, und ein zweiter
// Uploader anderswo waere eine zweite Wahrheit ueber dieselbe Schnittstelle.
//
// Der Kontext ist Pflicht und wird NICHT aus der Konfiguration ergaenzt:
// uploadText lehnt einen leeren Kontext ausdruecklich ab, damit ein Posten
// nicht versehentlich im persoenlichen Vorgabekontext landet (SPEC-0225 P5).
func UploadTextItem(cfg *er1.Config, body, filename, tags, contentType, ctxID string) (string, error) {
	return uploadText(cfg, body, filename, tags, contentType, ctxID)
}

// LoadItemBody holt den Rumpf EINES Postens.
//
// Getrennt von ListItemsByTags, weil Zaehlen und Nachpruefen verschiedene
// Kosten haben: die Liste laeuft oft und traegt nur Marken, der Rumpf nur
// dann, wenn jemand etwas belegen will.
func LoadItemBody(cfg *er1.Config, ctxID, docID string) (string, error) {
	if ctxID == "" || docID == "" {
		return "", errNoTags
	}
	raw, err := searchByTagsRaw(cfg, ctxID, nil)
	if err != nil {
		return "", err
	}
	for _, it := range raw {
		id, _ := it["id"].(string)
		if id == "" {
			id, _ = it["doc_id"].(string)
		}
		if id != docID {
			continue
		}
		for _, k := range []string{"transcript", "description", "body"} {
			if v, ok := it[k].(string); ok && v != "" {
				return v, nil
			}
		}
		return "", fmt.Errorf("item %s has no readable body", docID)
	}
	return "", fmt.Errorf("item %s not found in %s", docID, ctxID)
}

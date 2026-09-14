// trust_installed_test.go: BUG-0253 B2 und B3.
//
// Beide Faelle sind Negativproben gegen den Zustand vor dem 2026-09-14:
// der Scanner suchte das Buendel an einer Stelle, an die kein Installierer
// schreibt, und verlangte eine Signatur, die kein Installationspfad erzeugt.
// Jeder Test hier ist ROT gegen das alte trust.go.
package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/model"
)

// legtSkillAn baut einen Skillordner so, wie ihn ein Installierer
// hinterlaesst: das Buendel INNEN, nicht daneben.
func legtSkillAn(t *testing.T, name string, mitBundle bool, abzug string) *model.SkillDescriptor {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "skills", name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: "+name+"\n---\nbody\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if mitBundle {
		// Genau so benennt install.go: <name>-<version>.skb, Modus 0600.
		if err := os.WriteFile(filepath.Join(dir, name+"-0.0.0.skb"), []byte("PK\x03\x04 fake bundle"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if abzug != "" {
		if err := os.WriteFile(filepath.Join(dir, abzug), []byte(`{"trust_roots_fp":"abc"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return &model.SkillDescriptor{
		Name:       name,
		Type:       model.SkillTypeClaudeCodeSkill,
		Tier:       "user",
		SourcePath: dir,
	}
}

// --- B2: der Scanner findet, was der Installierer ablegt -----------------

func TestB2_BuendelImSkillordnerWirdGefunden(t *testing.T) {
	sk := legtSkillAn(t, "rollback", true, "")
	ba := annotateSkillTrust(sk)
	if ba.SKBPath == "" {
		t.Fatal("das Buendel im Skillordner wurde nicht gefunden (BUG-0253 B2)")
	}
	if filepath.Dir(ba.SKBPath) != sk.SourcePath {
		t.Fatalf("gefunden an %s, erwartet im Skillordner %s", ba.SKBPath, sk.SourcePath)
	}
	if ba.TrustChain == TrustUnverified {
		t.Fatal("trotz gefundenem Buendel UNVERIFIED gemeldet")
	}
}

func TestB2_OhneBuendelBleibtUnverified(t *testing.T) {
	sk := legtSkillAn(t, "handgeschrieben", false, "")
	ba := annotateSkillTrust(sk)
	if ba.TrustChain != TrustUnverified {
		t.Fatalf("ohne jedes Buendel: %s, erwartet unverified", ba.TrustChain)
	}
}

// Das Geschwisterbuendel bleibt der staerkere Fundort: ist eines daneben,
// wird nicht in den Ordner geschaut.
func TestB2_GeschwisterHatVorrang(t *testing.T) {
	sk := legtSkillAn(t, "doppelt", true, "")
	neben := filepath.Join(filepath.Dir(sk.SourcePath), "doppelt@1.0.0.skb")
	if err := os.WriteFile(neben, []byte("PK\x03\x04 sibling"), 0o644); err != nil {
		t.Fatal(err)
	}
	ba := annotateSkillTrust(sk)
	if ba.SKBPath != neben {
		t.Fatalf("Geschwister nicht bevorzugt: %s", ba.SKBPath)
	}
}

// --- B3: der Provenance-Abzug traegt das Urteil --------------------------

func TestB3_AbzugErsetztDieFehlendeSignatur(t *testing.T) {
	// Ausgeschrieben statt provenanceNames referenziert: der Test soll auch
	// gegen den Stand VOR der Aenderung kompilieren, sonst belegt sein
	// Fehlschlag einen Uebersetzungsfehler und nicht das Verhalten.
	for _, abzug := range []string{".m3c-provenance.json", ".skillctl-attest.json", ".skillctl-offline.json"} {
		t.Run(abzug, func(t *testing.T) {
			sk := legtSkillAn(t, "getrustet", true, abzug)
			ba := annotateSkillTrust(sk)
			if ba.TrustChain != TrustSignaturePresent {
				t.Fatalf("mit %s: %s (%s), erwartet verified", abzug, ba.TrustChain, ba.VerifierError)
			}
			if !ba.Signed {
				t.Fatal("Signed=false trotz Abzug")
			}
			if ba.ProvenancePath == "" {
				t.Fatal("der Abzug wird nicht benannt; ein Leser kann die schwaechere Grundlage nicht erkennen")
			}
		})
	}
}

// Ohne beides bleibt es ein Fehler, und die Meldung nennt beide Wege.
func TestB3_OhneSignaturUndOhneAbzugIstBroken(t *testing.T) {
	sk := legtSkillAn(t, "nackt", true, "")
	ba := annotateSkillTrust(sk)
	if ba.TrustChain != TrustBroken {
		t.Fatalf("ohne Signatur und ohne Abzug: %s, erwartet broken", ba.TrustChain)
	}
	if ba.VerifierError == "" {
		t.Fatal("kein Grund genannt")
	}
}

// Ein leerer Abzug ist kein Abzug: sonst genuegte `touch`.
func TestB3_LeererAbzugZaehltNicht(t *testing.T) {
	sk := legtSkillAn(t, "leer", true, "")
	if err := os.WriteFile(filepath.Join(sk.SourcePath, ".m3c-provenance.json"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ba := annotateSkillTrust(sk)
	if ba.TrustChain == TrustSignaturePresent {
		t.Fatal("ein leerer Abzug wurde als Beleg akzeptiert")
	}
}

// Ein Verzeichnis mit dem Namen eines Abzugs zaehlt ebenfalls nicht.
func TestB3_VerzeichnisIstKeinAbzug(t *testing.T) {
	sk := legtSkillAn(t, "verzeichnis", true, "")
	if err := os.MkdirAll(filepath.Join(sk.SourcePath, ".m3c-provenance.json"), 0o750); err != nil {
		t.Fatal(err)
	}
	ba := annotateSkillTrust(sk)
	if ba.TrustChain == TrustSignaturePresent {
		t.Fatal("ein Verzeichnis wurde als Abzug akzeptiert")
	}
}

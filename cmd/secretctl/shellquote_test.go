package main

// Challenge-gate LOW-1 (PR #319): ssh fuegt seine Argumente zu EINEM String
// zusammen, den die entfernte Login-Shell auswertet. Jedes entfernte Argument
// wird deshalb quotiert; die eine gewollte Expansion ($HOME/, aus readFile)
// ueberlebt als unquotiertes Praefix. Und ein Schluessel, der zu einem
// grep-Muster wird, muss die Form eines Env-Namens haben.

import (
	"strings"
	"testing"
)

func TestShellQuoteMachtMetazeichenInert(t *testing.T) {
	for arg, want := range map[string]string{
		`a b`:        `'a b'`,
		`x;rm -rf /`: `'x;rm -rf /'`,
		`$(reboot)`:  `'$(reboot)'`,
		`it's`:       `'it'\''s'`,
	} {
		if got := shellQuote(arg); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", arg, got, want)
		}
	}
}

func TestShellQuoteRemoteLaesstNurHomeExpandieren(t *testing.T) {
	if got := shellQuoteRemote(`$HOME/.m3c-tools/er1.env`); got != `"$HOME"'/.m3c-tools/er1.env'` {
		t.Errorf("shellQuoteRemote($HOME-Pfad) = %q", got)
	}
	// Ein $HOME MITTEN im Argument expandiert nicht: es steht in Quotes.
	if got := shellQuoteRemote(`x/$HOME/y`); got != `'x/$HOME/y'` {
		t.Errorf("shellQuoteRemote(mittiges $HOME) = %q", got)
	}
}

func TestReadFileWeistRegexSchluesselAb(t *testing.T) {
	h := Holder{ID: "boese-datei", Kind: "file", Path: "/tmp/nope.env", Key: "A.*B|C"}
	_, err := readFile(h)
	if err == nil {
		t.Fatal("ein Regex-Schluessel wurde zu einem grep-Muster")
	}
	if !strings.Contains(err.Error(), "env-style") {
		t.Errorf("Meldung %q nennt die verlangte Form nicht", err)
	}
}

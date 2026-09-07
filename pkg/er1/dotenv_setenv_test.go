package er1

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A .env line whose VALUE carries a NUL byte cannot enter the process
// environment: os.Setenv rejects it (measured on darwin/arm64, Go stdlib:
// an empty key, a NUL in the key and a NUL in the VALUE all return
// "setenv: invalid argument"; a space in the key does not).
//
// That last case is the one with teeth, because the key beside it can be a
// SENSITIVE one. The NOTE this loader prints exists to name what an opted-in
// working-directory .env contributed, and the applied list it is built from
// used to be appended to without looking at whether the write had succeeded.
// So a hostile file could get ER1_API_URL named in a security notice while
// the process environment never received it: a false provenance line in the
// one output whose whole job is provenance.
//
// The list now follows the write. This test pins that, and it fails against
// the previous version at the second assertion, not the first.
func TestLoadDotenvSkipsValuesSetenvRejects(t *testing.T) {
	clearProbeVars(t)
	t.Setenv(EnvDotenvOptIn, "1")

	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	body := "ER1_API_URL=https://attacker.example/upload\x00truncated\n" +
		"M3C_PLM_BASE_URL=https://sound.example\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	loadErr := LoadDotenvUntrusted(path)
	os.Stderr = orig
	if cerr := w.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, rerr := r.Read(buf)
		sb.Write(buf[:n])
		if rerr != nil {
			break
		}
	}
	note := sb.String()
	if cerr := r.Close(); cerr != nil {
		t.Fatal(cerr)
	}

	if loadErr != nil {
		t.Fatalf("LoadDotenvUntrusted: %v", loadErr)
	}
	if got := os.Getenv("ER1_API_URL"); got != "" {
		t.Errorf("a value os.Setenv rejects still reached the environment: %q", got)
	}
	if strings.Contains(note, "ER1_API_URL") {
		t.Errorf("the NOTE names a key the process never received.\nNOTE: %s", note)
	}
	// The sound line beside it must still be applied and still be reported,
	// so the fix skips one line and not the file.
	if got := os.Getenv("M3C_PLM_BASE_URL"); got != "https://sound.example" {
		t.Errorf("the sound line was skipped too: M3C_PLM_BASE_URL=%q", got)
	}
	if !strings.Contains(note, "M3C_PLM_BASE_URL") {
		t.Errorf("the NOTE dropped a key that WAS applied.\nNOTE: %s", note)
	}
}

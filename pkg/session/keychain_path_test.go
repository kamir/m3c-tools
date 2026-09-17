package session

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHTTPGetJSONDoesNotExecPATHSecurity(t *testing.T) {
	t.Setenv("ER1_API_KEY", "")
	t.Setenv("ER1_DEVICE_TOKEN", "")
	t.Setenv("M3C_ER1_KEYCHAIN", "off")

	dir := t.TempDir()
	marker := filepath.Join(dir, "planted")
	script := filepath.Join(dir, "security")
	body := "#!/bin/sh\necho planted > \"" + marker + "\"\necho fake-key\n"
	if err := os.WriteFile(script, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	_, _ = httpGetJSON("http://127.0.0.1:1", "/nope")

	if _, err := os.Stat(marker); err == nil {
		t.Fatal("planted PATH security binary was executed")
	}
}

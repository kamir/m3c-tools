package config

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestApplyProfileQuotesUntrustedLogFields(t *testing.T) {
	key := "SYNTHETIC\nFORGED"
	t.Setenv(key, "synthetic-value")
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(previous) })
	manager := &ProfileManager{}
	if err := manager.ApplyProfile(&Profile{Name: "test\nFORGED", Vars: map[string]string{key: ""}}); err != nil {
		t.Fatal(err)
	}
	if strings.Count(output.String(), "\n") != 1 || strings.Contains(output.String(), "synthetic-value") {
		t.Fatalf("unsafe profile diagnostic: %q", output.String())
	}
}

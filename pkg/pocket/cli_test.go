package pocket

import "testing"

func TestCanonicalCLI_USBSync(t *testing.T) {
	got, ok := CanonicalCLI("usb-sync")
	if !ok {
		t.Fatal("usb-sync must be a recognised pocket subcommand")
	}
	if got != "sync" {
		t.Errorf("usb-sync canonical = %q, want sync", got)
	}
}

func TestCanonicalCLI_Unknown(t *testing.T) {
	if _, ok := CanonicalCLI("not-a-verb"); ok {
		t.Fatal("unknown verb must not be recognised")
	}
}

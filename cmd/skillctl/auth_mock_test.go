package main

import (
	"os"
	"testing"

	keyring "github.com/zalando/go-keyring"
)

// Install the process-wide in-memory provider before any test uses auth stores.
// Child product binaries do not inherit it; helper test processes initialize
// their own explicit mock before invoking the real main function.
func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Exit(m.Run())
}

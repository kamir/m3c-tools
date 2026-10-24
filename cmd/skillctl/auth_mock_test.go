package main

import (
	"os"
	"testing"

	keyring "github.com/zalando/go-keyring"
)

// Install the process-wide in-memory provider before any legacy test can call
// auth.Save, including its file-backend native Clear path. Child CLI processes
// do not inherit this test provider and must use separately isolated fixtures.
func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Exit(m.Run())
}

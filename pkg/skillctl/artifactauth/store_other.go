//go:build !darwin && !windows

package artifactauth

import "fmt"

// No protected credential store here. Store() checks HasProtectedStore first and
// returns a message naming the environment variable, so these two exist only to
// keep the package compiling on every platform.

func HasProtectedStore() bool { return false }

func ProtectedStoreName() string { return "none" }

func platformStore(service, account, secret string) error {
	return fmt.Errorf("artifactauth: no protected credential store on this platform")
}

func platformDelete(service, account string) error { return nil }

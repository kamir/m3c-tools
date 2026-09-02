//go:build !windows

package artifactauth

// osCredStore has no OS credential store on non-Windows platforms here: macOS
// resolves through the Keychain (creds.go:keychain, gated on runtime.GOOS), and
// Linux relies on the env override or ambient git credentials. Returning "" keeps
// the resolver's fail-soft-to-anonymous contract. The real Windows DPAPI store is
// in creds_windows.go (WIN-T6).
func osCredStore(service, account string) string { return "" }

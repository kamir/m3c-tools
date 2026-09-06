//go:build windows

package artifactauth

// On Windows the protected store is DPAPI, implemented in creds_windows.go. This
// file is only the dispatch the platform-neutral Store/Delete call.

func HasProtectedStore() bool { return true }

func ProtectedStoreName() string { return "Windows DPAPI (per user account)" }

func platformStore(service, account, secret string) error {
	return StoreCred(service, account, secret)
}

func platformDelete(service, account string) error {
	return DeleteCred(service, account)
}

package pocket

// CanonicalCLI maps a user-facing pocket verb to the dispatched verb.
// "usb-sync" is an alias of "sync": the menubar tells operators to run
// that name when cloud and USB are both available.
func CanonicalCLI(cmd string) (string, bool) {
	switch cmd {
	case "list", "sync", "api", "cloud-sync", "backfill", "mappings":
		return cmd, true
	case "usb-sync":
		return "sync", true
	default:
		return "", false
	}
}

package plaud

import "path/filepath"

// LocalSyncDir is ~/plaud-sync/<recID> after ValidateDocID, so a recording id
// cannot walk out of that directory.
func LocalSyncDir(home, recID string) (string, error) {
	if err := ValidateDocID(recID); err != nil {
		return "", err
	}
	return filepath.Join(home, "plaud-sync", recID), nil
}

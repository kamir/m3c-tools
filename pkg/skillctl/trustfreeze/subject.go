package trustfreeze

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// subjectDomain separates subject ids from every other SHA-256 in the tree.
const subjectDomain = "trust-freeze/subject/v1"

// SubjectID derives the stable subject id of a device (SPEC-0466):
//
//	"device/" + first 16 hex of sha256("trust-freeze/subject/v1" NUL osFamily NUL lower(hostname))
//
// The identity probe and the self-approval check (seal) both call this
// function, so a captured subject and an approver subject compare equal
// exactly when they are the same device. The hostname is lowercased and
// otherwise used as given; callers pass it the way os.Hostname returns it.
func SubjectID(osFamily, hostname string) string {
	h := sha256.Sum256([]byte(subjectDomain + "\x00" + osFamily + "\x00" + strings.ToLower(hostname)))
	return "device/" + hex.EncodeToString(h[:])[:16]
}

// BundleID returns a deterministic bundle id such as
// "tf-capture-20260102T030405.000000000Z-device-0123456789abcdef". It only
// labels a bundle; integrity comes from the content digest.
func BundleID(kind Kind, createdAt time.Time, subjectID string) string {
	return "tf-" + string(kind) + "-" + createdAt.UTC().Format("20060102T150405.000000000Z") +
		"-" + strings.ReplaceAll(subjectID, "/", "-")
}

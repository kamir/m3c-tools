package main

import "strings"

// normalizeIdentity canonicalises an identity id for the SPEC-0246 §5
// reviewer≠author comparison: trim surrounding whitespace and lowercase. The
// comparison must be robust to "id:Kamir@m3c" vs " id:kamir@m3c " representing
// the same principal across the admit record, the attestation, and the CLI
// flag — a self-attestation must NOT be launderable by re-casing the id.
func normalizeIdentity(id string) string {
	return strings.ToLower(strings.TrimSpace(id))
}

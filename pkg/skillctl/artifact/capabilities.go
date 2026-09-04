package artifact

// Capabilities is a backend's declarative statement of what it can do. Callers
// branch on these flags BEFORE offering a CLI flag or calling an optional
// sub-interface, never by probing a method and catching an error. The flag
// that mirrors an optional interface (ServerEventLog ⇔ GovernanceLog) MUST
// agree with the type assertion; that invariant is what the conformance suite
// checks.
type Capabilities struct {
	// Lifecycle events this backend can PUBLISH.
	CanAdmit   bool
	CanAttest  bool
	CanRevoke  bool
	CanInstall bool // emit BundleInstalledEvent

	// Read surfaces.
	ServerEventLog bool // full admit/attest/revoke/install timeline (⇔ GovernanceLog)
	Paginated      bool // List honours Page.Cursor (false => single-shot, NextCursor always "")
	HonoursSince   bool // ListFilter.Since applied server-side (else best-effort client filter)

	// Where the governance verdict comes from.
	Governance GovernanceSource

	// Explicit "latest" semantics: designs out the compareSemver guesswork.
	LatestPolicy LatestPolicy

	// ClaimCheck is true when the bundle blob is stored out-of-line (MinIO
	// claim-check / OCI blob / git Release asset) rather than inline.
	ClaimCheck bool
}

// GovernanceSource names where a backend's governance verdict is read from.
type GovernanceSource string

const (
	GovFromEventLog       GovernanceSource = "event-log"       // ER1: newest signed attest event
	GovServerComputed     GovernanceSource = "server-computed" // HTTP: BundleMeta.CurrentGovernance
	GovFromCosignReferrer GovernanceSource = "cosign-referrer" // OCI
	GovFromCodeowners     GovernanceSource = "codeowners"      // git (advisory; NOT the trust verdict)
	GovNone               GovernanceSource = "none"
)

// LatestPolicy names how a backend resolves RefQuery{Version:""} to a concrete
// version. The canonical portable rule is LatestSemverMax; ER1 ships
// LatestMostRecent until reconciled (SPEC-0356 P4).
type LatestPolicy string

const (
	LatestSemverMax   LatestPolicy = "semver-max"        // git tags, OCI version tags
	LatestMostRecent  LatestPolicy = "most-recent-admit" // ER1 today (occurred_at max)
	LatestTagMutable  LatestPolicy = "tag-mutable"       // OCI :latest points wherever
	LatestServerOrder LatestPolicy = "server-order"      // HTTP: server returns newest-first
	LatestUnsupported LatestPolicy = "unsupported"       // require an explicit @version / --digest
)

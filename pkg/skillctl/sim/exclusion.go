package sim

// exclusion.go separates two things that were one predicate, and the confusion
// between them was reported as a finding by an IEEE 1012 reviewer on 2026-09-05.
//
// The report told the reader that excluded factor combinations were "excluded by
// the model's own rules and are therefore not coverable, not missing". For some
// rules that is true: the world cannot produce them. For others it was false. They
// were dropped because the extra rows would not have taught anything new, which is
// an ECONOMY argument, and the same file elsewhere records that exactly this kind
// of pruning had once deleted the only point able to catch a gate-order regression.
//
// Reporting an economy cut as an impossibility is the more expensive of the two
// mistakes: it tells a reader that a region cannot exist when it merely was not
// visited. So the predicate now returns WHY, in two kinds, and the report counts
// and prints them apart.

// ExclusionKind distinguishes the two.
type ExclusionKind string

const (
	// KindImpossible: the world cannot produce this point. A move needs a
	// precondition that the point denies.
	KindImpossible ExclusionKind = "impossible"
	// KindEconomy: the world can produce it; the corpus leaves it out because it is
	// expected to add rows without adding statements. This is a judgement and it can
	// be wrong, so it is reported as a judgement.
	KindEconomy ExclusionKind = "economy"
)

// Exclusion says why a point is not in the corpus.
type Exclusion struct {
	Rule string
	Kind ExclusionKind
	Why  string
}

// excludedBy returns nil when the point belongs in the corpus.
func excludedBy(p Params) *Exclusion {
	if (p.Adv == AdvStripRevoke || p.Adv == AdvRelabelRevoke) && !p.Revoke {
		return &Exclusion{"revoke-suppression needs a revoke", KindImpossible,
			"the move edits a revoke event; without one there is nothing to edit"}
	}
	if p.Adv == AdvTamperInstalled && p.Gov != GovGreen {
		return &Exclusion{"post-install tamper needs an install", KindImpossible,
			"the move edits installed files; without governance nothing installs"}
	}
	if p.Adv == AdvStolenKey && p.Gov == GovNone {
		return &Exclusion{"stolen key without governance", KindEconomy,
			"the pull fails at governance first, so the stolen key changes no outcome"}
	}
	if p.Adv == AdvForgeEnvelope && (p.Gov != GovGreen || p.Key != KeySeparatePin) {
		return &Exclusion{"envelope forgery pinned to green and pinned", KindEconomy,
			"gate 1 decides first, so the other axes cannot change the outcome"}
	}
	if (p.Adv == AdvTransitChecked || p.Adv == AdvTransitSkipped) && p.Gov != GovGreen {
		return &Exclusion{"transit attacks pinned to green", KindEconomy,
			"the governance axis adds no distinct outcome for these moves"}
	}
	if p.Key == KeyShared && p.Cast != CastSolo && p.Adv != AdvNone {
		return &Exclusion{"shared key collapses duo and trio onto solo", KindImpossible,
			"with one key there is no second key holder to distinguish the casts"}
	}
	return nil
}

// meaningful keeps its old name and meaning for every caller.
func meaningful(p Params) bool { return excludedBy(p) == nil }

// ExclusionCensus counts the factor space by admissibility class.
type ExclusionCensus struct {
	Total      int
	Admissible int
	Impossible int
	Economy    int
	ByRule     map[string]int
}

// Census walks the whole factor space and classifies every point.
func Census() ExclusionCensus {
	c := ExclusionCensus{ByRule: map[string]int{}}
	for _, p := range allParams() {
		c.Total++
		ex := excludedBy(p)
		switch {
		case ex == nil:
			c.Admissible++
		case ex.Kind == KindImpossible:
			c.Impossible++
			c.ByRule[ex.Rule]++
		default:
			c.Economy++
			c.ByRule[ex.Rule]++
		}
	}
	return c
}

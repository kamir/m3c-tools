package govlevel

import "testing"

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"green": "green", "GREEN": "green", "Green": "green",
		" green ": "green", "\tYellow\n": "yellow", "RED": "red", "": "",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

// ValidFloor is the SEC-L1 guard: a valid floor is exactly {green, yellow},
// case/whitespace-insensitive. "red"/unknown are rejected REGARDLESS of case —
// the property the two trust-root loaders previously spelled separately.
func TestValidFloor(t *testing.T) {
	accept := map[string]string{
		"green": "green", "GREEN": "green", " Green ": "green",
		"yellow": "yellow", "YELLOW": "yellow", "\tyellow": "yellow",
	}
	for in, want := range accept {
		n, ok := ValidFloor(in)
		if !ok || n != want {
			t.Errorf("ValidFloor(%q) = (%q,%v), want (%q,true)", in, n, ok, want)
		}
	}
	// red (any case/space) and unknown values must be rejected — a red floor
	// would admit everything; a typo must fail loudly.
	for _, in := range []string{"red", "RED", "Red", " red ", "", "greenish", "amber", "0"} {
		if _, ok := ValidFloor(in); ok {
			t.Errorf("ValidFloor(%q) accepted; must reject (red/unknown is not a valid floor)", in)
		}
	}
}

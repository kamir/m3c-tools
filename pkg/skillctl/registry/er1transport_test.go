package registry

import "testing"

func TestIsER1Registry(t *testing.T) {
	cases := []struct {
		spec string
		want bool
	}{
		{"self", true},
		{"er1://prod/skills", true},
		{"er1://", true},
		{"", false},
		{"http://localhost:8080/api/skills", false},
		{"https://kup.onboarding.guide/api/skills", false},
		{"selfish", false},   // must not prefix-match "self"
		{"SELF", false},      // case-sensitive
		{"er1:/prod", false}, // not the scheme
	}
	for _, c := range cases {
		if got := IsER1Registry(c.spec); got != c.want {
			t.Errorf("IsER1Registry(%q) = %v, want %v", c.spec, got, c.want)
		}
	}
}

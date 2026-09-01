package registry

import (
	"errors"
	"testing"
)

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
		{"selfish", false},  // must not prefix-match "self"
		{"SELF", false},     // case-sensitive
		{"er1:/prod", false}, // not the scheme
	}
	for _, c := range cases {
		if got := IsER1Registry(c.spec); got != c.want {
			t.Errorf("IsER1Registry(%q) = %v, want %v", c.spec, got, c.want)
		}
	}
}

func TestER1TransportStubReturnsNotImplemented(t *testing.T) {
	tr := NewER1Transport(ER1RegistrySelf)
	if tr == nil {
		t.Fatal("NewER1Transport returned nil")
	}
	if tr.Spec != "self" {
		t.Errorf("Spec = %q, want %q", tr.Spec, "self")
	}
	for name, fn := range map[string]func() error{
		"Publish": tr.Publish,
		"Pull":    tr.Pull,
		"List":    tr.List,
		"Get":     tr.Get,
		"Revoke":  tr.Revoke,
	} {
		if err := fn(); !errors.Is(err, ErrNotImplemented) {
			t.Errorf("%s() = %v, want ErrNotImplemented", name, err)
		}
	}
}

func TestER1TransportString(t *testing.T) {
	if got := NewER1Transport("self").String(); got != "er1-transport(self)" {
		t.Errorf("String() = %q, want %q", got, "er1-transport(self)")
	}
	var nilT *ER1Transport
	if got := nilT.String(); got != "er1-transport(<nil>)" {
		t.Errorf("nil String() = %q, want %q", got, "er1-transport(<nil>)")
	}
}

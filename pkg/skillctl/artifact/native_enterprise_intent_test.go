package artifact

import (
	"errors"
	"strings"
	"testing"
)

func TestNativeEnterpriseIntentDenials(t *testing.T) {
	intent, e := NewNativeEnterpriseIntent(strings.Repeat("a", 64), strings.Repeat("b", 64))
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	Register("native-denial-oracle", func(_ string, _ OpenOptions) (Backend, error) { calls++; return &fakeBackend{}, nil })
	defer delete(drivers, "native-denial-oracle")
	if _, e = Open("native-denial-oracle://selected", OpenOptions{}); e != nil || calls != 1 {
		t.Fatal("legacy positive control", e)
	}
	for _, selected := range []*NativeEnterpriseIntent{intent, {}} {
		if e = RejectNativeEnterpriseMutation(selected); !errors.Is(e, ErrNativeMutationUnavailable) {
			t.Fatal("intent granted mutation", e)
		}
		if _, e = Open("native-denial-oracle://selected", OpenOptions{NativeEnterpriseIntent: selected}); !errors.Is(e, ErrNativeMutationUnavailable) || calls != 1 {
			t.Fatal("selected intent reached backend", e)
		}
		if _, e = Open("unsupported://invalid", OpenOptions{NativeEnterpriseIntent: selected}); !errors.Is(e, ErrNativeMutationUnavailable) {
			t.Fatal("guard not before driver selection", e)
		}
	}
	if RejectNativeEnterpriseMutation(nil) != nil {
		t.Fatal("legacy nil contract changed")
	}
	for _, bad := range []string{"", strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("x", 1<<20)} {
		if _, e = NewNativeEnterpriseIntent(bad, strings.Repeat("b", 64)); e == nil {
			t.Fatal("invalid selection identity accepted")
		}
	}
}

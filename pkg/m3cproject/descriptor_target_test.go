package m3cproject

import "testing"

func TestDescriptorTargetPreservesURLPathCase(t *testing.T) {
	var d Descriptor
	for _, tc := range []struct{ in, want string }{
		{" HTTPS://EXAMPLE.COM/TenantA ", "HTTPS://EXAMPLE.COM/TenantA"},
		{" LOCAL ", "local"}, {"", "prod"},
	} {
		d.ER1.Target = tc.in
		if got := d.EffectiveER1Target(); got != tc.want {
			t.Fatalf("target=%q want=%q", got, tc.want)
		}
	}
}

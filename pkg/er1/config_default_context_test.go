package er1

import "testing"

const formerDefaultContextID = "107677460544181387647___mft"

func TestLoadConfig_NoDefaultTenant(t *testing.T) {
	t.Setenv("ER1_CONTEXT_ID", "")
	t.Setenv("ER1_API_KEY", "")
	t.Setenv("ER1_DEVICE_TOKEN", "")
	t.Setenv("M3C_ER1_KEYCHAIN", "off")

	cfg := LoadConfig()
	if cfg.ContextID == formerDefaultContextID {
		t.Fatalf("LoadConfig defaulted ContextID to a tenant id")
	}
	if cfg.ContextID != "" {
		t.Errorf("ContextID = %q, want empty when ER1_CONTEXT_ID is unset", cfg.ContextID)
	}
}

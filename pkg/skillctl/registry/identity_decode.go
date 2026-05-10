package registry

import "encoding/json"

// UnmarshalJSON allows the wire format to spell the public-key field as
// either `pubkey_b64` (S5 brief) or `pubkey` (older skill_registry
// models). Whichever lands, the canonical Go field is PubkeyB64.
//
// We use an alias type to avoid infinite recursion, then layer the
// flexible field name on top.
func (i *Identity) UnmarshalJSON(data []byte) error {
	type alias Identity
	tmp := struct {
		*alias
		PubkeyAlt string `json:"pubkey"`
	}{alias: (*alias)(i)}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}
	if i.PubkeyB64 == "" && tmp.PubkeyAlt != "" {
		i.PubkeyB64 = tmp.PubkeyAlt
	}
	return nil
}

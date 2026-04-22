package schema

import (
	"encoding/json"
	"errors"
)

// MarshalJSON encodes Content as either a plain string (inline text)
// or an object {"ref":"..."}. Exactly mirrors the oneOf in T.schema.json.
func (c Content) MarshalJSON() ([]byte, error) {
	if c.Ref != "" && c.Text != "" {
		return nil, errors.New("schema.Content: cannot set both Text and Ref")
	}
	if c.Ref != "" {
		return json.Marshal(struct {
			Ref string `json:"ref"`
		}{Ref: c.Ref})
	}
	return json.Marshal(c.Text)
}

// UnmarshalJSON decodes either a JSON string or an object {"ref":"..."}.
func (c *Content) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		c.Text = s
		return nil
	}
	var obj struct {
		Ref string `json:"ref"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}
	if obj.Ref == "" {
		return errors.New("schema.Content: object form must have non-empty ref")
	}
	c.Ref = obj.Ref
	return nil
}

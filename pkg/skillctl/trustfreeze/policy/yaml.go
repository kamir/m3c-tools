package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// maxYAMLDepth bounds the nesting of a YAML policy.
const maxYAMLDepth = 32

// yamlToJSON converts one YAML document into JSON, so a YAML policy goes
// through the same strict JSON decoder as a JSON policy. Only mappings with
// string keys, sequences, strings, booleans, integers and null are accepted;
// floats, timestamps, binary values, anchors, aliases, merge keys, duplicate
// keys and further documents are errors.
func yamlToJSON(b []byte) ([]byte, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("yaml: empty document")
		}
		return nil, fmt.Errorf("yaml: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("yaml: more than one document")
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, errors.New("yaml: expected a single document")
	}
	v, err := yamlValue(doc.Content[0], 0)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

func yamlValue(n *yaml.Node, depth int) (any, error) {
	if depth > maxYAMLDepth {
		return nil, fmt.Errorf("yaml: nesting deeper than %d at line %d", maxYAMLDepth, n.Line)
	}
	if n.Anchor != "" {
		return nil, fmt.Errorf("yaml: anchors are not allowed (line %d)", n.Line)
	}
	switch n.Kind {
	case yaml.MappingNode:
		out := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" {
				return nil, fmt.Errorf("yaml: mapping key at line %d is not a plain string", k.Line)
			}
			if _, dup := out[k.Value]; dup {
				return nil, fmt.Errorf("yaml: duplicate key %q at line %d", k.Value, k.Line)
			}
			val, err := yamlValue(v, depth+1)
			if err != nil {
				return nil, err
			}
			out[k.Value] = val
		}
		return out, nil
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			val, err := yamlValue(c, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, val)
		}
		return out, nil
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!str":
			return n.Value, nil
		case "!!null":
			return nil, nil
		case "!!bool":
			var v bool
			if err := n.Decode(&v); err != nil {
				return nil, fmt.Errorf("yaml: line %d: %w", n.Line, err)
			}
			return v, nil
		case "!!int":
			var v int64
			if err := n.Decode(&v); err != nil {
				return nil, fmt.Errorf("yaml: line %d: %w", n.Line, err)
			}
			return v, nil
		}
		return nil, fmt.Errorf("yaml: value of type %s at line %d is not allowed", n.Tag, n.Line)
	case yaml.AliasNode:
		return nil, fmt.Errorf("yaml: aliases are not allowed (line %d)", n.Line)
	}
	return nil, fmt.Errorf("yaml: unexpected node at line %d", n.Line)
}

package report

// YAML rendering of the report (FR-0472). The bytes come from the canonical
// JSON of Marshal and from nothing else: the JSON token stream is turned into
// an ordered yaml.Node tree and emitted. There is deliberately no second set
// of yaml struct tags, because two sets of tags can drift apart and then
// nobody knows which of the two renderings carries the older statement.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"

	"gopkg.in/yaml.v3"
)

// MarshalYAML returns the report as YAML with two-space indentation, the same
// fields, the same values and the same order as Marshal, and one trailing
// newline. It projects nothing of its own: it converts the canonical JSON.
func MarshalYAML(r Report) ([]byte, error) {
	raw, err := Marshal(r)
	if err != nil {
		return nil, err
	}
	return yamlFromCanonicalJSON(raw)
}

// yamlFromCanonicalJSON converts one canonical JSON document into YAML. It
// reads the token stream, so the document order of the JSON is the document
// order of the YAML.
func yamlFromCanonicalJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	root, err := yamlNextValue(dec)
	if err != nil {
		return nil, fmt.Errorf("report: yaml: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("report: yaml: trailing data after the document")
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{root}}); err != nil {
		return nil, fmt.Errorf("report: yaml: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("report: yaml: %w", err)
	}
	return buf.Bytes(), nil
}

// yamlNextValue reads the next JSON value from the stream as a yaml.Node.
func yamlNextValue(dec *json.Decoder) (*yaml.Node, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	return yamlFromToken(dec, tok)
}

func yamlFromToken(dec *json.Decoder, tok json.Token) (*yaml.Node, error) {
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			return yamlMapping(dec)
		case '[':
			return yamlSequence(dec)
		}
		return nil, fmt.Errorf("unexpected delimiter %q", t)
	case string:
		return yamlString(t), nil
	case json.Number:
		return yamlNumber(t)
	case bool:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(t)}, nil
	case nil:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}, nil
	}
	return nil, fmt.Errorf("unexpected token %v of type %T", tok, tok)
}

// yamlMapping reads the rest of a JSON object, key by key in document order.
func yamlMapping(dec *json.Decoder) (*yaml.Node, error) {
	node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, ok := key.(string)
		if !ok {
			return nil, fmt.Errorf("object key %v is not a string", key)
		}
		value, err := yamlNextValue(dec)
		if err != nil {
			return nil, err
		}
		node.Content = append(node.Content, yamlString(name), value)
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return nil, err
	}
	return node, nil
}

// yamlSequence reads the rest of a JSON array.
func yamlSequence(dec *json.Decoder) (*yaml.Node, error) {
	node := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for dec.More() {
		value, err := yamlNextValue(dec)
		if err != nil {
			return nil, err
		}
		node.Content = append(node.Content, value)
	}
	if _, err := dec.Token(); err != nil { // the closing bracket
		return nil, err
	}
	return node, nil
}

// yamlNumber renders a JSON number. The canonical form of a report has no
// floating-point number (see canonical.go), so a number that is not an
// integer is refused instead of being rendered as one.
func yamlNumber(n json.Number) (*yaml.Node, error) {
	if _, err := strconv.ParseInt(n.String(), 10, 64); err != nil {
		return nil, fmt.Errorf("number %s is not an integer", n)
	}
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: n.String()}, nil
}

// yamlString renders a JSON string as a YAML string scalar, quoted where a
// plain scalar would be read as something else (see yamlNeedsQuotes).
func yamlString(s string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s}
	if yamlNeedsQuotes(s) {
		n.Style = yaml.DoubleQuotedStyle
	}
	return n
}

// yaml11Words are the plain scalars that yaml.v3 writes unquoted because its
// own resolver follows the YAML 1.2 core schema, while a reader of YAML 1.1
// (PyYAML, yaml.v2, Ruby Psych) resolves them as a boolean, as a merge key or
// as the default-value key. Measured against yaml.v3 v3.0.1: each of these
// comes out of the encoder as a bare word. In a freeze they are not edge
// cases: an sshd directive reads "PasswordAuthentication no", and "no" is the
// attribute value that carries it.
var yaml11Words = map[string]bool{
	"y": true, "Y": true, "yes": true, "Yes": true, "YES": true,
	"n": true, "N": true, "no": true, "No": true, "NO": true,
	"true": true, "True": true, "TRUE": true,
	"false": true, "False": true, "FALSE": true,
	"on": true, "On": true, "ON": true,
	"off": true, "Off": true, "OFF": true,
	"<<": true, "=": true,
}

// yaml11Sexagesimal matches the YAML 1.1 base-60 integer and float forms. A
// 1.1 reader turns 1:30 into 90, and a time value in a host configuration can
// look exactly like that.
var yaml11Sexagesimal = regexp.MustCompile(`^[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+(?:\.[0-9_]*)?$`)

// yaml11Numeric matches the YAML 1.1 integer forms that its 1.2 successor does
// not resolve: digits with an underscore separator, and a leading-zero octal.
var yaml11Numeric = regexp.MustCompile(`^[-+]?(?:0[0-7_]+|[0-9][0-9_]*_[0-9_]*)$`)

// yamlNeedsQuotes reports whether a string scalar must be quoted although
// yaml.v3 would leave it plain. It only ever adds quotes: the value is
// unchanged either way, and a quoted scalar is a string for every reader.
func yamlNeedsQuotes(s string) bool {
	return yaml11Words[s] || yaml11Sexagesimal.MatchString(s) || yaml11Numeric.MatchString(s)
}

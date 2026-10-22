package skillbundle

import "strings"

// RuntimeDependencyStatus describes declaration assessment, not availability.
type RuntimeDependencyStatus string

const (
	RuntimeDependenciesNone       RuntimeDependencyStatus = "none"
	RuntimeDependenciesUnresolved RuntimeDependencyStatus = "unresolved"
	RuntimeDependenciesInvalid    RuntimeDependencyStatus = "invalid"
)

// RuntimeDeclarationAssessment covers only depends_on, never data_dependencies.
// No status asserts resolution, signature verification, or an audited override.
type RuntimeDeclarationAssessment struct {
	Schema       string                  `json:"schema"`
	Scope        string                  `json:"scope"`
	KindCatalog  string                  `json:"kind_catalog"`
	Status       RuntimeDependencyStatus `json:"status"`
	Declarations []Dependency            `json:"declarations"`
	Reason       string                  `json:"reason,omitempty"`
	Source       string                  `json:"source"`
	Digest       string                  `json:"digest,omitempty"`
}

// AssessRuntimeDeclarations validates a manifest projection without authenticating
// it. Callers must bind and authenticate its source separately. The versioned kind
// catalog is python/system/skill/agent; no resolver runs for any of these kinds.
func AssessRuntimeDeclarations(manifest map[string]any) RuntimeDeclarationAssessment {
	out := RuntimeDeclarationAssessment{
		Schema:       "m3c.skillctl.runtime-declaration-assessment/v1",
		Scope:        "runtime_dependencies",
		KindCatalog:  "m3c.skillctl.runtime-kinds/v1",
		Status:       RuntimeDependenciesInvalid,
		Declarations: []Dependency{},
		Source:       "manifest_projection",
	}
	invalid := func(reason string) RuntimeDeclarationAssessment {
		out.Status, out.Reason = RuntimeDependenciesInvalid, reason
		return out
	}
	if manifest == nil {
		return invalid("manifest_missing")
	}
	// This implementation has one wire field. Do not silently read an unsupported
	// alias as an empty declaration or choose between conflicting field names.
	if hasRuntimeFieldAlias(manifest, "depends_on", "package_dependencies") {
		return invalid("dependency_field_alias")
	}
	if _, present := manifest["package_dependencies"]; present {
		return invalid("unsupported_dependency_field")
	}
	raw, present := manifest["depends_on"]
	if !present || raw == nil {
		out.Status = RuntimeDependenciesNone
		return out
	}
	list, ok := raw.([]any)
	if !ok {
		return invalid("depends_on_not_list")
	}
	seen := make(map[[2]string]bool)
	for _, entry := range list {
		object, ok := entry.(map[string]any)
		if !ok {
			return invalid("dependency_not_object")
		}
		if hasRuntimeFieldAlias(object, "kind", "name", "constraint") {
			return invalid("dependency_entry_field_alias")
		}
		kind, ok := object["kind"].(string)
		if !ok || strings.TrimSpace(kind) == "" {
			return invalid("dependency_kind_invalid")
		}
		switch kind {
		case "python", "system", "skill", "agent":
		default:
			return invalid("dependency_kind_unsupported")
		}
		name, ok := object["name"].(string)
		if !ok || strings.TrimSpace(name) == "" || name != strings.TrimSpace(name) {
			return invalid("dependency_name_invalid")
		}
		constraint := ""
		if rawConstraint, present := object["constraint"]; present {
			constraint, ok = rawConstraint.(string)
			if !ok {
				return invalid("dependency_constraint_invalid")
			}
		}
		identity := [2]string{kind, name}
		if seen[identity] {
			return invalid("dependency_identity_duplicate")
		}
		seen[identity] = true
		out.Declarations = append(out.Declarations, Dependency{Kind: kind, Name: name, Constraint: constraint})
	}
	out.Status = RuntimeDependenciesNone
	if len(out.Declarations) > 0 {
		out.Status = RuntimeDependenciesUnresolved
	}
	return out
}

// encoding/json matches tagged struct fields without regard to case. Reject
// those alternate spellings rather than disagreeing with typed consumers.
func hasRuntimeFieldAlias(object map[string]any, fields ...string) bool {
	for key := range object {
		for _, field := range fields {
			if key != field && strings.EqualFold(key, field) {
				return true
			}
		}
	}
	return false
}

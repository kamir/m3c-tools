package skillbundle

import (
	"encoding/json"
	"testing"
)

func TestRuntimeDeclarationAssessmentShape(t *testing.T) {
	for _, tc := range []struct {
		name     string
		manifest map[string]any
		status   RuntimeDependencyStatus
		reason   string
	}{
		{"missing-manifest", nil, RuntimeDependenciesInvalid, "manifest_missing"},
		{"absent", map[string]any{}, RuntimeDependenciesNone, ""},
		{"legacy-null", map[string]any{"depends_on": nil}, RuntimeDependenciesNone, ""},
		{"empty", map[string]any{"depends_on": []any{}}, RuntimeDependenciesNone, ""},
		{"object", map[string]any{"depends_on": map[string]any{}}, RuntimeDependenciesInvalid, "depends_on_not_list"},
		{"entry-scalar", map[string]any{"depends_on": []any{"skill:x"}}, RuntimeDependenciesInvalid, "dependency_not_object"},
		{"empty-kind", map[string]any{"depends_on": []any{map[string]any{"kind": " ", "name": "x"}}}, RuntimeDependenciesInvalid, "dependency_kind_invalid"},
		{"kind-type", map[string]any{"depends_on": []any{map[string]any{"kind": 1, "name": "x"}}}, RuntimeDependenciesInvalid, "dependency_kind_invalid"},
		{"unknown-kind", map[string]any{"depends_on": []any{map[string]any{"kind": "quantum", "name": "x"}}}, RuntimeDependenciesInvalid, "dependency_kind_unsupported"},
		{"kind-alias", map[string]any{"depends_on": []any{map[string]any{"kind": " python ", "name": "x"}}}, RuntimeDependenciesInvalid, "dependency_kind_unsupported"},
		{"empty-name", map[string]any{"depends_on": []any{map[string]any{"kind": "skill", "name": " "}}}, RuntimeDependenciesInvalid, "dependency_name_invalid"},
		{"name-type", map[string]any{"depends_on": []any{map[string]any{"kind": "skill", "name": 1}}}, RuntimeDependenciesInvalid, "dependency_name_invalid"},
		{"name-alias", map[string]any{"depends_on": []any{map[string]any{"kind": "skill", "name": " x "}}}, RuntimeDependenciesInvalid, "dependency_name_invalid"},
		{"constraint-type", map[string]any{"depends_on": []any{map[string]any{"kind": "python", "name": "x", "constraint": 1}}}, RuntimeDependenciesInvalid, "dependency_constraint_invalid"},
		{"unsupported-field", map[string]any{"package_dependencies": []any{}}, RuntimeDependenciesInvalid, "unsupported_dependency_field"},
		{"both-fields", map[string]any{"depends_on": []any{}, "package_dependencies": []any{}}, RuntimeDependenciesInvalid, "unsupported_dependency_field"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := AssessRuntimeDeclarations(tc.manifest)
			if got.Status != tc.status || got.Reason != tc.reason {
				t.Fatalf("wrong assessment: %+v", got)
			}
			if got.Scope != "runtime_dependencies" || got.Source != "manifest_projection" || got.Digest != "" {
				t.Fatalf("projection overclaimed source/scope: %+v", got)
			}
			if got.Declarations == nil {
				t.Fatal("declaration list must serialize as empty array")
			}
		})
	}
}

func TestRuntimeDeclarationAssessmentAllCatalogKinds(t *testing.T) {
	for _, kind := range []string{"python", "system", "skill", "agent"} {
		for _, constraint := range []string{"", ">=999.0.0", "opaque-unimplemented-range"} {
			t.Run(kind+"/"+constraint, func(t *testing.T) {
				declaration := map[string]any{"kind": kind, "name": "synthetic-missing", "constraint": constraint}
				got := AssessRuntimeDeclarations(map[string]any{"depends_on": []any{declaration}})
				if got.Status != RuntimeDependenciesUnresolved || len(got.Declarations) != 1 || got.Declarations[0].Constraint != constraint {
					t.Fatalf("nonempty declaration falsely resolved: %+v", got)
				}
				declaration["name"] = "mutated-after-assessment"
				if got.Declarations[0].Name != "synthetic-missing" {
					t.Fatal("assessment retained mutable map alias")
				}
			})
		}
	}
}

func TestRuntimeDeclarationAssessmentIdentityAndScope(t *testing.T) {
	deps := []any{map[string]any{"kind": "skill", "name": "synthetic"}, map[string]any{"kind": "agent", "name": "synthetic"}}
	got := AssessRuntimeDeclarations(map[string]any{"depends_on": deps})
	if got.Status != RuntimeDependenciesUnresolved || len(got.Declarations) != 2 {
		t.Fatalf("kind namespace collapsed: %+v", got)
	}
	deps = append(deps, map[string]any{"kind": "skill", "name": "synthetic", "constraint": ">=2"})
	if got := AssessRuntimeDeclarations(map[string]any{"depends_on": deps}); got.Status != RuntimeDependenciesInvalid || got.Reason != "dependency_identity_duplicate" {
		t.Fatalf("duplicate identity accepted: %+v", got)
	}
	for _, kind := range []string{"local_fs", "http_endpoint", "er1_collection", "firestore_collection", "gcs_bucket", "secrets_store"} {
		got := AssessRuntimeDeclarations(map[string]any{"data_dependencies": []any{map[string]any{"kind": kind}}})
		if got.Status != RuntimeDependenciesNone || got.Scope != "runtime_dependencies" {
			t.Fatalf("data dependency confused with runtime scope: %+v", got)
		}
	}
}

func TestRuntimeAssessmentTypedJSONAliasDifferential(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		typed     Dependency
	}{
		{"top-only", `{"Depends_On":[{"kind":"skill","name":"synthetic"}]}`, Dependency{Kind: "skill", Name: "synthetic"}},
		{"top-with-canonical", `{"depends_on":[],"Depends_On":[{"kind":"skill","name":"synthetic"}]}`, Dependency{Kind: "skill", Name: "synthetic"}},
		{"uppercase", `{"DEPENDS_ON":[{"kind":"skill","name":"synthetic"}]}`, Dependency{Kind: "skill", Name: "synthetic"}},
		{"unicode-kind", `{"depends_on":[{"Kind":"skill","name":"synthetic"}]}`, Dependency{Kind: "skill", Name: "synthetic"}},
		{"kind-only", `{"depends_on":[{"Kind":"skill","name":"synthetic"}]}`, Dependency{Kind: "skill", Name: "synthetic"}},
		{"kind-conflict", `{"depends_on":[{"kind":"python","Kind":"system","name":"synthetic"}]}`, Dependency{Kind: "system", Name: "synthetic"}},
		{"name-only", `{"depends_on":[{"kind":"skill","Name":"synthetic"}]}`, Dependency{Kind: "skill", Name: "synthetic"}},
		{"name-conflict", `{"depends_on":[{"kind":"skill","name":"decoy","Name":"synthetic"}]}`, Dependency{Kind: "skill", Name: "synthetic"}},
		{"constraint-only", `{"depends_on":[{"kind":"python","name":"synthetic","Constraint":">=999"}]}`, Dependency{Kind: "python", Name: "synthetic", Constraint: ">=999"}},
		{"constraint-conflict", `{"depends_on":[{"kind":"python","name":"synthetic","constraint":"","Constraint":">=999"}]}`, Dependency{Kind: "python", Name: "synthetic", Constraint: ">=999"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var typed BundleManifest
			if err := json.Unmarshal([]byte(tc.raw), &typed); err != nil {
				t.Fatal(err)
			}
			if len(typed.DependsOn) != 1 || typed.DependsOn[0] != tc.typed {
				t.Fatalf("fixture does not reproduce typed alias: %+v", typed.DependsOn)
			}
			var projection map[string]any
			if err := json.Unmarshal([]byte(tc.raw), &projection); err != nil {
				t.Fatal(err)
			}
			if got := AssessRuntimeDeclarations(projection); got.Status != RuntimeDependenciesInvalid {
				t.Fatalf("case alias disagrees silently with typed parser: %+v", got)
			}
		})
	}
	for _, field := range []string{"Package_Dependencies", "PACKAGE_DEPENDENCIES"} {
		if got := AssessRuntimeDeclarations(map[string]any{field: []any{}, "depends_on": []any{}}); got.Status != RuntimeDependenciesInvalid {
			t.Fatalf("unsupported alias became none: %+v", got)
		}
	}
	got := AssessRuntimeDeclarations(map[string]any{"unrelated_extension": true, "depends_on": []any{map[string]any{"kind": "skill", "name": "synthetic", "extension": map[string]any{"Kind": "opaque"}}}})
	if got.Status != RuntimeDependenciesUnresolved {
		t.Fatalf("unrelated extension was rejected or resolved: %+v", got)
	}
}

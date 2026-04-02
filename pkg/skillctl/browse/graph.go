// Package browse provides an interactive D3.js skill graph browser.
package browse

// NodeKind classifies nodes in the skill graph.
type NodeKind string

const (
	NodeSkill    NodeKind = "skill"
	NodeProject  NodeKind = "project"
	NodeCategory NodeKind = "category"
	NodeTag      NodeKind = "tag"
)

// EdgeKind classifies relationships between nodes.
type EdgeKind string

const (
	EdgeBelongsTo  EdgeKind = "belongs_to"
	EdgeTaggedWith EdgeKind = "tagged_with"
	EdgeInCategory EdgeKind = "in_category"
	EdgeDependsOn  EdgeKind = "depends_on"
	EdgeSimilarTo  EdgeKind = "similar_to"
	EdgeReferences EdgeKind = "references"
	EdgeColocated  EdgeKind = "colocated"
)

// Node represents a vertex in the skill graph.
type Node struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	Kind        NodeKind `json:"kind"`
	SkillType   string   `json:"skill_type,omitempty"`
	Project     string   `json:"project,omitempty"`
	Description string   `json:"description,omitempty"`
	SizeBytes   int64    `json:"size_bytes,omitempty"`
	SourcePath  string   `json:"source_path,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Category    string   `json:"category,omitempty"`
	HasFM       bool     `json:"has_frontmatter"`
	Degree      int      `json:"degree"`
}

// Edge represents a directed relationship between two nodes.
type Edge struct {
	Source   string   `json:"source"`
	Target   string   `json:"target"`
	Kind     EdgeKind `json:"kind"`
	Weight   float64  `json:"weight"`
	Evidence string   `json:"evidence,omitempty"`
}

// GraphStats provides summary metrics.
type GraphStats struct {
	TotalNodes    int `json:"total_nodes"`
	SkillNodes    int `json:"skill_nodes"`
	ProjectNodes  int `json:"project_nodes"`
	CategoryNodes int `json:"category_nodes"`
	TagNodes      int `json:"tag_nodes"`
	TotalEdges    int `json:"total_edges"`
}

// SkillGraph is the complete graph sent to the frontend.
type SkillGraph struct {
	Nodes      []Node     `json:"nodes"`
	Edges      []Edge     `json:"edges"`
	Stats      GraphStats `json:"stats"`
	Projects   []string   `json:"projects"`
	Categories []string   `json:"categories"`
	Tags       []string   `json:"tags"`
	SkillTypes []string   `json:"skill_types"`
}

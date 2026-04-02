package browse

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/internal/dbdriver"
)

// DefaultGraphDBPath returns the default path for the skill graph database.
func DefaultGraphDBPath() string {
	if v := os.Getenv("M3C_SKILL_GRAPH_DB"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".m3c-tools", "skill-graph.db")
	}
	return filepath.Join(home, ".m3c-tools", "skill-graph.db")
}

// GraphStore provides SQLite-backed persistence for the skill graph.
type GraphStore struct {
	db     *sql.DB
	dbPath string
}

// OpenGraphStore opens or creates the skill graph database at the given path.
func OpenGraphStore(dbPath string) (*GraphStore, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	db, err := sql.Open(dbdriver.DriverName(), dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	s := &GraphStore{db: db, dbPath: dbPath}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// Close closes the database connection.
func (s *GraphStore) Close() error {
	return s.db.Close()
}

func (s *GraphStore) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS graph_meta (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);

		CREATE TABLE IF NOT EXISTS nodes (
			id          TEXT PRIMARY KEY,
			label       TEXT NOT NULL,
			kind        TEXT NOT NULL,
			skill_type  TEXT DEFAULT '',
			project     TEXT DEFAULT '',
			description TEXT DEFAULT '',
			size_bytes  INTEGER DEFAULT 0,
			source_path TEXT DEFAULT '',
			category    TEXT DEFAULT '',
			has_fm      INTEGER DEFAULT 0,
			degree      INTEGER DEFAULT 0
		);

		CREATE TABLE IF NOT EXISTS node_tags (
			node_id TEXT NOT NULL,
			tag     TEXT NOT NULL,
			PRIMARY KEY (node_id, tag)
		);

		CREATE TABLE IF NOT EXISTS edges (
			source   TEXT NOT NULL,
			target   TEXT NOT NULL,
			kind     TEXT NOT NULL,
			weight   REAL DEFAULT 1.0,
			evidence TEXT DEFAULT '',
			PRIMARY KEY (source, target, kind)
		);
	`)
	return err
}

// SaveGraph persists the full graph to SQLite, replacing any previous data.
// All writes are wrapped in a single transaction.
func (s *GraphStore) SaveGraph(g *SkillGraph) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Clear existing data.
	for _, table := range []string{"edges", "node_tags", "nodes", "graph_meta"} {
		if _, err := tx.Exec("DELETE FROM " + table); err != nil {
			return fmt.Errorf("clear %s: %w", table, err)
		}
	}

	// Insert nodes.
	nodeStmt, err := tx.Prepare(`INSERT INTO nodes (id, label, kind, skill_type, project, description, size_bytes, source_path, category, has_fm, degree)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare node insert: %w", err)
	}
	defer nodeStmt.Close()

	tagStmt, err := tx.Prepare(`INSERT OR IGNORE INTO node_tags (node_id, tag) VALUES (?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare tag insert: %w", err)
	}
	defer tagStmt.Close()

	for _, n := range g.Nodes {
		_, err := nodeStmt.Exec(n.ID, n.Label, string(n.Kind), n.SkillType, n.Project,
			n.Description, n.SizeBytes, n.SourcePath, n.Category, boolToInt(n.HasFM), n.Degree)
		if err != nil {
			return fmt.Errorf("insert node %s: %w", n.ID, err)
		}
		for _, tag := range n.Tags {
			if _, err := tagStmt.Exec(n.ID, tag); err != nil {
				return fmt.Errorf("insert tag for %s: %w", n.ID, err)
			}
		}
	}

	// Insert edges.
	edgeStmt, err := tx.Prepare(`INSERT OR IGNORE INTO edges (source, target, kind, weight, evidence)
		VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare edge insert: %w", err)
	}
	defer edgeStmt.Close()

	for _, e := range g.Edges {
		if _, err := edgeStmt.Exec(e.Source, e.Target, string(e.Kind), e.Weight, e.Evidence); err != nil {
			return fmt.Errorf("insert edge %s->%s: %w", e.Source, e.Target, err)
		}
	}

	// Write metadata.
	metaStmt, err := tx.Prepare(`INSERT INTO graph_meta (key, value) VALUES (?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare meta insert: %w", err)
	}
	defer metaStmt.Close()

	now := time.Now().UTC().Format(time.RFC3339)
	meta := map[string]string{
		"built_at":   now,
		"node_count": strconv.Itoa(len(g.Nodes)),
		"edge_count": strconv.Itoa(len(g.Edges)),
	}
	for k, v := range meta {
		if _, err := metaStmt.Exec(k, v); err != nil {
			return fmt.Errorf("insert meta %s: %w", k, err)
		}
	}

	return tx.Commit()
}

// SaveGraphWithHash persists the graph and records the inventory hash for
// staleness detection via IsStale.
func (s *GraphStore) SaveGraphWithHash(g *SkillGraph, inventoryHash string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Clear existing data.
	for _, table := range []string{"edges", "node_tags", "nodes", "graph_meta"} {
		if _, err := tx.Exec("DELETE FROM " + table); err != nil {
			return fmt.Errorf("clear %s: %w", table, err)
		}
	}

	// Insert nodes.
	nodeStmt, err := tx.Prepare(`INSERT INTO nodes (id, label, kind, skill_type, project, description, size_bytes, source_path, category, has_fm, degree)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare node insert: %w", err)
	}
	defer nodeStmt.Close()

	tagStmt, err := tx.Prepare(`INSERT OR IGNORE INTO node_tags (node_id, tag) VALUES (?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare tag insert: %w", err)
	}
	defer tagStmt.Close()

	for _, n := range g.Nodes {
		_, err := nodeStmt.Exec(n.ID, n.Label, string(n.Kind), n.SkillType, n.Project,
			n.Description, n.SizeBytes, n.SourcePath, n.Category, boolToInt(n.HasFM), n.Degree)
		if err != nil {
			return fmt.Errorf("insert node %s: %w", n.ID, err)
		}
		for _, tag := range n.Tags {
			if _, err := tagStmt.Exec(n.ID, tag); err != nil {
				return fmt.Errorf("insert tag for %s: %w", n.ID, err)
			}
		}
	}

	// Insert edges.
	edgeStmt, err := tx.Prepare(`INSERT OR IGNORE INTO edges (source, target, kind, weight, evidence)
		VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare edge insert: %w", err)
	}
	defer edgeStmt.Close()

	for _, e := range g.Edges {
		if _, err := edgeStmt.Exec(e.Source, e.Target, string(e.Kind), e.Weight, e.Evidence); err != nil {
			return fmt.Errorf("insert edge %s->%s: %w", e.Source, e.Target, err)
		}
	}

	// Write metadata including inventory hash.
	metaStmt, err := tx.Prepare(`INSERT INTO graph_meta (key, value) VALUES (?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare meta insert: %w", err)
	}
	defer metaStmt.Close()

	now := time.Now().UTC().Format(time.RFC3339)
	meta := map[string]string{
		"inventory_hash": inventoryHash,
		"built_at":       now,
		"node_count":     strconv.Itoa(len(g.Nodes)),
		"edge_count":     strconv.Itoa(len(g.Edges)),
	}
	for k, v := range meta {
		if _, err := metaStmt.Exec(k, v); err != nil {
			return fmt.Errorf("insert meta %s: %w", k, err)
		}
	}

	return tx.Commit()
}

// LoadGraph reads the full graph from the database and recomputes stats
// and filter lists. Returns nil if the database is empty.
func (s *GraphStore) LoadGraph() (*SkillGraph, error) {
	// Check whether we have any data.
	var nodeCount int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM nodes").Scan(&nodeCount); err != nil {
		return nil, fmt.Errorf("count nodes: %w", err)
	}
	if nodeCount == 0 {
		return nil, nil
	}

	g := &SkillGraph{
		Nodes: make([]Node, 0, nodeCount),
		Edges: make([]Edge, 0),
	}

	// Load nodes.
	rows, err := s.db.Query(`SELECT id, label, kind, skill_type, project, description,
		size_bytes, source_path, category, has_fm, degree FROM nodes`)
	if err != nil {
		return nil, fmt.Errorf("query nodes: %w", err)
	}
	defer rows.Close()

	nodeIndex := make(map[string]int) // node ID -> index in g.Nodes
	for rows.Next() {
		var n Node
		var kind string
		var hasFM int
		if err := rows.Scan(&n.ID, &n.Label, &kind, &n.SkillType, &n.Project,
			&n.Description, &n.SizeBytes, &n.SourcePath, &n.Category, &hasFM, &n.Degree); err != nil {
			return nil, fmt.Errorf("scan node: %w", err)
		}
		n.Kind = NodeKind(kind)
		n.HasFM = hasFM != 0
		nodeIndex[n.ID] = len(g.Nodes)
		g.Nodes = append(g.Nodes, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate nodes: %w", err)
	}

	// Load tags and attach to their nodes.
	tagRows, err := s.db.Query(`SELECT node_id, tag FROM node_tags ORDER BY node_id, tag`)
	if err != nil {
		return nil, fmt.Errorf("query node_tags: %w", err)
	}
	defer tagRows.Close()

	for tagRows.Next() {
		var nodeID, tag string
		if err := tagRows.Scan(&nodeID, &tag); err != nil {
			return nil, fmt.Errorf("scan tag: %w", err)
		}
		if idx, ok := nodeIndex[nodeID]; ok {
			g.Nodes[idx].Tags = append(g.Nodes[idx].Tags, tag)
		}
	}
	if err := tagRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tags: %w", err)
	}

	// Load edges.
	edgeRows, err := s.db.Query(`SELECT source, target, kind, weight, evidence FROM edges`)
	if err != nil {
		return nil, fmt.Errorf("query edges: %w", err)
	}
	defer edgeRows.Close()

	for edgeRows.Next() {
		var e Edge
		var kind string
		if err := edgeRows.Scan(&e.Source, &e.Target, &kind, &e.Weight, &e.Evidence); err != nil {
			return nil, fmt.Errorf("scan edge: %w", err)
		}
		e.Kind = EdgeKind(kind)
		g.Edges = append(g.Edges, e)
	}
	if err := edgeRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate edges: %w", err)
	}

	// Recompute stats and filter lists from loaded data.
	recomputeStats(g)

	return g, nil
}

// IsStale returns true if the stored inventory hash differs from the given
// hash, or if no graph has been persisted yet. This lets callers skip
// expensive rebuilds when the inventory hasn't changed.
func (s *GraphStore) IsStale(inventoryHash string) bool {
	var stored string
	err := s.db.QueryRow("SELECT value FROM graph_meta WHERE key = 'inventory_hash'").Scan(&stored)
	if err != nil {
		// No hash stored (empty DB or missing key) means stale.
		return true
	}
	return stored != inventoryHash
}

// BuiltAt returns the timestamp when the graph was last persisted,
// or the zero time if no graph has been saved.
func (s *GraphStore) BuiltAt() time.Time {
	var raw string
	err := s.db.QueryRow("SELECT value FROM graph_meta WHERE key = 'built_at'").Scan(&raw)
	if err != nil {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339, raw)
	return t
}

// recomputeStats rebuilds Stats, Projects, Categories, Tags, and SkillTypes
// from the loaded node and edge data.
func recomputeStats(g *SkillGraph) {
	projectSet := make(map[string]bool)
	categorySet := make(map[string]bool)
	tagSet := make(map[string]bool)
	typeSet := make(map[string]bool)

	for _, n := range g.Nodes {
		switch n.Kind {
		case NodeSkill:
			g.Stats.SkillNodes++
			if n.SkillType != "" {
				typeSet[n.SkillType] = true
			}
		case NodeProject:
			g.Stats.ProjectNodes++
		case NodeCategory:
			g.Stats.CategoryNodes++
		case NodeTag:
			g.Stats.TagNodes++
		}

		if n.Project != "" {
			projectSet[n.Project] = true
		}
		if n.Category != "" {
			categorySet[n.Category] = true
		}
		for _, t := range n.Tags {
			t = strings.TrimSpace(t)
			if t != "" {
				tagSet[t] = true
			}
		}
	}

	g.Stats.TotalNodes = len(g.Nodes)
	g.Stats.TotalEdges = len(g.Edges)

	g.Projects = sortedKeysFromMap(projectSet)
	g.Categories = sortedKeysFromMap(categorySet)
	g.Tags = sortedKeysFromMap(tagSet)
	g.SkillTypes = sortedKeysFromMap(typeSet)
}

// sortedKeysFromMap returns sorted keys from a bool map.
func sortedKeysFromMap(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

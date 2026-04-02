package browse

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/model"
)

// BuildGraph constructs a SkillGraph from a skill Inventory.
// Phase A: structural edges (belongs_to, tagged_with, in_category).
// Phase B: inferred edges (references, similar_to, colocated).
func BuildGraph(inv *model.Inventory) *SkillGraph {
	g := &SkillGraph{
		Nodes: make([]Node, 0, inv.TotalCount*2),
		Edges: make([]Edge, 0, inv.TotalCount*3),
	}

	projectSet := make(map[string]bool)
	categorySet := make(map[string]bool)
	tagSet := make(map[string]bool)
	typeSet := make(map[string]bool)

	// Phase A: Create skill nodes and structural edges.
	seenIDs := make(map[string]int)
	for _, sk := range inv.Skills {
		baseID := fmt.Sprintf("skill:%s/%s", sk.SourceProject, sk.Name)
		skillID := baseID
		if seenIDs[baseID] > 0 {
			skillID = fmt.Sprintf("%s_%d", baseID, seenIDs[baseID])
		}
		seenIDs[baseID]++

		var desc, category string
		var tags []string
		if sk.Frontmatter != nil {
			desc = sk.Frontmatter.Description
			category = sk.Frontmatter.Category
			tags = sk.Frontmatter.Tags

			// Extract from nested metadata block if top-level is empty.
			if sk.Frontmatter.Metadata != nil {
				if category == "" {
					if c, ok := sk.Frontmatter.Metadata["category"].(string); ok {
						category = c
					}
				}
				if len(tags) == 0 {
					if rawTags, ok := sk.Frontmatter.Metadata["tags"]; ok {
						if tagSlice, ok := rawTags.([]interface{}); ok {
							for _, t := range tagSlice {
								if s, ok := t.(string); ok {
									tags = append(tags, s)
								}
							}
						}
					}
				}
			}
		}

		// Map skill type to the proper node kind.
		kind := NodeSkill
		switch sk.Type {
		case model.SkillTypeAgent:
			kind = NodeAgent
		case model.SkillTypeSkillIndex:
			kind = NodeSkillIndex
		case model.SkillTypeCommand:
			kind = NodeCommand
		}

		node := Node{
			ID:          skillID,
			Label:       sk.Name,
			Kind:        kind,
			SkillType:   string(sk.Type),
			Project:     sk.SourceProject,
			Description: desc,
			SizeBytes:   sk.ContentSizeBytes,
			SourcePath:  sk.SourcePath,
			Tags:        tags,
			Category:    category,
			HasFM:       sk.HasYAMLFrontmatter,
		}
		g.Nodes = append(g.Nodes, node)
		typeSet[string(sk.Type)] = true

		// belongs_to: skill → project
		projID := fmt.Sprintf("project:%s", sk.SourceProject)
		if !projectSet[sk.SourceProject] {
			projectSet[sk.SourceProject] = true
			g.Nodes = append(g.Nodes, Node{
				ID:    projID,
				Label: sk.SourceProject,
				Kind:  NodeProject,
			})
		}
		g.Edges = append(g.Edges, Edge{
			Source: skillID,
			Target: projID,
			Kind:   EdgeBelongsTo,
			Weight: 1.0,
		})

		// in_category: skill → category
		if category != "" {
			catID := fmt.Sprintf("category:%s", category)
			if !categorySet[category] {
				categorySet[category] = true
				g.Nodes = append(g.Nodes, Node{
					ID:    catID,
					Label: category,
					Kind:  NodeCategory,
				})
			}
			g.Edges = append(g.Edges, Edge{
				Source: skillID,
				Target: catID,
				Kind:   EdgeInCategory,
				Weight: 0.9,
			})
		}

		// tagged_with: skill → tag
		for _, tag := range tags {
			tag = strings.TrimSpace(tag)
			if tag == "" {
				continue
			}
			tagID := fmt.Sprintf("tag:%s", tag)
			if !tagSet[tag] {
				tagSet[tag] = true
				g.Nodes = append(g.Nodes, Node{
					ID:    tagID,
					Label: tag,
					Kind:  NodeTag,
				})
			}
			g.Edges = append(g.Edges, Edge{
				Source: skillID,
				Target: tagID,
				Kind:   EdgeTaggedWith,
				Weight: 0.8,
			})
		}
	}

	// Phase B: Inferred edges (relationship inference).

	// Collect content nodes (skills, agents, commands, skill indexes) for inference passes.
	var skillNodes []Node
	for _, n := range g.Nodes {
		if n.Kind.IsContentNode() {
			skillNodes = append(skillNodes, n)
		}
	}

	// B-1: Cross-reference edges (references, weight 0.7).
	// Build a map of skill name → skill ID for lookup.
	nameToID := make(map[string]string, len(skillNodes))
	for _, n := range skillNodes {
		if n.Label != "" {
			nameToID[strings.ToLower(n.Label)] = n.ID
		}
	}
	// Read each skill's source file and check for mentions of other skills.
	for _, n := range skillNodes {
		if n.SourcePath == "" {
			continue
		}
		data, err := os.ReadFile(n.SourcePath)
		if err != nil {
			continue // skip files that can't be read
		}
		contentLower := strings.ToLower(string(data))
		for otherName, otherID := range nameToID {
			if otherID == n.ID {
				continue // skip self-references
			}
			if strings.Contains(contentLower, otherName) {
				g.Edges = append(g.Edges, Edge{
					Source:   n.ID,
					Target:   otherID,
					Kind:     EdgeReferences,
					Weight:   0.7,
					Evidence: fmt.Sprintf("content mentions '%s'", otherName),
				})
			}
		}
	}

	// B-2: Shared-tag similarity edges (similar_to, weight 0.3-0.6).
	// Pre-build a set of existing same-project pairs to skip.
	type nodePair struct{ a, b string }
	sameProjectPairs := make(map[nodePair]bool)
	for i := 0; i < len(skillNodes); i++ {
		for j := i + 1; j < len(skillNodes); j++ {
			if skillNodes[i].Project == skillNodes[j].Project {
				sameProjectPairs[nodePair{skillNodes[i].ID, skillNodes[j].ID}] = true
			}
		}
	}
	for i := 0; i < len(skillNodes); i++ {
		if len(skillNodes[i].Tags) == 0 {
			continue
		}
		tagsA := make(map[string]bool, len(skillNodes[i].Tags))
		for _, t := range skillNodes[i].Tags {
			tagsA[strings.TrimSpace(t)] = true
		}
		for j := i + 1; j < len(skillNodes); j++ {
			if len(skillNodes[j].Tags) == 0 {
				continue
			}
			// Skip pairs already connected by a stronger edge (same project).
			if sameProjectPairs[nodePair{skillNodes[i].ID, skillNodes[j].ID}] {
				continue
			}
			// Count shared tags.
			var shared []string
			for _, t := range skillNodes[j].Tags {
				t = strings.TrimSpace(t)
				if tagsA[t] {
					shared = append(shared, t)
				}
			}
			if len(shared) < 2 {
				continue
			}
			maxLen := len(skillNodes[i].Tags)
			if len(skillNodes[j].Tags) > maxLen {
				maxLen = len(skillNodes[j].Tags)
			}
			weight := float64(len(shared)) / float64(maxLen)
			if weight > 0.6 {
				weight = 0.6
			}
			g.Edges = append(g.Edges, Edge{
				Source:   skillNodes[i].ID,
				Target:   skillNodes[j].ID,
				Kind:     EdgeSimilarTo,
				Weight:   weight,
				Evidence: fmt.Sprintf("shared tags: %s", strings.Join(shared, ", ")),
			})
		}
	}

	// B-3: Colocated edges (colocated, weight 0.2).
	// Pre-build a set of existing category-edge pairs to avoid duplicates.
	categoryPairs := make(map[nodePair]bool)
	for i := 0; i < len(skillNodes); i++ {
		if skillNodes[i].Category == "" {
			continue
		}
		for j := i + 1; j < len(skillNodes); j++ {
			if skillNodes[j].Category == "" {
				continue
			}
			if skillNodes[i].Category == skillNodes[j].Category {
				categoryPairs[nodePair{skillNodes[i].ID, skillNodes[j].ID}] = true
			}
		}
	}
	for i := 0; i < len(skillNodes); i++ {
		for j := i + 1; j < len(skillNodes); j++ {
			if skillNodes[i].Project != skillNodes[j].Project {
				continue
			}
			if skillNodes[i].SkillType != skillNodes[j].SkillType {
				continue
			}
			// Skip if they already share a category edge.
			if categoryPairs[nodePair{skillNodes[i].ID, skillNodes[j].ID}] {
				continue
			}
			g.Edges = append(g.Edges, Edge{
				Source:   skillNodes[i].ID,
				Target:   skillNodes[j].ID,
				Kind:     EdgeColocated,
				Weight:   0.2,
				Evidence: "same project + same type",
			})
		}
	}

	// Compute node degrees.
	degreeMap := make(map[string]int)
	for _, e := range g.Edges {
		degreeMap[e.Source]++
		degreeMap[e.Target]++
	}
	for i := range g.Nodes {
		g.Nodes[i].Degree = degreeMap[g.Nodes[i].ID]
	}

	// Collect sorted filter lists.
	g.Projects = sortedKeys(projectSet)
	g.Categories = sortedKeys(categorySet)
	g.Tags = sortedKeys(tagSet)
	g.SkillTypes = sortedKeys(typeSet)

	// Compute stats.
	for _, n := range g.Nodes {
		switch n.Kind {
		case NodeSkill:
			g.Stats.SkillNodes++
		case NodeAgent:
			g.Stats.AgentNodes++
		case NodeSkillIndex:
			g.Stats.SkillIndexNodes++
		case NodeCommand:
			g.Stats.CommandNodes++
		case NodeProject:
			g.Stats.ProjectNodes++
		case NodeCategory:
			g.Stats.CategoryNodes++
		case NodeTag:
			g.Stats.TagNodes++
		}
	}
	g.Stats.TotalNodes = len(g.Nodes)
	g.Stats.TotalEdges = len(g.Edges)

	return g
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

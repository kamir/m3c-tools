package browse

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/model"
)

// BuildGraph constructs a SkillGraph from a skill Inventory.
// Phase 1: structural edges only (belongs_to, tagged_with, in_category).
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
	for _, sk := range inv.Skills {
		skillID := fmt.Sprintf("skill:%s/%s", sk.SourceProject, sk.Name)

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

		node := Node{
			ID:          skillID,
			Label:       sk.Name,
			Kind:        NodeSkill,
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

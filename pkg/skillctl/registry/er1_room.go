package registry

// SPEC-0246 §7 — room mapping for already-published bundles.
//
// `skillctl publish --share-room <label>` stamps the room label at admit time.
// This file backs `skillctl room share/unshare`, which maps (or un-maps)
// bundles that are ALREADY in the registry into a SPEC-0096 co-learning room
// by adding/removing the bare room_label tag on their ER1 event items.
//
// Transport: maindrec's dual-auth tag endpoints (X-API-KEY), same base + auth
// as searchByTagsRaw/er1Get:
//   POST /memory/<ctx>/add_tags     {"ids":[...], "tags":[label]}
//   POST /memory/<ctx>/remove_tag   {"id":..,   "tag": label}     (per item)

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/er1"
)

// RoomShareSelector picks which published items to (un)map into a room.
// Exactly one of SkillName / Digest must be set, unless All is true.
type RoomShareSelector struct {
	SkillName string // map every event item carrying skill:<name>
	Digest    string // map every event item carrying skill-digest:<digest>
	All       bool   // map every m3c-skill-bundle item in the context
}

func (s RoomShareSelector) tags() ([]string, error) {
	switch {
	case s.All:
		return []string{"m3c-skill-bundle"}, nil
	case s.Digest != "":
		return []string{"m3c-skill-bundle", "skill-digest:" + s.Digest}, nil
	case s.SkillName != "":
		return []string{"m3c-skill-bundle", "skill:" + s.SkillName}, nil
	default:
		return nil, fmt.Errorf("room: need a skill name, --digest, or --all")
	}
}

// RoomShareResult reports what was (un)mapped.
type RoomShareResult struct {
	ItemIDs []string // ER1 item ids touched
	Skills  []string // distinct skill:<name> values seen (for the human summary)
}

// itemIDsAndSkills extracts the doc id (doc_id, falling back to the maindrec
// list `id`) and the skill name from each matched item.
func itemIDsAndSkills(items []map[string]any) ([]string, []string) {
	var ids []string
	skillSet := map[string]struct{}{}
	for _, it := range items {
		id, _ := it["doc_id"].(string)
		if id == "" {
			id, _ = it["id"].(string)
		}
		if id == "" {
			continue
		}
		ids = append(ids, id)
		for _, t := range itemTags(it) {
			if strings.HasPrefix(t, "skill:") {
				skillSet[strings.TrimPrefix(t, "skill:")] = struct{}{}
			}
		}
	}
	skills := make([]string, 0, len(skillSet))
	for s := range skillSet {
		skills = append(skills, s)
	}
	return ids, skills
}

func itemTags(it map[string]any) []string {
	switch tags := it["tags"].(type) {
	case string:
		var out []string
		for _, t := range strings.Split(tags, ",") {
			if t = strings.TrimSpace(t); t != "" {
				out = append(out, t)
			}
		}
		return out
	case []any:
		var out []string
		for _, x := range tags {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// MatchRoomItems resolves (read-only) the items a selector would touch. Used
// by `--dry-run` and internally by ShareToRoom. `extraTags` lets the caller
// further constrain the match (e.g. "only items that already carry the label").
func MatchRoomItems(cfg *er1.Config, ctxID string, sel RoomShareSelector, extraTags ...string) (*RoomShareResult, error) {
	wantTags, err := sel.tags()
	if err != nil {
		return nil, err
	}
	wantTags = append(wantTags, extraTags...)
	items, err := searchByTagsRaw(cfg, ctxID, wantTags)
	if err != nil {
		return nil, err
	}
	ids, skills := itemIDsAndSkills(items)
	return &RoomShareResult{ItemIDs: ids, Skills: skills}, nil
}

// ShareToRoom adds the bare room label as a tag to every matched item, mapping
// the bundle(s) into the SPEC-0096 room. Idempotent server-side (add_tags
// unions). Returns the items touched.
func ShareToRoom(cfg *er1.Config, ctxID, roomLabel string, sel RoomShareSelector) (*RoomShareResult, error) {
	if strings.TrimSpace(roomLabel) == "" {
		return nil, fmt.Errorf("room: room label required")
	}
	match, err := MatchRoomItems(cfg, ctxID, sel)
	if err != nil {
		return nil, err
	}
	ids, skills := match.ItemIDs, match.Skills
	if len(ids) == 0 {
		return &RoomShareResult{}, nil
	}
	base := strings.TrimSuffix(cfg.APIURL, "/upload_2")
	path := "/memory/" + url.PathEscape(ctxID) + "/add_tags"
	if _, err := er1PostJSON(base, cfg, path, map[string]any{
		"ids":  ids,
		"tags": []string{roomLabel},
	}); err != nil {
		return nil, fmt.Errorf("add_tags: %w", err)
	}
	return &RoomShareResult{ItemIDs: ids, Skills: skills}, nil
}

// UnshareFromRoom removes the room label from every matched item. remove_tag is
// per-item, so we loop; a single failure aborts and reports how far we got.
func UnshareFromRoom(cfg *er1.Config, ctxID, roomLabel string, sel RoomShareSelector) (*RoomShareResult, error) {
	if strings.TrimSpace(roomLabel) == "" {
		return nil, fmt.Errorf("room: room label required")
	}
	// Only items that actually carry the label need removal.
	match, err := MatchRoomItems(cfg, ctxID, sel, roomLabel)
	if err != nil {
		return nil, err
	}
	ids, skills := match.ItemIDs, match.Skills
	base := strings.TrimSuffix(cfg.APIURL, "/upload_2")
	path := "/memory/" + url.PathEscape(ctxID) + "/remove_tag"
	done := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, err := er1PostJSON(base, cfg, path, map[string]any{
			"id":  id,
			"tag": roomLabel,
		}); err != nil {
			return &RoomShareResult{ItemIDs: done, Skills: skills},
				fmt.Errorf("remove_tag %s: %w", id, err)
		}
		done = append(done, id)
	}
	return &RoomShareResult{ItemIDs: done, Skills: skills}, nil
}

// er1PostJSON POSTs a JSON body to base+path with the same dual-auth headers
// (X-API-KEY / device token) as er1Get. Returns the decoded JSON response.
func er1PostJSON(base string, cfg *er1.Config, path string, payload any) (any, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	if !cfg.VerifySSL {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	req, err := http.NewRequest("POST", base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range cfg.AuthHeaders() {
		req.Header.Set(k, v)
	}
	if os.Getenv("ER1_DEVICE_TOKEN") == "" && cfg.APIKey != "" {
		req.Header.Set("X-API-KEY", cfg.APIKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("POST %s -> HTTP %d: %s", path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var v any
	if len(bytes.TrimSpace(b)) > 0 {
		_ = json.Unmarshal(bytes.TrimSpace(b), &v)
	}
	return v, nil
}

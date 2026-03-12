package e2e

import (
	"sort"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/impression"
)

// --- ParseMetadataTags basic extraction ---

func TestMetadataTagsPlainFilename(t *testing.T) {
	mt := impression.ParseMetadataTags("2026-03-09_braindump_meeting.wav")
	assertContainsTag(t, mt.Plain, "braindump")
	assertContainsTag(t, mt.Plain, "meeting")
	if len(mt.KeyValue) != 0 {
		t.Errorf("Expected no key-value tags, got %v", mt.KeyValue)
	}
	if mt.Source != "" {
		t.Errorf("Expected no source, got %q", mt.Source)
	}
	t.Logf("Plain tags: %v", mt.Plain)
}

func TestMetadataTagsHashTags(t *testing.T) {
	mt := impression.ParseMetadataTags("braindump_#meeting_#standup.wav")
	assertContainsTag(t, mt.HashTags, "meeting")
	assertContainsTag(t, mt.HashTags, "standup")
	// Hash tags should NOT also appear in plain tags.
	for _, ht := range mt.HashTags {
		for _, pt := range mt.Plain {
			if ht == pt {
				t.Errorf("Hash tag %q should not appear in plain tags", ht)
			}
		}
	}
	t.Logf("Hash tags: %v, Plain: %v", mt.HashTags, mt.Plain)
}

func TestMetadataTagsBracketCategories(t *testing.T) {
	mt := impression.ParseMetadataTags("[draft]_braindump_notes.wav")
	assertContainsTag(t, mt.Categories, "draft")
	assertContainsTag(t, mt.Plain, "braindump")
	assertContainsTag(t, mt.Plain, "notes")
	t.Logf("Categories: %v, Plain: %v", mt.Categories, mt.Plain)
}

func TestMetadataTagsMultipleBrackets(t *testing.T) {
	mt := impression.ParseMetadataTags("[draft][urgent]_notes.wav")
	assertContainsTag(t, mt.Categories, "draft")
	assertContainsTag(t, mt.Categories, "urgent")
	if len(mt.Categories) != 2 {
		t.Errorf("Expected 2 categories, got %d: %v", len(mt.Categories), mt.Categories)
	}
}

func TestMetadataTagsColonKeyValue(t *testing.T) {
	mt := impression.ParseMetadataTags("braindump_speaker:john.wav")
	if v := mt.Get("speaker"); v != "john" {
		t.Errorf("Expected speaker:john, got speaker:%q", v)
	}
	if !mt.HasKeyValue("speaker") {
		t.Error("HasKeyValue should return true for 'speaker'")
	}
	t.Logf("KeyValue: %v, Plain: %v", mt.KeyValue, mt.Plain)
}

func TestMetadataTagsKnownPrefixKeyValue(t *testing.T) {
	// "speaker" followed by "alice" should be parsed as speaker:alice
	mt := impression.ParseMetadataTags("braindump_speaker_alice_notes.wav")
	if v := mt.Get("speaker"); v != "alice" {
		t.Errorf("Expected speaker:alice, got speaker:%q", v)
	}
	// "alice" and "speaker" should NOT appear in plain tags
	for _, tag := range mt.Plain {
		if tag == "speaker" || tag == "alice" {
			t.Errorf("KV consumed tag %q should not appear in plain tags", tag)
		}
	}
	assertContainsTag(t, mt.Plain, "braindump")
	assertContainsTag(t, mt.Plain, "notes")
}

func TestMetadataTagsMultipleKnownPrefixes(t *testing.T) {
	mt := impression.ParseMetadataTags("speaker_bob_project_alpha.wav")
	if v := mt.Get("speaker"); v != "bob" {
		t.Errorf("Expected speaker:bob, got speaker:%q", v)
	}
	if v := mt.Get("project"); v != "alpha" {
		t.Errorf("Expected project:alpha, got project:%q", v)
	}
	if len(mt.Plain) != 0 {
		t.Errorf("Expected no plain tags, got %v", mt.Plain)
	}
}

// --- Device/source detection ---

func TestMetadataTagsZoomDevice(t *testing.T) {
	mt := impression.ParseMetadataTags("ZOOM0001_braindump.wav")
	if mt.Source != "zoom" {
		t.Errorf("Expected source 'zoom', got %q", mt.Source)
	}
	// "zoom" should not be in plain tags
	for _, tag := range mt.Plain {
		if tag == "zoom" {
			t.Error("Source device should not appear in plain tags")
		}
	}
	t.Logf("Source: %s, Plain: %v", mt.Source, mt.Plain)
}

func TestMetadataTagsDictaphoneDevice(t *testing.T) {
	mt := impression.ParseMetadataTags("DM_0001_meeting.wav")
	if mt.Source != "dictaphone" {
		t.Errorf("Expected source 'dictaphone', got %q", mt.Source)
	}
}

func TestMetadataTagsVoiceMemo(t *testing.T) {
	mt := impression.ParseMetadataTags("voice_memo_standup.m4a")
	if mt.Source != "voice-memo" {
		t.Errorf("Expected source 'voice-memo', got %q", mt.Source)
	}
}

func TestMetadataTagsRecorderDevice(t *testing.T) {
	mt := impression.ParseMetadataTags("rec001_braindump.wav")
	if mt.Source != "recorder" {
		t.Errorf("Expected source 'recorder', got %q", mt.Source)
	}
}

func TestMetadataTagsNoDevice(t *testing.T) {
	mt := impression.ParseMetadataTags("braindump_meeting.wav")
	if mt.Source != "" {
		t.Errorf("Expected no source, got %q", mt.Source)
	}
}

// --- AllTags and MergedTagString ---

func TestMetadataTagsAllTags(t *testing.T) {
	mt := impression.ParseMetadataTags("[draft]_braindump_speaker:john_#standup.wav")
	all := mt.AllTags()
	allStr := strings.Join(all, ",")

	// Should contain plain, kv, hash, category
	if !strings.Contains(allStr, "braindump") {
		t.Error("AllTags should contain plain tag 'braindump'")
	}
	if !strings.Contains(allStr, "speaker:john") {
		t.Error("AllTags should contain 'speaker:john'")
	}
	if !strings.Contains(allStr, "standup") {
		t.Error("AllTags should contain hash tag 'standup'")
	}
	if !strings.Contains(allStr, "category:draft") {
		t.Error("AllTags should contain 'category:draft'")
	}
	t.Logf("AllTags: %v", all)
}

func TestMetadataTagsMergedTagString(t *testing.T) {
	mt := impression.ParseMetadataTags("braindump_meeting.wav")
	merged := mt.MergedTagString()
	if merged == "" {
		t.Error("MergedTagString should not be empty")
	}
	if !strings.Contains(merged, "braindump") {
		t.Error("MergedTagString should contain 'braindump'")
	}
	t.Logf("Merged: %s", merged)
}

// --- Integration with BuildImportTags ---

func TestMetadataTagsIntegrationWithBuildImportTags(t *testing.T) {
	mt := impression.ParseMetadataTags("2026-03-09_braindump_speaker:alice_#standup.wav")
	allTags := mt.AllTags()
	importTags := impression.BuildImportTags(allTags)
	parsed := impression.ParseTagLine(importTags)

	// Should have import prefix tags + metadata tags
	found := map[string]bool{}
	for _, tag := range parsed {
		found[tag] = true
	}
	for _, want := range []string{"audio-import", "braindump"} {
		if !found[want] {
			t.Errorf("Missing expected tag %q in %v", want, parsed)
		}
	}
	t.Logf("Full import tag string: %s", importTags)
}

// --- Edge cases ---

func TestMetadataTagsEmptyFilename(t *testing.T) {
	mt := impression.ParseMetadataTags(".wav")
	if len(mt.Plain) != 0 {
		t.Errorf("Expected no plain tags, got %v", mt.Plain)
	}
	if len(mt.HashTags) != 0 {
		t.Errorf("Expected no hash tags, got %v", mt.HashTags)
	}
	if len(mt.Categories) != 0 {
		t.Errorf("Expected no categories, got %v", mt.Categories)
	}
}

func TestMetadataTagsOnlyTimestamp(t *testing.T) {
	mt := impression.ParseMetadataTags("2026-03-09.wav")
	if len(mt.Plain) != 0 {
		t.Errorf("Expected no plain tags, got %v", mt.Plain)
	}
}

func TestMetadataTagsHashTagCaseInsensitive(t *testing.T) {
	mt := impression.ParseMetadataTags("notes_#MeetingRoom.wav")
	assertContainsTag(t, mt.HashTags, "meetingroom")
}

func TestMetadataTagsBracketCaseInsensitive(t *testing.T) {
	mt := impression.ParseMetadataTags("[DRAFT]_notes.wav")
	assertContainsTag(t, mt.Categories, "draft")
}

func TestMetadataTagsColonKVCaseInsensitive(t *testing.T) {
	mt := impression.ParseMetadataTags("Project:Alpha_notes.wav")
	if v := mt.Get("project"); v != "alpha" {
		t.Errorf("Expected project:alpha, got project:%q", v)
	}
}

func TestMetadataTagsHasKeyValueFalse(t *testing.T) {
	mt := impression.ParseMetadataTags("braindump.wav")
	if mt.HasKeyValue("speaker") {
		t.Error("HasKeyValue should return false for missing key")
	}
}

func TestMetadataTagsGetMissing(t *testing.T) {
	mt := impression.ParseMetadataTags("braindump.wav")
	if v := mt.Get("speaker"); v != "" {
		t.Errorf("Get should return empty for missing key, got %q", v)
	}
}

func TestMetadataTagsWithPath(t *testing.T) {
	mt := impression.ParseMetadataTags("/Users/test/audio/ZOOM0001_braindump_#standup.wav")
	if mt.Source != "zoom" {
		t.Errorf("Expected source 'zoom', got %q", mt.Source)
	}
	assertContainsTag(t, mt.HashTags, "standup")
	assertContainsTag(t, mt.Plain, "braindump")
}

func TestMetadataTagsAllTagsStable(t *testing.T) {
	// AllTags should be deterministic across calls for plain/hash/category
	mt := impression.ParseMetadataTags("braindump_meeting_#standup_[draft].wav")
	tags1 := mt.AllTags()
	tags2 := mt.AllTags()

	sort.Strings(tags1)
	sort.Strings(tags2)
	if strings.Join(tags1, ",") != strings.Join(tags2, ",") {
		t.Errorf("AllTags not stable: %v vs %v", tags1, tags2)
	}
}

func TestMetadataTagsSourceInAllTags(t *testing.T) {
	mt := impression.ParseMetadataTags("ZOOM0001_braindump.wav")
	all := mt.AllTags()
	found := false
	for _, tag := range all {
		if tag == "source:zoom" {
			found = true
		}
	}
	if !found {
		t.Errorf("AllTags should contain 'source:zoom', got %v", all)
	}
}

func TestMetadataTagsComplexFilename(t *testing.T) {
	// Complex real-world-like filename with multiple metadata types
	mt := impression.ParseMetadataTags("ZOOM0001_2026-03-09T14-30-00_[draft]_speaker:bob_braindump_#weekly.wav")
	if mt.Source != "zoom" {
		t.Errorf("Expected source 'zoom', got %q", mt.Source)
	}
	assertContainsTag(t, mt.Categories, "draft")
	if v := mt.Get("speaker"); v != "bob" {
		t.Errorf("Expected speaker:bob, got speaker:%q", v)
	}
	assertContainsTag(t, mt.HashTags, "weekly")
	assertContainsTag(t, mt.Plain, "braindump")

	// The timestamp portion should not produce tags
	for _, tag := range mt.Plain {
		if tag == "2026" || tag == "03" || tag == "09" {
			t.Errorf("Date fragment %q should not be in plain tags", tag)
		}
	}
	t.Logf("Complex parse result - Source: %s, KV: %v, Hash: %v, Cat: %v, Plain: %v",
		mt.Source, mt.KeyValue, mt.HashTags, mt.Categories, mt.Plain)
}

// --- ExtractMetadata standalone ---

func TestExtractMetadataFromParsedInfo(t *testing.T) {
	info := impression.ParseFilename("ZOOM0001_2026-03-09_braindump.wav")
	mt := impression.ExtractMetadata(info.BaseName, info.Tags)
	if mt.Source != "zoom" {
		t.Errorf("Expected source 'zoom', got %q", mt.Source)
	}
	assertContainsTag(t, mt.Plain, "braindump")
}

func TestExtractMetadataEmptyTags(t *testing.T) {
	mt := impression.ExtractMetadata("", nil)
	if len(mt.Plain) != 0 || len(mt.HashTags) != 0 || len(mt.Categories) != 0 {
		t.Errorf("Expected empty metadata, got plain=%v hash=%v cat=%v",
			mt.Plain, mt.HashTags, mt.Categories)
	}
}

func TestMetadataTagsKnownPrefixAtEnd(t *testing.T) {
	// Known prefix at end of tags with no value — should stay as plain tag
	mt := impression.ParseMetadataTags("braindump_speaker.wav")
	// "speaker" is at end with no following value, so it stays as plain tag
	assertContainsTag(t, mt.Plain, "braindump")
	assertContainsTag(t, mt.Plain, "speaker")
}

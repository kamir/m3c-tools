package impression

import (
	"fmt"
	"os"
	"strings"
)

// BuildTags creates a comma-separated tag string for an observation.
// Tags are semantic content descriptors per SPEC-0001 REQ-9.
// The observation type (progress, idea, impulse, import) is internal
// metadata, NOT a user-visible tag. See BUG-0004.
func BuildTags(obsType ObservationType, extra ...string) string {
	var tags []string

	switch obsType {
	case Progress:
		tags = append(tags, "youtube")
	case Idea:
		tags = append(tags, "idea")
	case Impulse:
		tags = append(tags, "impulse")
	case Import:
		tags = append(tags, "audio-import")
	case Fieldnote:
		tags = append(tags, "plaud", "fieldnote")
	}

	tags = append(tags, extra...)
	return strings.Join(tags, ",")
}

// BuildVideoTags creates tags for a YouTube video observation.
func BuildVideoTags(videoID string, channelTitle string, obsType ObservationType) string {
	extra := []string{
		fmt.Sprintf("video_id:%s", videoID),
	}
	if channelTitle != "" {
		extra = append(extra, fmt.Sprintf("channel:%s", channelTitle))
	}
	return BuildTags(obsType, extra...)
}

// BuildImportTags creates tags for a batch audio import.
func BuildImportTags(filenameTags []string) string {
	return BuildTags(Import, filenameTags...)
}

// BuildFieldnoteTags creates tags for a Plaud fieldnote recording.
func BuildFieldnoteTags(title string, extra ...string) string {
	tags := []string{}
	if title != "" {
		tags = append(tags, fmt.Sprintf("recording:%s", title))
	}
	tags = append(tags, extra...)
	return BuildTags(Fieldnote, tags...)
}

// OriginTags returns tags identifying where this observation was captured:
// host:<hostname> and optionally source:<path>.
func OriginTags(sourcePath string) []string {
	var tags []string
	if h, err := os.Hostname(); err == nil && h != "" {
		tags = append(tags, fmt.Sprintf("host:%s", h))
	}
	if sourcePath != "" {
		tags = append(tags, fmt.Sprintf("source:%s", sourcePath))
	}
	return tags
}

// ParseTagLine parses a tag string back to a slice.
func ParseTagLine(line string) []string {
	var tags []string
	for _, t := range strings.Split(line, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			tags = append(tags, t)
		}
	}
	return tags
}

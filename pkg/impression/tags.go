package impression

import (
	"fmt"
	"strings"
)

// BuildTags creates a comma-separated tag string for an observation.
func BuildTags(obsType ObservationType, extra ...string) string {
	tags := []string{string(obsType)}

	switch obsType {
	case Progress:
		tags = append(tags, "youtube")
	case Idea:
		tags = append(tags, "screenshot")
	case Impulse:
		tags = append(tags, "impulse")
	case Import:
		tags = append(tags, "audio-import")
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

package transcript

const (
	watchURL        = "https://www.youtube.com/watch?v=%s"
	innertubeAPIURL = "https://www.youtube.com/youtubei/v1/player?key=%s"
)

// innertubeContext is the client context sent to YouTube's InnerTube API.
// Using the Android client avoids age-restriction issues on many videos.
var innertubeContext = map[string]any{
	"client": map[string]any{
		"clientName":    "ANDROID",
		"clientVersion": "20.10.38",
	},
}

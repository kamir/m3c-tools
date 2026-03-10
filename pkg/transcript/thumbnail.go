package transcript

import (
	"fmt"
	"io"
)

// ThumbnailSize represents the available YouTube thumbnail sizes.
type ThumbnailSize string

const (
	ThumbnailMaxRes  ThumbnailSize = "maxresdefault" // 1280x720
	ThumbnailSD      ThumbnailSize = "sddefault"     // 640x480
	ThumbnailHQ      ThumbnailSize = "hqdefault"     // 480x360
	ThumbnailMQ      ThumbnailSize = "mqdefault"     // 320x180
	ThumbnailDefault ThumbnailSize = "default"       // 120x90
)

const thumbnailURLTemplate = "https://img.youtube.com/vi/%s/%s.jpg"

// FetchThumbnail downloads the video's thumbnail image.
// It tries sizes in order from largest to smallest, returning the first available.
func (f *Fetcher) FetchThumbnail(videoID string) ([]byte, error) {
	sizes := []ThumbnailSize{ThumbnailMaxRes, ThumbnailSD, ThumbnailHQ, ThumbnailMQ, ThumbnailDefault}

	for _, size := range sizes {
		url := fmt.Sprintf(thumbnailURLTemplate, videoID, size)
		resp, err := f.client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			continue
		}

		data, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		// YouTube returns a small placeholder for missing sizes (< 1KB)
		if len(data) > 1000 {
			return data, nil
		}
	}

	return nil, fmt.Errorf("no thumbnail available for %s", videoID)
}

// FetchThumbnailSize downloads a specific thumbnail size.
func (f *Fetcher) FetchThumbnailSize(videoID string, size ThumbnailSize) ([]byte, error) {
	url := fmt.Sprintf(thumbnailURLTemplate, videoID, size)
	resp, err := f.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch thumbnail: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("thumbnail not available at size %s (status %d)", size, resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// ThumbnailURL returns the direct URL for a video's thumbnail at the given size.
func ThumbnailURL(videoID string, size ThumbnailSize) string {
	return fmt.Sprintf(thumbnailURLTemplate, videoID, size)
}

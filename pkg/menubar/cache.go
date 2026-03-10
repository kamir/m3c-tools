// cache.go — Local transcript cache to avoid redundant YouTube API calls.
//
// Transcripts are stored as JSON files in ~/.m3c-tools/cache/transcripts/<videoID>.json.
// Cache entries expire after a configurable TTL (default: 7 days).
package menubar

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"
)

const (
	defaultCacheTTL = 7 * 24 * time.Hour // 7 days
	cacheSubDir     = "cache/transcripts"
)

// transcriptCache handles local caching of FetchResult data.
type transcriptCache struct {
	dir string
	ttl time.Duration
}

// cachedEntry wraps a FetchResult with a timestamp for TTL expiry.
type cachedEntry struct {
	Result    *FetchResult `json:"result"`
	FetchedAt time.Time   `json:"fetched_at"`
}

// newTranscriptCache creates a cache rooted at ~/.m3c-tools/cache/transcripts/.
func newTranscriptCache() *transcriptCache {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".m3c-tools", cacheSubDir)
	return &transcriptCache{dir: dir, ttl: defaultCacheTTL}
}

// Get returns a cached FetchResult if it exists and hasn't expired.
func (c *transcriptCache) Get(videoID string) *FetchResult {
	path := c.path(videoID)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var entry cachedEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		log.Printf("[cache] corrupt cache file %s: %v", path, err)
		_ = os.Remove(path)
		return nil
	}

	if time.Since(entry.FetchedAt) > c.ttl {
		log.Printf("[cache] expired video=%s age=%s", videoID, time.Since(entry.FetchedAt).Round(time.Hour))
		_ = os.Remove(path)
		return nil
	}

	log.Printf("[cache] HIT video=%s age=%s chars=%d", videoID, time.Since(entry.FetchedAt).Round(time.Minute), entry.Result.CharCount)
	return entry.Result
}

// Put stores a FetchResult in the cache.
func (c *transcriptCache) Put(videoID string, result *FetchResult) {
	if err := os.MkdirAll(c.dir, 0755); err != nil {
		log.Printf("[cache] mkdir failed: %v", err)
		return
	}

	entry := cachedEntry{
		Result:    result,
		FetchedAt: time.Now(),
	}
	data, err := json.Marshal(entry)
	if err != nil {
		log.Printf("[cache] marshal failed video=%s: %v", videoID, err)
		return
	}

	path := c.path(videoID)
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Printf("[cache] write failed path=%s: %v", path, err)
		return
	}
	log.Printf("[cache] STORE video=%s chars=%d path=%s", videoID, result.CharCount, path)
}

// path returns the cache file path for a video ID.
func (c *transcriptCache) path(videoID string) string {
	return filepath.Join(c.dir, videoID+".json")
}

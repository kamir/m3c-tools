package plaud

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PlaudTokenEnvVar is the environment variable that supplies the Plaud API
// token without exposing it on the command line (SEC-M8). Preferred over the
// bare-argv form, which leaks the secret to ps/argv.
const PlaudTokenEnvVar = "M3C_PLAUD_TOKEN"

// ResolveAuthToken resolves a Plaud API token from secure sources, in order:
//
//  1. --token-file <path> (tokenFile arg): read the token from a file (trimmed).
//  2. $M3C_PLAUD_TOKEN environment variable.
//  3. argvToken: the bare command-line argument (DEPRECATED — leaks via ps/argv).
//
// When the bare-argv form is used and a secure source was available, callers
// should warn. ResolveAuthToken itself returns argvLeaked=true whenever the
// returned token came from the bare argv, so the caller can emit the SEC-M8
// deprecation warning. An empty argvToken is ignored.
//
// tokenFile takes precedence over the env var, which takes precedence over
// argv — so an explicit --token-file always wins.
func ResolveAuthToken(tokenFile, argvToken string) (token string, argvLeaked bool, err error) {
	if tokenFile != "" {
		data, readErr := os.ReadFile(tokenFile)
		if readErr != nil {
			return "", false, fmt.Errorf("plaud: read --token-file %q: %w", tokenFile, readErr)
		}
		tok := strings.TrimSpace(string(data))
		if tok == "" {
			return "", false, fmt.Errorf("plaud: --token-file %q is empty", tokenFile)
		}
		if hasControlChars(tok) {
			return "", false, fmt.Errorf("plaud: --token-file %q contains control characters", tokenFile)
		}
		return tok, false, nil
	}
	if env := strings.TrimSpace(os.Getenv(PlaudTokenEnvVar)); env != "" {
		if hasControlChars(env) {
			return "", false, fmt.Errorf("plaud: %s contains control characters", PlaudTokenEnvVar)
		}
		return env, false, nil
	}
	if argvToken != "" {
		if hasControlChars(argvToken) {
			return "", false, fmt.Errorf("plaud: token contains control characters")
		}
		return argvToken, true, nil
	}
	return "", false, fmt.Errorf("plaud: no token provided (set %s, pass --token-file <path>, or 'plaud auth login')", PlaudTokenEnvVar)
}

// TranscribeMode controls what happens when Plaud has no transcript for a recording.
type TranscribeMode string

const (
	// TranscribeModeQueue sends DO_TRANSCRIBE=true — server transcribes immediately.
	TranscribeModeQueue TranscribeMode = "queue"
	// TranscribeModeLazy adds todo.transcribe tag — background workers pick it up.
	TranscribeModeLazy TranscribeMode = "lazy"
	// TranscribeModeOff sends no transcription signal — audio stored as-is.
	TranscribeModeOff TranscribeMode = "off"
)

// Config holds Plaud API connection settings.
type Config struct {
	APIURL         string         // Plaud API base URL
	TokenPath      string         // path to session token JSON file
	ContentType    string         // ER1 content-type label for Plaud uploads
	DefaultTags    string         // default tags prepended to every plaud sync upload
	TranscribeMode TranscribeMode // what to do when Plaud has no transcript (queue|lazy|off)
}

const defaultPlaudAPIURL = "https://api.plaud.ai"

// LoadConfig reads Plaud settings from environment variables with defaults.
//
// SECURITY: the API base receives the raw bearer token on every request (and,
// during extraction, EVERY harvested candidate). PLAUD_API_URL can be set by a
// project-local `.env` in the current working directory (LoadDotenv → os.Setenv),
// so an untrusted repo could otherwise redirect those secrets to an attacker
// host. We therefore refuse any base that is not an https *.plaud.ai host and
// fall back to the default, warning secret-safely (origin only — never the token
// a hostile value might smuggle in the path/query).
func LoadConfig() *Config {
	apiURL := envOr("PLAUD_API_URL", defaultPlaudAPIURL)
	if !isAllowedPlaudDomain(apiURL) {
		fmt.Fprintf(os.Stderr, "  [plaud] refusing PLAUD_API_URL=%s (not an https *.plaud.ai host) — "+
			"using %s; the API base receives your bearer token\n", plaudURLOrigin(apiURL), defaultPlaudAPIURL)
		apiURL = defaultPlaudAPIURL
	}
	return &Config{
		APIURL:         apiURL,
		TokenPath:      envOr("PLAUD_TOKEN_FILE", defaultTokenPath()),
		ContentType:    envOr("PLAUD_CONTENT_TYPE", "Plaud-Fieldnote"),
		DefaultTags:    os.Getenv("PLAUD_DEFAULT_TAGS"),
		TranscribeMode: parseTranscribeMode(os.Getenv("PLAUD_TRANSCRIBE_MODE")),
	}
}

func parseTranscribeMode(s string) TranscribeMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "queue":
		return TranscribeModeQueue
	case "off":
		return TranscribeModeOff
	default:
		return TranscribeModeLazy
	}
}

func defaultTokenPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "plaud-session.json")
	}
	return filepath.Join(home, ".m3c-tools", "plaud-session.json")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

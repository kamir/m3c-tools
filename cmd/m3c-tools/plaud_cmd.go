//go:build darwin

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/auth"
	"github.com/kamir/m3c-tools/pkg/er1"
	"github.com/kamir/m3c-tools/pkg/httpsafe"
	"github.com/kamir/m3c-tools/pkg/impression"
	"github.com/kamir/m3c-tools/pkg/menubar"
	"github.com/kamir/m3c-tools/pkg/plaud"
	"github.com/kamir/m3c-tools/pkg/tracking"
	"github.com/kamir/m3c-tools/pkg/whisper"
)

func cmdPlaud(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: m3c-tools plaud <list|dev|check|sync|fix-times|auth> [args]")
		os.Exit(1)
	}
	switch args[0] {
	case "list":
		cmdPlaudList()
	case "dev":
		cmdPlaudDev(args[1:])
	case "check":
		cmdPlaudCheck()
	case "fix-times":
		apply, since, limit := false, "", 0
		for i := 1; i < len(args); i++ {
			switch a := args[i]; {
			case a == "--apply":
				apply = true
			case a == "--since" && i+1 < len(args):
				since = args[i+1]
				i++
			case strings.HasPrefix(a, "--since="):
				since = strings.TrimPrefix(a, "--since=")
			case a == "--limit" && i+1 < len(args):
				if v, err := strconv.Atoi(args[i+1]); err == nil {
					limit = v
				}
				i++
			case strings.HasPrefix(a, "--limit="):
				if v, err := strconv.Atoi(strings.TrimPrefix(a, "--limit=")); err == nil {
					limit = v
				}
			}
		}
		cmdPlaudFixTimes(apply, since, limit)
	case "sync":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: m3c-tools plaud sync <#|ID|--all> [flags]")
			fmt.Fprintln(os.Stderr, "  -f, --force         Force re-sync: re-download from Plaud and re-upload to ER1")
			fmt.Fprintln(os.Stderr, "      --tags <list>   Comma-separated tags to apply to every synced item")
			fmt.Fprintln(os.Stderr, "      --filter <re>   Only sync items whose title matches this regex")
			fmt.Fprintln(os.Stderr, "      --dry-run       Print the items that WOULD be synced; do not download or upload")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "Examples:")
			fmt.Fprintln(os.Stderr, "  m3c-tools plaud sync 17")
			fmt.Fprintln(os.Stderr, "  m3c-tools plaud sync --all")
			fmt.Fprintln(os.Stderr, "  m3c-tools plaud sync --all --filter '^(02-04|02-10|02-11|03-12)' --tags 'Denny,DV,test 2' --dry-run")
			os.Exit(1)
		}
		syncArg := ""
		force := false
		customTags := ""
		filter := ""
		dryRun := false
		for i := 1; i < len(args); i++ {
			a := args[i]
			switch {
			case a == "-f" || a == "--force":
				force = true
			case a == "--dry-run":
				dryRun = true
			case a == "--tags":
				if i+1 < len(args) {
					customTags = args[i+1]
					i++
				} else {
					fmt.Fprintln(os.Stderr, "--tags requires a value")
					os.Exit(1)
				}
			case strings.HasPrefix(a, "--tags="):
				customTags = strings.TrimPrefix(a, "--tags=")
			case a == "--filter":
				if i+1 < len(args) {
					filter = args[i+1]
					i++
				} else {
					fmt.Fprintln(os.Stderr, "--filter requires a value")
					os.Exit(1)
				}
			case strings.HasPrefix(a, "--filter="):
				filter = strings.TrimPrefix(a, "--filter=")
			case a == "--all":
				syncArg = "all"
			case syncArg == "" && !strings.HasPrefix(a, "-"):
				syncArg = a
			}
		}
		if syncArg == "" {
			fmt.Fprintln(os.Stderr, "Usage: m3c-tools plaud sync <#|ID|--all> [flags]")
			os.Exit(1)
		}
		cmdPlaudSync(syncArg, force, customTags, filter, dryRun)
	case "auth":
		cmdPlaudAuthDispatch(args[1:])
	case "debug":
		cmdPlaudDebugAPI()
	default:
		fmt.Fprintf(os.Stderr, "Unknown plaud subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func cmdPlaudAuthLogin() {
	cfg := plaud.LoadConfig()

	// Try to extract token from an already-open Chrome tab.
	fmt.Println("Checking Chrome for open Plaud tab...")
	token, err := plaud.ExtractTokenFromChrome()
	if err != nil {
		fmt.Printf("Could not extract token: %v\n", err)
		fmt.Println("\nOpening web.plaud.ai: please log in, then run this command again.")
		_ = plaud.OpenPlaudLogin()
		os.Exit(1)
	}

	session := &plaud.TokenSession{Token: token}
	if err := plaud.SaveToken(cfg.TokenPath, session); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving token: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Token extracted from Chrome and saved to %s\n", cfg.TokenPath)

	// Verify the token works.
	client := plaud.NewClient(cfg, token)
	recordings, err := client.ListRecordings()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: token saved but API test failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Authenticated. Found %d recordings.\n", len(recordings))
}

// cmdPlaudAuthFromER1 pulls the Plaud token from the ER1 Credential Vault
// (SPEC-0304) (captured once via the "Plaud verbinden" page, any OS) and
// saves it locally so `plaud sync` works. Replaces browser harvesting for the
// common case (BUG-0168): capture once, use anywhere.
func cmdPlaudAuthFromER1() {
	cfg := plaud.LoadConfig()

	fmt.Println("Fetching Plaud token from the ER1 credential vault...")
	token, _, err := plaud.FetchTokenFromER1()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	session := &plaud.TokenSession{Token: token}
	if err := plaud.SaveToken(cfg.TokenPath, session); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving token: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Token retrieved from ER1 and saved to %s\n", cfg.TokenPath)

	client := plaud.NewClient(cfg, token)
	recordings, err := client.ListRecordings()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: token saved but API test failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Authenticated. Found %d recordings.\n", len(recordings))
}

// cmdPlaudAuthPassword logs in with an email + password (Plaud's consumer
// password grant) and stores the resulting long-lived (~300-day) token. This is
// the robust replacement for browser token-scraping, no Chrome, no CDP, no
// localStorage. Credentials come from $PLAUD_EMAIL / $PLAUD_PASSWORD when set
// (for automation), otherwise from an interactive prompt (password read without
// echo). Only the resulting token is stored, never the password.
func cmdPlaudAuthPassword() {
	cfg := plaud.LoadConfig()

	email := strings.TrimSpace(os.Getenv("PLAUD_EMAIL"))
	if email == "" {
		email = strings.TrimSpace(promptLine("Plaud email: "))
	}
	password := os.Getenv("PLAUD_PASSWORD")
	if password == "" {
		password = readSecret("Plaud password: ")
	}
	if email == "" || password == "" {
		fmt.Fprintln(os.Stderr, "Error: email and password are required "+
			"(set PLAUD_EMAIL/PLAUD_PASSWORD, or enter them when prompted).")
		os.Exit(1)
	}

	fmt.Println("Logging in to Plaud...")
	session, err := plaud.Login(cfg, email, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Login failed: %v\n", err)
		fmt.Fprintln(os.Stderr, "If your account is Google/Apple-SSO only, set a password via "+
			"'Forgot password' at https://web.plaud.ai, or use 'plaud auth login' (browser).")
		os.Exit(1)
	}
	if err := plaud.SaveToken(cfg.TokenPath, session); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving token: %v\n", err)
		os.Exit(1)
	}

	client := plaud.NewClient(cfg, session.Token)
	recordings, err := client.ListRecordings()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: token saved but API test failed: %v\n", err)
		os.Exit(1)
	}
	exp := "unknown"
	if !session.ExpiresAt.IsZero() {
		exp = session.ExpiresAt.Format("2006-01-02")
	}
	fmt.Printf("Authenticated. Found %d recordings. Token saved to %s (valid until ~%s).\n",
		len(recordings), cfg.TokenPath, exp)
}

// cmdPlaudAuthMCP imports the durable OAuth token minted by the official
// `npx @plaud-ai/mcp login` (Google-SSO, ~300-day, auto-refreshing) from
// ~/.plaud/tokens-mcp.json. This is the no-DevTools, no-daily-re-auth path.
func cmdPlaudAuthMCP() {
	cfg := plaud.LoadConfig()
	path := plaud.DefaultMCPTokenPath()
	session, err := plaud.LoadMCPTokenFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		fmt.Fprintln(os.Stderr, "First, mint the token once (opens a browser for Google/Apple sign-in):")
		fmt.Fprintln(os.Stderr, "  node tools/plaud-mcp-login.mjs")
		fmt.Fprintln(os.Stderr, "(In @plaud-ai/mcp, 'login' is an MCP tool, not a CLI command: `npx … login` just")
		fmt.Fprintln(os.Stderr, " starts the server and hangs; the driver script invokes the tool for you.)")
		fmt.Fprintln(os.Stderr, "then re-run:  m3c-tools plaud auth mcp")
		os.Exit(1)
	}
	// Verify BEFORE saving so an incompatible token can never clobber a working
	// one. (The @plaud-ai/mcp token authenticates against the DEVELOPER API
	// platform.plaud.ai/developer/api, not the consumer api.plaud.ai this client
	// speaks, so this check currently fails for it; a developer-API client is
	// the durable fix. See SPEC-0341.)
	recordings, err := plaud.NewClient(cfg, session.Token).ListRecordings()
	if err != nil {
		fmt.Fprintf(os.Stderr, "The @plaud-ai/mcp token is a DEVELOPER-API token (platform.plaud.ai), not a consumer token.\n")
		fmt.Fprintln(os.Stderr, "Don't import it here: use the durable developer-API path directly:")
		fmt.Fprintln(os.Stderr, "  m3c-tools plaud dev sync --all      (capture → ER1, no browser, no daily re-auth)")
		fmt.Fprintln(os.Stderr, "Your existing consumer token was left untouched.")
		os.Exit(1)
	}
	if err := plaud.SaveToken(cfg.TokenPath, session); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving token: %v\n", err)
		os.Exit(1)
	}
	exp := "unknown"
	if !session.ExpiresAt.IsZero() {
		exp = session.ExpiresAt.Format("2006-01-02")
	}
	fmt.Printf("Authenticated via official MCP OAuth token. Found %d recordings. Saved to %s (valid until ~%s).\n",
		len(recordings), cfg.TokenPath, exp)
}

// cmdPlaudAuthPaste imports the Plaud bearer from the macOS clipboard (falling
// back to stdin): the reliable path for Google/Apple-SSO accounts whose token
// never lands in localStorage. Copy the `authorization` request-header value
// from DevTools → Network (a live api.plaud.ai call), then run `plaud auth paste`.
func cmdPlaudAuthPaste() {
	var raw string
	if out, err := exec.Command("pbpaste").Output(); err == nil && strings.TrimSpace(string(out)) != "" {
		raw = string(out)
	} else if data, rerr := io.ReadAll(os.Stdin); rerr == nil {
		raw = string(data)
	}
	if strings.TrimSpace(raw) == "" {
		fmt.Fprintln(os.Stderr, "Nothing to import. On a logged-in web.plaud.ai tab: DevTools → Network → "+
			"click a live api.plaud.ai request → copy the 'authorization' header value, then run: plaud auth paste")
		os.Exit(1)
	}
	cmdPlaudAuth(strings.TrimSpace(raw))
}

// promptLine reads a single echoed line from stdin (for non-secret input).
func promptLine(prompt string) string {
	fmt.Fprint(os.Stderr, prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

// readSecret reads a line from stdin with terminal echo disabled via stty on the
// controlling terminal (dependency-free). Falls back to echoed input if stty is
// unavailable (e.g. stdin is not a TTY).
func readSecret(prompt string) string {
	fmt.Fprint(os.Stderr, prompt)
	hide := exec.Command("stty", "-echo")
	hide.Stdin = os.Stdin
	if err := hide.Run(); err == nil {
		defer func() {
			show := exec.Command("stty", "echo")
			show.Stdin = os.Stdin
			_ = show.Run()
			fmt.Fprintln(os.Stderr)
		}()
	}
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

// cmdPlaudAuthDispatch parses `plaud auth` arguments and routes to the right
// handler. Supported forms:
//
//	plaud auth password                  email+password login → ~300-day token (recommended)
//	plaud auth login                     extract token from Chrome (CDP): legacy/fragile
//	plaud auth --token-file <path>       read token from a file (secure)
//	plaud auth                           read token from $M3C_PLAUD_TOKEN (secure)
//	plaud auth <token>                   bare argv token (DEPRECATED: leaks via ps)
//
// SEC-M8: the bare-argv form is kept for backward compatibility but emits a
// loud deprecation warning, because command-line arguments are visible to other
// users via ps/argv.
func cmdPlaudAuthDispatch(args []string) {
	if len(args) > 0 && args[0] == "login" {
		cmdPlaudAuthLogin()
		return
	}

	if len(args) > 0 && (args[0] == "--from-er1" || args[0] == "from-er1") {
		cmdPlaudAuthFromER1()
		return
	}

	if len(args) > 0 && (args[0] == "password" || args[0] == "login-password") {
		cmdPlaudAuthPassword()
		return
	}

	if len(args) > 0 && (args[0] == "paste" || args[0] == "clipboard") {
		cmdPlaudAuthPaste()
		return
	}

	if len(args) > 0 && (args[0] == "mcp" || args[0] == "from-mcp") {
		cmdPlaudAuthMCP()
		return
	}

	tokenFile := ""
	bareToken := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--token-file":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--token-file requires a path")
				os.Exit(1)
			}
			tokenFile = args[i+1]
			i++
		case strings.HasPrefix(a, "--token-file="):
			tokenFile = strings.TrimPrefix(a, "--token-file=")
		case !strings.HasPrefix(a, "-") && bareToken == "":
			bareToken = a
		}
	}

	token, argvLeaked, err := plaud.ResolveAuthToken(tokenFile, bareToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		fmt.Fprintln(os.Stderr, "Usage: m3c-tools plaud auth paste            (import the Authorization header from the clipboard: best for SSO accounts)")
		fmt.Fprintln(os.Stderr, "       m3c-tools plaud auth password         (email+password login → ~300-day token)")
		fmt.Fprintln(os.Stderr, "       m3c-tools plaud auth login            (Chrome auto-capture. Fragile vs Plaud's app)")
		fmt.Fprintln(os.Stderr, "       m3c-tools plaud auth --from-er1        (pull from the ER1 vault, SPEC-0304)")
		fmt.Fprintln(os.Stderr, "       m3c-tools plaud auth --token-file <path>")
		fmt.Fprintf(os.Stderr, "       %s=<token> m3c-tools plaud auth\n", plaud.PlaudTokenEnvVar)
		os.Exit(1)
	}
	if argvLeaked {
		fmt.Fprintf(os.Stderr, "WARNING: passing the Plaud token as a command-line argument leaks it to other users via ps/argv.\n")
		fmt.Fprintf(os.Stderr, "         Prefer: %s=<token> m3c-tools plaud auth   (or --token-file <path>)\n", plaud.PlaudTokenEnvVar)
	}
	cmdPlaudAuth(token)
}

func cmdPlaudAuth(token string) {
	cfg := plaud.LoadConfig()
	// Normalize a pasted value (strip "Bearer "/quotes) and record the JWT's real
	// expiry. This is the reliable path for Google/Apple-SSO accounts, whose
	// bearer never lands in localStorage: copy the Authorization header from the
	// DevTools Network tab of a logged-in web.plaud.ai.
	session := plaud.NewImportedTokenSession(token)
	if session.Token == "" {
		fmt.Fprintln(os.Stderr, "Error: no Plaud token (a JWT starting 'eyJ') was found in the input.")
		fmt.Fprintln(os.Stderr, "In DevTools → Network on a logged-in web.plaud.ai tab, click a live api.plaud.ai request,")
		fmt.Fprintln(os.Stderr, "then right-click the 'authorization' header → Copy value, and run: plaud auth paste")
		os.Exit(1)
	}
	if err := plaud.SaveToken(cfg.TokenPath, session); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving token: %v\n", err)
		os.Exit(1)
	}

	// Verify against the API so the user gets immediate confirmation.
	recordings, err := plaud.NewClient(cfg, session.Token).ListRecordings()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: token saved to %s but API test failed: %v\n", cfg.TokenPath, err)
		fmt.Fprintln(os.Stderr, "Copy the *Authorization* request header from a live api.plaud.ai call "+
			"(DevTools → Network) on a logged-in web.plaud.ai tab, then import that value.")
		os.Exit(1)
	}
	exp := "unknown"
	if !session.ExpiresAt.IsZero() {
		exp = session.ExpiresAt.Format("2006-01-02")
	}
	fmt.Printf("Authenticated. Found %d recordings. Token saved to %s (valid until ~%s).\n",
		len(recordings), cfg.TokenPath, exp)
}

func cmdPlaudDebugAPI() {
	cfg := plaud.LoadConfig()
	session, err := plaud.LoadToken(cfg.TokenPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "No token: %v\n", err)
		os.Exit(1)
	}
	client := plaud.NewClient(cfg, session.Token)

	// Get the full list and find sample IDs.
	body, listErr := client.DebugGet("/file/simple/web?skip=0&limit=100&is_trash=2&is_desc=true")
	if listErr != nil {
		fmt.Fprintf(os.Stderr, "List failed: %v\n", listErr)
		os.Exit(1)
	}
	var listResp struct {
		DataFileList []struct {
			ID      string `json:"id"`
			Name    string `json:"filename"`
			IsTrans bool   `json:"is_trans"`
			IsSumm  bool   `json:"is_summary"`
			Dur     int64  `json:"duration"`
		} `json:"data_file_list"`
	}
	json.Unmarshal(body, &listResp) //nolint:errcheck // debug endpoint explorer; an empty list on parse failure is acceptable here
	fmt.Printf("Total recordings in list: %d\n", len(listResp.DataFileList))

	// Find one untranscribed and one transcribed recording.
	var sampleID, transID string
	for _, f := range listResp.DataFileList {
		fmt.Printf("  %s  %-30s  dur=%ds  trans=%v  summ=%v\n",
			f.ID[:8], f.Name, f.Dur/1000, f.IsTrans, f.IsSumm)
		if sampleID == "" {
			sampleID = f.ID
		}
		if transID == "" && f.IsTrans {
			transID = f.ID
		}
	}

	// Try detail endpoint for the sample recording.
	endpoints := []string{}
	if sampleID != "" {
		fmt.Printf("\n=== Sample recording: %s ===\n", sampleID)
		endpoints = append(endpoints,
			"/file/detail/"+sampleID,
			"/file/download/"+sampleID,
			"/file/ori/download/"+sampleID,
			"/file/audio/"+sampleID,
		)
	}
	if transID != "" && transID != sampleID {
		fmt.Printf("\n=== Transcribed recording: %s ===\n", transID)
		endpoints = append(endpoints, "/file/detail/"+transID)
	}
	for _, ep := range endpoints {
		fmt.Printf("\n--- GET %s ---\n", ep)
		body, apiErr := client.DebugGet(ep)
		if apiErr != nil {
			fmt.Printf("ERROR: %v\n", apiErr)
			continue
		}
		s := string(body)
		if len(s) > 2000 {
			s = s[:2000] + "..."
		}
		// Pretty-print JSON if possible.
		var pretty json.RawMessage
		if json.Unmarshal(body, &pretty) == nil {
			if pp, ppErr := json.MarshalIndent(pretty, "", "  "); ppErr == nil {
				s = string(pp)
				if len(s) > 3000 {
					s = s[:3000] + "..."
				}
			}
		}
		fmt.Println(s)
	}
}

// cmdPlaudDev drives the DURABLE developer-API path: the official OAuth token
// from tools/plaud-mcp-login.mjs (~/.plaud/tokens-mcp.json), the platform.plaud.ai
// developer API, and a straight map to ER1. No browser scraping, no ephemeral
// token, no consumer API. See SPEC-0341.
func cmdPlaudDev(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: m3c-tools plaud dev <list|sync|status> [selectors] [flags]")
		fmt.Fprintln(os.Stderr, "  Requires the durable OAuth token:  node tools/plaud-mcp-login.mjs")
		fmt.Fprintln(os.Stderr, "  plaud dev list                       numbered list, newest first")
		fmt.Fprintln(os.Stderr, "  plaud dev sync <#|ID|N-M> ...        sync selected items (numbers from 'dev list')")
		fmt.Fprintln(os.Stderr, "  plaud dev sync --all | --limit N     sync all / the N most recent")
		fmt.Fprintln(os.Stderr, "  plaud dev status                     server-side transcription queue (progress of un-transcribed items)")
		fmt.Fprintln(os.Stderr, "  flags: --dry-run   --force (re-sync)   --tags a,b   --whisper (transcribe un-transcribed audio locally)")
		os.Exit(1)
	}
	// One-time, idempotent: migrate any legacy "plaud-dev" ledger rows to the
	// SHARED consumer format so the menubar and `plaud dev` agree.
	if db, err := tracking.OpenFilesDB(defaultFilesDBPath()); err == nil {
		migratePlaudDevLedger(db)
		db.Close() //nolint:errcheck // best-effort close after a one-time idempotent ledger migration
	}

	switch args[0] {
	case "status":
		cmdPlaudDevStatus()
		return
	case "list":
		preview, limit := false, 0
		for i := 1; i < len(args); i++ {
			a := args[i]
			switch {
			case a == "--preview" || a == "--transcript":
				preview = true
			case a == "--limit" && i+1 < len(args):
				if n, e := strconv.Atoi(args[i+1]); e == nil {
					limit = n
				}
				i++
			}
		}
		cmdPlaudDevList(preview, limit)
	case "sync":
		var selectors []string
		all, dryRun, force, whisper, limit, tags := false, false, false, false, 0, ""
		for i := 1; i < len(args); i++ {
			a := args[i]
			switch {
			case a == "--all":
				all = true
			case a == "--dry-run":
				dryRun = true
			case a == "--force" || a == "-f":
				force = true
			case a == "--whisper":
				whisper = true
			case a == "--tags" && i+1 < len(args):
				tags = args[i+1]
				i++
			case a == "--limit" && i+1 < len(args):
				if n, e := strconv.Atoi(args[i+1]); e == nil {
					limit = n
				}
				i++
			case !strings.HasPrefix(a, "-"):
				selectors = append(selectors, a)
			default:
				fmt.Fprintf(os.Stderr, "Unknown flag: %s\n", a)
				os.Exit(1)
			}
		}
		cmdPlaudDevSync(selectors, all, limit, dryRun, force, whisper, tags)
	default:
		fmt.Fprintf(os.Stderr, "Unknown plaud dev subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

// migratePlaudDevLedger converts any legacy "plaud-dev" tracking rows (an earlier
// dev-sync format that stored the recording ID as FileHash) into the SHARED
// consumer format (path plaud://<id>, importType "plaud"), so the menubar and
// `plaud dev` share one truth. Idempotent; skips rows already in the new format.
func migratePlaudDevLedger(filesDB *tracking.FilesDB) {
	files, err := filesDB.ListFiles(100000)
	if err != nil {
		return
	}
	for _, f := range files {
		if f.ImportType != "plaud-dev" || f.UploadDocID == "" {
			continue
		}
		recID := f.FileHash // legacy rows stored the recording ID as the hash
		plaudPath := "plaud://" + recID
		if existing, _ := filesDB.GetByPath(plaudPath); existing != nil && existing.UploadDocID != "" {
			continue
		}
		h := fmt.Sprintf("%x", sha256.Sum256([]byte(recID)))
		_, _ = filesDB.RecordFile(plaudPath, h, 0, "plaud", "")
		_ = filesDB.RecordUploadSuccess(h, "plaud", f.UploadDocID)
	}
}

// cmdPlaudDevStatus prints the server-side transcription queue (SPEC-0113) so the
// MacPro processing queue draining is visible after a `plaud dev sync` that left
// transcripts to the server. The endpoint (`GET /transcription-queue`) is
// @auth_required but resolves the tenant from `?user_id=` (session or query), NOT
// from the Bearer, so we pass the device-token user id as the query param.
func cmdPlaudDevStatus() {
	er1Cfg := er1.LoadConfig()
	applyRuntimeER1Context(er1Cfg)
	userID := strings.SplitN(er1Cfg.ContextID, "___", 2)[0]
	if userID == "" {
		fmt.Fprintln(os.Stderr, "No ER1 user id (ER1_CONTEXT_ID). Configure ER1 first (check-er1).")
		os.Exit(1)
	}
	base := er1Cfg.APIURL
	for _, s := range []string{"/upload_2", "/upload"} {
		base = strings.TrimSuffix(base, s)
	}
	u := base + "/transcription-queue?user_id=" + neturl.QueryEscape(userID)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	auth.ApplyAuth(req, er1Cfg.APIKey)
	resp, err := (&http.Client{Timeout: 30 * time.Second, CheckRedirect: httpsafe.NoCredentialRedirect}).Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reaching transcription queue: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "transcription-queue: HTTP %d: %.300s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		os.Exit(1)
	}
	fmt.Print(formatTranscriptionQueue(body))
}

// transcriptionQueueItem mirrors one row of audioassistant.transcription_queue.
type transcriptionQueueItem struct {
	DocID       string `json:"doc_id"`
	Status      string `json:"status"`
	Attempt     int    `json:"attempt"`
	MaxAttempts int    `json:"max_attempts"`
	DurationLbl string `json:"audio_duration_label"`
	Preview     string `json:"transcript_preview"`
	ClaimedBy   string `json:"claimed_by"`
}

// formatTranscriptionQueue renders the /transcription-queue JSON into the CLI's
// progress block. Pure (no I/O) so the render is unit-tested offline. Response
// shape: {queue:[…], failed:[…], queue_count:N, failed_count:M}.
func formatTranscriptionQueue(body []byte) string {
	var q struct {
		Queue       []transcriptionQueueItem `json:"queue"`
		Failed      []map[string]any         `json:"failed"`
		QueueCount  int                      `json:"queue_count"`
		FailedCount int                      `json:"failed_count"`
	}
	if err := json.Unmarshal(body, &q); err != nil {
		return fmt.Sprintf("Server-side transcription queue (raw response):\n%.1500s\n", strings.TrimSpace(string(body)))
	}

	if len(q.Queue) == 0 && q.FailedCount == 0 {
		return "Server-side transcription queue: empty: nothing pending, nothing failed. ✅\n"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Server-side transcription queue: %d active · %d failed\n", q.QueueCount, q.FailedCount)
	byStatus := map[string]int{}
	for _, it := range q.Queue {
		byStatus[strings.ToLower(it.Status)]++
	}
	for _, st := range []string{"queued", "processing", "detecting_language", "transcribing", "retry"} {
		if n := byStatus[st]; n > 0 {
			fmt.Fprintf(&b, "  %-18s %d\n", st, n)
		}
	}
	// Per-item detail (bounded) so progress is legible, not just a count.
	if len(q.Queue) > 0 {
		b.WriteString("  ─────\n")
		shown := q.Queue
		if len(shown) > 15 {
			shown = shown[:15]
		}
		for _, it := range shown {
			claim := ""
			if it.ClaimedBy != "" {
				claim = "  ← " + stripCtrl(truncateForLog(it.ClaimedBy, 16))
			}
			fmt.Fprintf(&b, "  %-18s %-10s %2d/%d  %s%s\n",
				stripCtrl(it.Status), it.DurationLbl, it.Attempt, it.MaxAttempts,
				stripCtrl(truncateForLog(it.DocID, 24)), claim)
		}
		if len(q.Queue) > len(shown) {
			fmt.Fprintf(&b, "  … and %d more\n", len(q.Queue)-len(shown))
		}
	}
	return b.String()
}

func newPlaudDevClient() *plaud.DevClient {
	c, err := plaud.NewDevClientFromFile(plaud.DefaultMCPTokenPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	return c
}

// sortDevNewestFirst orders recordings newest-first by StartAt (ISO-8601 strings
// sort chronologically), so list number #1 is the most recent: "the last items".
func sortDevNewestFirst(recs []plaud.DevRecording) {
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].StartAt > recs[j].StartAt })
}

// devWhen renders the developer API's ISO StartAt as LOCAL "YYYY-MM-DD HH:MM".
//
// FR-0095: the API emits a zone-less ISO string that is UTC ("2026-09-03T13:44:14"
// for a recording made at 15:44 CEST). Slicing those 16 characters printed the UTC
// wall clock as if it were local time: every row an hour (CET) or two (CEST) too
// early. Parse, then convert; an unparsable value is shown RAW rather than guessed,
// so a format change from Plaud is visible instead of silently plausible.
func devWhen(iso string) string {
	if t, ok := plaud.ParseDevTime(iso); ok {
		return t.Local().Format("2006-01-02 15:04")
	}
	return iso
}

// stripCtrl removes C0/C1 control bytes (except tab) from untrusted Plaud text
// before it is printed to a terminal, so a hostile recording name/transcript
// cannot inject ANSI/OSC escape sequences.
func stripCtrl(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return r
		}
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return -1
		}
		return r
	}, s)
}

// firstWords returns the first max runes of s (whitespace-collapsed) + "…".
func firstWords(s string, max int) string {
	s = stripCtrl(strings.Join(strings.Fields(s), " "))
	if s == "" {
		return ": "
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

// cmdPlaudDevList prints the numbered, newest-first recording list with each
// item's ER1 sync status + doc_id (from the local tracking DB, no API calls).
// --preview additionally fetches each shown item's transcript first-words (one
// API call per item, so it is bounded to --limit, default 25).
func cmdPlaudDevList(preview bool, limit int) {
	client := newPlaudDevClient()
	recs, err := client.ListRecordings()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	sortDevNewestFirst(recs)
	total := len(recs)

	if limit > 0 && limit < len(recs) {
		recs = recs[:limit]
	} else if preview && limit == 0 && len(recs) > 25 {
		fmt.Fprintln(os.Stderr, "  (transcript preview does one API call per item: showing the 25 most recent; use --limit N for more)")
		recs = recs[:25]
	}

	// Shared sync truth (SAME source as the menubar/consumer `plaud check`):
	// local tracking DB (plaud://<id>) merged with the SPEC-0117 server mapping.
	ids := make([]string, len(recs))
	for i, r := range recs {
		ids[i] = r.ID
	}
	states := resolvePlaudSyncStates(ids, client.AccessToken())

	fmt.Printf("Plaud recordings via developer API (%d, newest first):\n\n", total)
	lastCol := "ID"
	if preview {
		lastCol = "Transcript (first words)"
	}
	fmt.Printf("  %4s  %-16s  %6s  %-7s  %-20s  %s\n", "#", "Recorded", "Dur", "Status", "ER1 Doc", lastCol)
	for i, r := range recs {
		status, docID := "new", ": "
		if st, ok := states[r.ID]; ok {
			if st.DocID != "" {
				docID = st.DocID
			}
			if plaudStateSynced(st) {
				status = "SYNCED"
			} else if st.Status != "" {
				status = st.Status
			}
		}
		last := r.ID
		if preview {
			last = ": "
			if d, derr := client.GetDetail(r.ID); derr == nil {
				txt := d.TranscriptText()
				if txt == "" {
					txt = d.NotesText()
				}
				last = firstWords(txt, 60)
			}
		}
		fmt.Printf("  %4d  %-16s  %6s  %-7s  %-20s  %s\n",
			i+1, devWhen(r.StartAt), plaud.FormatDuration(int(r.Duration/1000)), status, docID, last)
	}
	fmt.Println("\n  Sync selected:  plaud dev sync <#|ID|N-M> ...   ·   all: --all   ·   recent: --limit N   ·   preview: plaud dev list --preview --limit 10")
}

// resolveDevSelection turns list-numbers (1-based, newest-first), N-M ranges and
// full IDs into a concrete recording subset (deduped, order preserved).
func resolveDevSelection(selectors []string, recs []plaud.DevRecording) ([]plaud.DevRecording, error) {
	byID := make(map[string]plaud.DevRecording, len(recs))
	for _, r := range recs {
		byID[r.ID] = r
	}
	var out []plaud.DevRecording
	seen := map[string]bool{}
	add := func(r plaud.DevRecording) {
		if !seen[r.ID] {
			seen[r.ID] = true
			out = append(out, r)
		}
	}
	pick := func(n int) error {
		if n < 1 || n > len(recs) {
			return fmt.Errorf("index %d out of range (1..%d)", n, len(recs))
		}
		add(recs[n-1])
		return nil
	}
	for _, s := range selectors {
		if a, b, ok := parseIntRange(s); ok {
			if a > b {
				a, b = b, a
			}
			for n := a; n <= b; n++ {
				if err := pick(n); err != nil {
					return nil, err
				}
			}
			continue
		}
		if n, err := strconv.Atoi(s); err == nil {
			if err := pick(n); err != nil {
				return nil, err
			}
			continue
		}
		if r, ok := byID[s]; ok {
			add(r)
			continue
		}
		return nil, fmt.Errorf("no recording matches %q (use a 'dev list' number, an N-M range, or a full ID)", s)
	}
	return out, nil
}

// parseIntRange parses "N-M" into (N, M, true); anything else → (0, 0, false).
func parseIntRange(s string) (int, int, bool) {
	i := strings.IndexByte(s, '-')
	if i <= 0 || i >= len(s)-1 {
		return 0, 0, false
	}
	a, e1 := strconv.Atoi(s[:i])
	b, e2 := strconv.Atoi(s[i+1:])
	if e1 != nil || e2 != nil {
		return 0, 0, false
	}
	return a, b, true
}

// cmdPlaudDevSync uploads selected developer-API recordings to ER1 (audio +
// transcript + notes), deduped by recording ID (tracking importType "plaud-dev").
// Selection: explicit <#|ID|N-M> selectors, else --all, else the --limit N most
// recent (default 1). --force re-syncs already-synced items.
// devSyncProgress is called once per item during a dev sync.
// phase is "done" | "skipped" | "failed".
type devSyncProgress func(recID, name, phase, disposition, docID string, err error)

// devSyncTotals summarizes a dev-sync run for a clear progress report.
type devSyncTotals struct {
	Synced, Skipped, Failed       int
	Deferred                      int // BUG-0222: waiting for Plaud's cloud transcript
	Plaud, Queued, Whisper, Audio int // transcript disposition of the synced items
}

// syncOneDevRecording uploads ONE developer-API recording to ER1 (audio +
// transcript + notes) and records it in the SHARED ledger (path plaud://<id>,
// importType "plaud") + the SPEC-0117 server mapping. Returns the ER1 doc_id.
// localWhisperTranscript transcribes MP3 bytes on THIS Mac via the whisper CLI.
// Returns "" if whisper is unavailable or fails (caller falls back to audio-only).

// plaudTranscriptGrace is how long a recording with NO Plaud transcript is left
// alone before we conclude Plaud will never produce one. BUG-0222: an empty
// source_list means two different things, "there will never be a transcript" and
// "the cloud ASR is not finished yet", and the hourly timer reliably hits the
// second case: a recording that stops at :19:38 is read at :20:00, 22 seconds
// later. Treating that as the first case burns the recording, because a synced
// recording is never looked at again. Within the grace window we defer instead.
// PLAUD_TRANSCRIPT_GRACE_MIN tunes it; 0 disables the wait (old behavior).
func plaudTranscriptGrace() time.Duration {
	graceMin := 30
	if v := strings.TrimSpace(os.Getenv("PLAUD_TRANSCRIPT_GRACE_MIN")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			graceMin = n
		}
	}
	return time.Duration(graceMin) * time.Minute
}

// plaudTranscriptPending reports whether a recording without a Plaud transcript
// is merely still being processed. It measures from the END of the recording
// (start + duration), not its start: a 40-minute recording started an hour ago
// stopped 20 minutes ago, and the cloud has had 20 minutes, not 60.
func plaudTranscriptPending(r plaud.DevRecording, grace time.Duration) (bool, time.Duration) {
	if grace <= 0 {
		return false, 0
	}
	start, ok := plaud.ParseDevTime(r.StartAt)
	if !ok {
		return false, 0 // an unreadable timestamp must not stall the recording
	}
	ready := start.Add(time.Duration(r.Duration) * time.Millisecond).Add(grace)
	if wait := time.Until(ready); wait > 0 {
		return true, wait
	}
	return false, 0
}

// plaudDeferForTranscript is THE decision "leave this recording alone for now".
// Both the dry run and the real sync call it, so a preview can never promise a
// sync the real run would defer. That divergence is how the dry run came to
// report WOULD sync for exactly the recordings BUG-0222 was about.
//
// A recording is deferred only when all three hold: no Plaud transcript, the
// caller did not force it, and the cloud has not yet had its grace period.
func plaudDeferForTranscript(r plaud.DevRecording, transcript string, force bool, grace time.Duration) (bool, time.Duration) {
	if force || strings.TrimSpace(transcript) != "" {
		return false, 0
	}
	return plaudTranscriptPending(r, grace)
}

// plaudMaxAudioBytes is the largest audio clip attached to an ER1 upload. Bigger
// clips are dropped (transcript-only) to stay under the ER1 ingress limit: Cloud
// Run / GFE reject requests over ~32 MiB with HTTP 413. Raise PLAUD_MAX_AUDIO_MB to
// mirror important long recordings (up to the ~32MB server cap); lower it if a
// stricter proxy sits in front. Default 30 MB leaves headroom for the multipart
// envelope (transcript + placeholder image + boundaries).
func plaudMaxAudioBytes() int {
	mb := 30
	if v := strings.TrimSpace(os.Getenv("PLAUD_MAX_AUDIO_MB")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			mb = n
		}
	}
	return mb * 1024 * 1024
}

// humanMB formats a byte count as a compact "12.3 MB" string (1 MB = 1024²).
func humanMB(b int) string {
	return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
}

func localWhisperTranscript(audio []byte, id string) string {
	if len(audio) == 0 {
		return ""
	}
	if _, err := whisper.FindBinary(); err != nil {
		log.Printf("[plaud-dev] --whisper set but whisper not found: %v", err)
		return ""
	}
	tmp, err := os.CreateTemp("", "plaud-*.mp3")
	if err != nil {
		return ""
	}
	defer os.Remove(tmp.Name())
	_, _ = tmp.Write(audio)
	_ = tmp.Close()
	txt, werr := whisper.TranscribeTextWithTimeout(tmp.Name(), menubarWhisperModel(), menubarWhisperLanguage(), menubarWhisperTimeout())
	if werr != nil {
		log.Printf("[plaud-dev] whisper failed for %s: %v", id, werr)
		return ""
	}
	return strings.TrimSpace(txt)
}

// syncOneDevRecording uploads ONE recording to ER1 and returns the ER1 doc_id +
// a disposition describing how the transcript was handled:
//
//	"plaud", used Plaud's own server transcript
//	"queued", no transcript → enqueued for SERVER-SIDE whisper (SPEC-0111, DEFAULT)
//	"whisper", no transcript → transcribed LOCALLY (--whisper override)
//	"audio", no transcript and no server-side transcription (audio only)
func syncOneDevRecording(client *plaud.DevClient, er1Cfg *er1.Config, contentType string,
	filesDB *tracking.FilesDB, syncAPI *plaud.SyncAPIClient, accountID string,
	r plaud.DevRecording, tags string, useWhisper, force bool, existingDocID string) (string, string, error) {

	detail, err := client.GetDetail(r.ID)
	if err != nil {
		return "", "", fmt.Errorf("detail: %w", err)
	}
	transcript := detail.TranscriptText()
	notes := detail.NotesText()

	// BUG-0222: read an empty Plaud transcript BEFORE spending an audio download,
	// and do not mistake "not finished yet" for "never". Inside the grace window
	// the recording is DEFERRED: nothing is uploaded, nothing is written to the
	// ledger or the SPEC-0117 mapping, so it stays `new` and the next hourly pass
	// takes it again, with the real text. --force means "do it now anyway".
	if pending, wait := plaudDeferForTranscript(r, transcript, force, plaudTranscriptGrace()); pending {
		log.Printf("[plaud-dev] %s: Plaud has no transcript yet. Deferring for ~%s "+
			"so the cloud can finish; the recording stays unsynced and the next pass retries",
			r.ID, wait.Round(time.Minute))
		return "", "pending", nil
	}

	var audio []byte
	if detail.PresignedURL != "" {
		if audio, err = client.DownloadAudio(detail.PresignedURL); err != nil {
			log.Printf("[plaud-dev] %s audio download failed: %v", r.ID, err)
			audio = nil
		}
	}
	// LOCAL, not UTC: both consumers of this instant, ER1's `current_time` and the
	// composite doc's "Date:" line, format with a ZONE-LESS layout, so whatever
	// zone the time.Time carries becomes the stored wall clock. The other producer
	// of the same ER1 field (the file import, ~line 1261) uses os.FileInfo.ModTime,
	// which is local; without this the two producers disagree by 1-2 h and the
	// braindump corpus mixes both. FR-0095.
	captureTime := parseDevTime(r.StartAt).Local()

	// Cap the attached audio: the ER1 ingress (Cloud Run / Google Front End)
	// rejects requests over ~32 MiB with HTTP 413. Audio is OPTIONAL whenever we
	// have a transcript, so an oversized clip is dropped from the upload. The
	// transcript still lands and the recording stays in Plaud. PLAUD_MAX_AUDIO_MB
	// tunes the cap so important long recordings can still be mirrored (default 30).
	maxAudio := plaudMaxAudioBytes()
	oversized := len(audio) > maxAudio

	// Transcript decision. When Plaud has no transcript, DEFAULT to server-side
	// whisper (the aims-core SPEC-0111 queue on the MacPro); --whisper overrides to
	// transcribe locally. Env PLAUD_TRANSCRIBE_MODE can force lazy/off. An oversized
	// clip cannot be shipped for server-side transcription, so it is forced onto the
	// LOCAL whisper path (we already hold the bytes) before the audio is dropped.
	disposition := "plaud"
	doTranscribe := false
	extraTag := ""
	if transcript == "" {
		if useWhisper || oversized {
			if transcript = localWhisperTranscript(audio, r.ID); transcript != "" {
				disposition = "whisper"
			} else if oversized {
				return "", "", fmt.Errorf(
					"audio %s exceeds the %s upload cap and no transcript is available: "+
						"install whisper for a local fallback (see `doctor`) or raise "+
						"PLAUD_MAX_AUDIO_MB (ER1 accepts up to ~32MB)",
					humanMB(len(audio)), humanMB(maxAudio))
			} else {
				disposition = "audio"
			}
		} else if len(audio) == 0 {
			disposition = "audio" // nothing to transcribe server-side
		} else {
			switch strings.ToLower(strings.TrimSpace(os.Getenv("PLAUD_TRANSCRIBE_MODE"))) {
			case "off":
				disposition = "audio"
			case "lazy":
				extraTag, disposition = "todo.transcribe", "queued"
			default: // "" | "queue" → enqueue server-side (SPEC-0111)
				doTranscribe, disposition = true, "queued"
			}
		}
	}

	// Drop oversized audio from the payload: by here we either had Plaud's
	// transcript or just produced a local one, so the bytes add nothing but 413s.
	if oversized && len(audio) > 0 {
		log.Printf("[plaud-dev] %s audio %s exceeds cap %s. Uploading transcript only; "+
			"recording stays in Plaud (raise PLAUD_MAX_AUDIO_MB to mirror it, ER1 cap ~32MB)",
			r.ID, humanMB(len(audio)), humanMB(maxAudio))
		audio = nil
	}

	allTags := "plaud"
	if extraTag != "" {
		allTags = extraTag + "," + allTags
	}
	if tags != "" {
		allTags += "," + tags
	}
	payload := &er1.UploadPayload{
		TranscriptFilename: fmt.Sprintf("plaud_%s.txt", r.ID),
		ImageFilename:      "placeholder-logo.png",
		Tags:               allTags,
		ContentType:        contentType,
		CurrentTime:        er1.FormatCaptureTime(captureTime),
		DoTranscribe:       doTranscribe,
		DocID:              existingDocID, // asks for an overwrite; NOT honored yet, see BUG-0223
	}
	if len(audio) > 0 {
		payload.AudioData = audio
		payload.AudioFilename = r.ID + ".mp3"
	}
	// Send a transcript body EXCEPT when deferring to the server queue: there the
	// server writes transcript_text itself (matches the consumer path).
	if !doTranscribe {
		impText := fmt.Sprintf("Plaud recording: %s", r.Name)
		if notes != "" {
			impText += "\n\nNotes:\n" + notes
		}
		doc := (&impression.CompositeDoc{
			ObsType:        impression.Import,
			Timestamp:      captureTime,
			TranscriptText: transcript,
			ImpressionText: impText,
		}).Build()
		payload.TranscriptData = []byte(strings.TrimSpace(doc) + "\n")
	}
	// Der Zeilenschluessel wird VOR dem Upload gebildet, damit ihn beide Zweige
	// benutzen koennen. Vorher kehrte der Fehlerzweig zurueck, ohne irgendetwas
	// zu schreiben: ein fehlgeschlagener Upload hinterliess in der lokalen
	// Ablage KEINE Spur. Deshalb stand upload_error dort in 612 Zeilen kein
	// einziges Mal, und die Datenbank kannte nur Erfolg.
	var audioHash, plaudPath string
	if filesDB != nil {
		h := sha256.Sum256(audio)
		if len(audio) == 0 {
			h = sha256.Sum256([]byte(r.ID)) // unique row key when audio is absent
		}
		audioHash = fmt.Sprintf("%x", h)
		plaudPath = "plaud://" + r.ID
	}

	resp, upErr := er1.Upload(er1Cfg, payload)
	if upErr != nil {
		if filesDB != nil {
			_, _ = filesDB.RecordFile(plaudPath, audioHash, int64(len(audio)), "plaud", "")
			_ = filesDB.RecordUploadError(audioHash, "plaud", upErr.Error())
		}
		return "", "", fmt.Errorf("upload: %w", upErr)
	}
	// SHARED local ledger (plaud://<id>, importType "plaud") + SPEC-0117 server
	// mapping: identical to the menubar/consumer sync, so both share one truth.
	if filesDB != nil {
		_, _ = filesDB.RecordFile(plaudPath, audioHash, int64(len(audio)), "plaud", "")
		_ = filesDB.RecordTranscript(audioHash, "plaud", transcript, "")
		if sErr := filesDB.RecordUploadSuccess(audioHash, "plaud", resp.DocID); sErr != nil {
			// Die Ablehnung einer leeren DocID darf nicht verschluckt werden:
			// sonst stuende die Zeile auf 'imported' und niemand wuesste warum.
			_ = filesDB.RecordUploadError(audioHash, "plaud", sErr.Error())
		}
	}
	if syncAPI != nil {
		if mapErr := syncAPI.RegisterMapping(plaud.SyncMapping{
			PlaudAccountID:    accountID,
			PlaudRecordingID:  r.ID,
			ER1DocID:          resp.DocID,
			ER1ContextID:      er1Cfg.ContextID,
			RecordingTitle:    r.Name,
			RecordingDuration: int(r.Duration / 1000),
			AudioSizeBytes:    len(audio),
			TranscriptLength:  len(transcript),
		}); mapErr != nil {
			log.Printf("[plaud-dev] server mapping failed (non-fatal): %v", mapErr)
		}
	}
	return resp.DocID, disposition, nil
}

// runDevSyncByIDs syncs the given recording IDs to ER1, deduped via the SHARED
// sync truth. It is the common core for `plaud dev sync` (CLI) and the menubar
// Plaud Sync, so the two never diverge. prog may be nil.
func runDevSyncByIDs(client *plaud.DevClient, recByID map[string]plaud.DevRecording,
	ids []string, tags string, force, whisper bool, prog devSyncProgress) devSyncTotals {

	var t devSyncTotals
	cfg := plaud.LoadConfig()
	er1Cfg := er1.LoadConfig()
	applyRuntimeER1Context(er1Cfg)
	states := resolvePlaudSyncStates(ids, client.AccessToken())

	filesDB, dbErr := tracking.OpenFilesDB(defaultFilesDBPath())
	if dbErr == nil {
		defer filesDB.Close()
	} else {
		filesDB = nil
	}
	var syncAPI *plaud.SyncAPIClient
	if er1Cfg.APIKey != "" {
		syncAPI = plaud.NewSyncAPIClient(er1Cfg.APIURL, er1Cfg.APIKey, er1Cfg.ContextID, !er1Cfg.VerifySSL)
	}
	accountID := plaud.DeriveAccountIDFromToken(client.AccessToken())

	for _, id := range ids {
		r, ok := recByID[id]
		if !ok {
			t.Failed++
			continue
		}
		if !force && plaudStateSynced(states[id]) {
			t.Skipped++
			if prog != nil {
				prog(id, r.Name, "skipped", "synced", states[id].DocID, nil)
			}
			continue
		}
		docID, disp, err := syncOneDevRecording(client, er1Cfg, cfg.ContentType, filesDB, syncAPI, accountID, r, tags, whisper, force, states[id].DocID)
		if err != nil {
			t.Failed++
			if prog != nil {
				prog(id, r.Name, "failed", "", "", err)
			}
			continue
		}
		// BUG-0222: deferred, not done. Nothing was uploaded and nothing was
		// recorded, so the recording stays `new` and the next pass retries it.
		if disp == "pending" {
			t.Deferred++
			if prog != nil {
				prog(id, r.Name, "deferred", disp, "", nil)
			}
			continue
		}
		t.Synced++
		switch disp {
		case "plaud":
			t.Plaud++
		case "queued":
			t.Queued++
		case "whisper":
			t.Whisper++
		default:
			t.Audio++
		}
		if prog != nil {
			prog(id, r.Name, "done", disp, docID, nil)
		}
	}
	return t
}

func cmdPlaudDevSync(selectors []string, all bool, limit int, dryRun, force, whisper bool, tags string) {
	client := newPlaudDevClient()
	recs, err := client.ListRecordings()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing recordings: %v\n", err)
		os.Exit(1)
	}
	sortDevNewestFirst(recs)

	var todo []plaud.DevRecording
	switch {
	case len(selectors) > 0:
		if todo, err = resolveDevSelection(selectors, recs); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case all:
		todo = recs
	default:
		if limit == 0 {
			limit = 1 // safety: use --all, --limit N, or explicit selectors
		}
		if limit > len(recs) {
			limit = len(recs)
		}
		todo = recs[:limit] // the N most recent
	}

	ids := make([]string, len(todo))
	recByID := make(map[string]plaud.DevRecording, len(todo))
	for i, r := range todo {
		ids[i] = r.ID
		recByID[r.ID] = r
	}

	if dryRun {
		states := resolvePlaudSyncStates(ids, client.AccessToken())
		grace := plaudTranscriptGrace()
		would, wait := 0, 0
		for _, r := range todo {
			if !force && plaudStateSynced(states[r.ID]) {
				continue
			}
			// BUG-0222: a preview that promises a sync the real run would defer is
			// the same misreport in a quieter place. Only recordings still inside
			// the grace window can be deferred, so only those cost a detail call,
			// and that is normally none or one.
			// Only a recording still inside the grace window can be deferred, so
			// only those cost a detail call: normally none or one.
			if pending, _ := plaudTranscriptPending(r, grace); pending && !force {
				if d, derr := client.GetDetail(r.ID); derr == nil {
					if defer_, left := plaudDeferForTranscript(r, d.TranscriptText(), force, grace); defer_ {
						fmt.Printf("  WOULD WAIT: %s  %s  (Plaud transcript not ready, ~%s left)\n",
							r.ID, stripCtrl(r.Name), left.Round(time.Minute))
						wait++
						continue
					}
				}
			}
			fmt.Printf("  WOULD sync: %s  %s\n", r.ID, stripCtrl(r.Name))
			would++
		}
		fmt.Printf("\nDone (dry-run). would_sync=%d  would_wait=%d  of %d selected\n", would, wait, len(todo))
		return
	}

	done := 0
	tot := runDevSyncByIDs(client, recByID, ids, tags, force, whisper, func(id, name, phase, disp, docID string, err error) {
		switch phase {
		case "done":
			done++
			fmt.Printf("  [%d/%d] ✓ %-7s  %s → %s\n", done, len(ids), disp, stripCtrl(name), docID)
		case "deferred":
			done++
			fmt.Printf("  [%d/%d] … waiting   %s (Plaud transcript not ready, retried next pass)\n",
				done, len(ids), stripCtrl(name))
		case "failed":
			done++
			fmt.Fprintf(os.Stderr, "  [%d/%d] ✗ %s: %v\n", done, len(ids), stripCtrl(name), err)
		}
	})
	fmt.Printf("\nDone. synced=%d  skipped(already)=%d  deferred=%d  failed=%d\n",
		tot.Synced, tot.Skipped, tot.Deferred, tot.Failed)
	if tot.Deferred > 0 {
		fmt.Printf("  → %d waiting for Plaud's cloud transcript. They stay unsynced on purpose; "+
			"the next pass takes them WITH the text (--force to sync one now, "+
			"PLAUD_TRANSCRIPT_GRACE_MIN=0 to disable the wait).\n", tot.Deferred)
	}
	if tot.Synced > 0 {
		fmt.Printf("  transcripts: %d Plaud · %d queued(server-side whisper) · %d local-whisper · %d audio-only\n",
			tot.Plaud, tot.Queued, tot.Whisper, tot.Audio)
	}
	if tot.Queued > 0 {
		fmt.Printf("  → %d queued for server-side transcription. Watch it:  m3c-tools plaud dev status\n", tot.Queued)
	}
}

// parseDevTime parses the developer API's timestamps (falls back to now).
// The zone handling lives in plaud.ParseDevTime: see FR-0095.
func parseDevTime(s string) time.Time {
	if t, ok := plaud.ParseDevTime(s); ok {
		return t
	}
	return time.Now()
}

func cmdPlaudList() {
	cfg := plaud.LoadConfig()
	session, err := plaud.LoadToken(cfg.TokenPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading token: %v\nRun: m3c-tools plaud auth <token>\n", err)
		os.Exit(1)
	}
	client := plaud.NewClient(cfg, session.Token)
	recordings, err := client.ListRecordings()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing recordings: %v\n", err)
		os.Exit(1)
	}

	// Resolve sync status + ER1 doc_id: local tracking DB merged with the
	// SPEC-0117 server sync check (so items synced from another Mac still show
	// as synced with their doc_id, instead of a misleading "new").
	ids := make([]string, len(recordings))
	for i, rec := range recordings {
		ids[i] = rec.ID
	}
	states := resolvePlaudSyncStates(ids, session.Token)

	fmt.Printf("Plaud recordings (%d):\n\n", len(recordings))
	fmt.Printf("  %3s  %-32s  %-40s  %6s  %s  %-10s  %s\n", "#", "ID", "Title", "Dur", "Date", "Status", "ER1 Doc")
	fmt.Println("  ---  --------------------------------  ----------------------------------------  ------  ----------  ----------  --------")
	for i, rec := range recordings {
		st := states[rec.ID]
		status := st.Status
		if status == "" {
			status = "new"
		}
		fmt.Printf("  %3d  %-32s  %-40s  %6s  %s  [%-8s]  %s\n",
			i+1,
			truncate(rec.ID, 32),
			truncate(rec.Title, 40),
			plaud.FormatDuration(rec.Duration),
			rec.CreatedAt.Format("2006-01-02"),
			status,
			st.DocID,
		)
	}
	fmt.Println()
	fmt.Println("  Use: plaud sync <#>   ·   plaud check (coverage)   ·   double-click a synced row in the Sync panel to open it")
}

func cmdPlaudSync(recordingID string, force bool, customTags string, filter string, dryRun bool) {
	cfg := plaud.LoadConfig()
	session, err := plaud.LoadToken(cfg.TokenPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading token: %v\nRun: m3c-tools plaud auth <token>\n", err)
		os.Exit(1)
	}
	client := plaud.NewClient(cfg, session.Token)

	// Compile filter regex up-front so we fail fast on invalid input.
	var filterRe *regexp.Regexp
	if filter != "" {
		var reErr error
		filterRe, reErr = regexp.Compile(filter)
		if reErr != nil {
			fmt.Fprintf(os.Stderr, "Invalid --filter regex %q: %v\n", filter, reErr)
			os.Exit(1)
		}
	}

	// Resolve numeric display index (e.g. "33") to real Plaud recording ID.
	if idx, numErr := strconv.Atoi(recordingID); numErr == nil && idx > 0 {
		recordings, listErr := client.ListRecordings()
		if listErr != nil {
			fmt.Fprintf(os.Stderr, "Error listing recordings: %v\n", listErr)
			os.Exit(1)
		}
		if idx > len(recordings) {
			fmt.Fprintf(os.Stderr, "Recording #%d not found (have %d recordings)\n", idx, len(recordings))
			os.Exit(1)
		}
		recordingID = recordings[idx-1].ID
		fmt.Printf("Resolved #%d → %s\n", idx, recordingID)
	}

	// SEC-L9: validate a directly-supplied DocID before it is used in any
	// request path. "all" is the bulk sentinel and is handled separately below.
	if recordingID != "all" {
		if vErr := plaud.ValidateDocID(recordingID); vErr != nil {
			fmt.Fprintf(os.Stderr, "Invalid Plaud recording ID: %v\n", vErr)
			os.Exit(1)
		}
	}

	if force {
		fmt.Println("Force mode: re-downloading and re-uploading (overwriting existing)")
	}
	if customTags != "" {
		fmt.Printf("Custom tags: %s\n", customTags)
	}
	if filter != "" {
		fmt.Printf("Filter regex: %s\n", filter)
	}
	if dryRun {
		fmt.Println("DRY RUN: items will be listed but NOT downloaded or uploaded")
	}

	var ids []string
	// Track titles so dry-run output is informative.
	titleByID := map[string]string{}

	if recordingID == "all" {
		recordings, listErr := client.ListRecordings()
		if listErr != nil {
			fmt.Fprintf(os.Stderr, "Error listing recordings: %v\n", listErr)
			os.Exit(1)
		}

		// Apply title filter first (if any).
		if filterRe != nil {
			filtered := recordings[:0:0]
			for _, rec := range recordings {
				if filterRe.MatchString(rec.Title) {
					filtered = append(filtered, rec)
				}
			}
			fmt.Printf("Filter matched %d / %d recordings.\n", len(filtered), len(recordings))
			recordings = filtered
		}

		if force {
			// Force: sync ALL (matched) recordings, ignoring tracking DB
			for _, rec := range recordings {
				ids = append(ids, rec.ID)
				titleByID[rec.ID] = rec.Title
			}
			fmt.Printf("Force syncing %d recordings...\n", len(ids))
		} else {
			// Normal: skip already-synced, but retry items without ER1 doc_id
			dbPath := defaultFilesDBPath()
			filesDB, dbErr := tracking.OpenFilesDB(dbPath)
			if dbErr != nil {
				log.Printf("[plaud] warning: cannot open tracking DB: %v", dbErr)
			}
			retryCount := 0
			for _, rec := range recordings {
				if filesDB != nil {
					if tracked, lookupErr := filesDB.GetByPath("plaud://" + rec.ID); lookupErr == nil && tracked != nil {
						if tracked.UploadDocID == "" {
							// Tracked but no doc_id: upload failed previously, retry
							ids = append(ids, rec.ID)
							titleByID[rec.ID] = rec.Title
							retryCount++
							continue
						}
						continue // fully synced, skip
					}
				}
				ids = append(ids, rec.ID)
				titleByID[rec.ID] = rec.Title
			}
			if retryCount > 0 {
				fmt.Printf("Retrying %d recordings with missing ER1 doc_id.\n", retryCount)
			}
			if filesDB != nil {
				filesDB.Close() //nolint:errcheck // best-effort close of the read-only tracking DB before syncing
			}
			fmt.Printf("Syncing %d new recordings (of %d after filter).\n", len(ids), len(recordings))
			if len(ids) == 0 {
				fmt.Println("Nothing to sync (all matched items already synced).")
				return
			}
		}
	} else {
		ids = []string{recordingID}
	}

	if dryRun {
		fmt.Println()
		fmt.Println("=== Items that WOULD be synced ===")
		for i, id := range ids {
			title := titleByID[id]
			if title == "" {
				title = "(title unknown: single-ID mode)"
			}
			fmt.Printf("  %3d. %s\n       %s\n", i+1, id, title)
		}
		fmt.Println()
		fmt.Printf("Total: %d items would be synced with tags=%q\n", len(ids), customTags)
		fmt.Println("Re-run without --dry-run to execute.")
		return
	}

	summary, err := runPlaudSyncPipeline(client, cfg, ids, defaultFilesDBPath(), session.Token, nil, force, customTags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sync failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Sync complete: %d synced, %d failed\n", summary.Success, summary.Failed)
}

type plaudSyncSummary struct {
	Total   int
	Success int
	Failed  int
}

func runPlaudSyncPipeline(client *plaud.Client, cfg *plaud.Config, recordingIDs []string, dbPath string, plaudToken string, onProgress func(menubar.BulkProgressEvent), force bool, customTags ...string) (*plaudSyncSummary, error) {
	filesDB, err := tracking.OpenFilesDB(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open tracking db: %w", err)
	}
	defer filesDB.Close()

	er1Cfg := er1.LoadConfig()
	applyRuntimeER1Context(er1Cfg)
	er1Cfg.ContentType = cfg.ContentType

	// Server-side dedup check (SPEC-0117): skipped in force mode
	var syncAPI *plaud.SyncAPIClient
	var plaudAccountID string
	serverSyncAvailable := false
	// Map plaud recording ID → existing ER1 doc_id (for force overwrite)
	existingDocIDs := map[string]string{}

	if er1Cfg.APIKey != "" && plaudToken != "" {
		syncAPI = plaud.NewSyncAPIClient(er1Cfg.APIURL, er1Cfg.APIKey, er1Cfg.ContextID, !er1Cfg.VerifySSL)
		plaudAccountID = plaud.DeriveAccountID(plaudToken)
	}
	if syncAPI != nil && !force {
		checkResult, checkErr := syncAPI.CheckRecordings(plaudAccountID, recordingIDs)
		if checkErr == nil && checkResult != nil {
			serverSyncAvailable = true
			serverSynced := len(checkResult.Synced)
			if serverSynced > 0 {
				log.Printf("[plaud] server check: %d/%d already synced remotely", serverSynced, len(recordingIDs))
				var filtered []string
				for _, id := range recordingIDs {
					if _, alreadySynced := checkResult.Synced[id]; !alreadySynced {
						filtered = append(filtered, id)
					}
				}
				recordingIDs = filtered
			}
		} else {
			log.Printf("[plaud] server sync unavailable, using local tracking only")
		}
	} else if syncAPI != nil && force {
		// Force mode: look up existing doc_ids so we can overwrite
		checkResult, checkErr := syncAPI.CheckRecordings(plaudAccountID, recordingIDs)
		if checkErr == nil && checkResult != nil {
			serverSyncAvailable = true
			for recID, info := range checkResult.Synced {
				if info.ER1DocID != "" {
					existingDocIDs[recID] = info.ER1DocID
					log.Printf("[plaud] force: will overwrite %s → %s", recID, info.ER1DocID)
				}
			}
		}
		log.Printf("[plaud] force mode: skipping dedup, %d existing docs to overwrite", len(existingDocIDs))
	}

	summary := &plaudSyncSummary{Total: len(recordingIDs)}

	for i, recID := range recordingIDs {
		itemName := recID

		// ITEM_START
		if onProgress != nil {
			onProgress(menubar.BulkProgressEvent{
				Event:       "ITEM_START",
				Item:        itemName,
				Index:       i + 1,
				Total:       summary.Total,
				CurrentFile: itemName,
				Phase:       menubar.BulkPhaseQueued,
			})
		}

		// 1. Get recording metadata.
		rec, recErr := client.GetRecording(recID)
		if recErr != nil {
			log.Printf("[plaud] get recording %s FAIL: %v", recID, recErr)
			summary.Failed++
			emitPlaudItemDone(onProgress, itemName, i+1, summary, recErr.Error())
			continue
		}
		itemName = rec.Title

		// 2. Download audio.
		if onProgress != nil {
			onProgress(menubar.BulkProgressEvent{
				Event: "ITEM_PHASE", Item: itemName, Index: i + 1,
				Total: summary.Total, Phase: menubar.BulkPhaseImport, CurrentFile: itemName,
			})
		}
		log.Printf("[plaud] downloading audio for %s (%s)...", recID, rec.Title)
		audioData, audioFmt, dlErr := client.DownloadAudio(recID)
		if dlErr != nil {
			log.Printf("[plaud] download %s FAIL: %v", recID, dlErr)
			summary.Failed++
			emitPlaudItemDone(onProgress, itemName, i+1, summary, dlErr.Error())
			continue
		}
		log.Printf("[plaud] downloaded %d bytes (%s)", len(audioData), audioFmt)

		// 3. Get transcript (Plaud-side).
		if onProgress != nil {
			onProgress(menubar.BulkProgressEvent{
				Event: "ITEM_PHASE", Item: itemName, Index: i + 1,
				Total: summary.Total, Phase: menubar.BulkPhaseTranscribe, CurrentFile: itemName,
			})
		}
		var transcriptText string
		hasPlaudTranscript := false
		tx, txErr := client.GetTranscript(recID)
		if txErr != nil {
			log.Printf("[plaud] no Plaud transcript for %s: %v: transcribe_mode=%s", recID, txErr, cfg.TranscribeMode)
		} else {
			hasPlaudTranscript = true
			transcriptText = tx.Text
			if tx.Summary != "" {
				transcriptText = transcriptText + "\n\n=== SUMMARY ===\n" + tx.Summary
			}
			log.Printf("[plaud] got Plaud transcript for %s (%d chars, summary %d chars)", recID, len(tx.Text), len(tx.Summary))
		}

		// 4. Build composite document (only when Plaud has a transcript).
		now := time.Now()
		var compositeDoc string
		if hasPlaudTranscript {
			compositeDoc = (&impression.CompositeDoc{
				ObsType:           impression.Fieldnote,
				Timestamp:         now,
				RecordingTitle:    rec.Title,
				RecordingDuration: plaud.FormatDuration(rec.Duration),
				TranscriptText:    strings.TrimSpace(transcriptText),
			}).Build()
		}

		tags := impression.BuildFieldnoteTags(rec.Title, impression.OriginTags("plaud://"+recID)...)
		// Prepend default tags from config if set.
		if cfg.DefaultTags != "" {
			tags = cfg.DefaultTags + "," + tags
		}
		// Prepend custom tags from UI if provided.
		if len(customTags) > 0 && customTags[0] != "" {
			tags = strings.TrimSpace(customTags[0]) + "," + tags
		}

		// Transcription decision: when Plaud has no transcript, use config mode.
		doTranscribe := false
		if !hasPlaudTranscript {
			switch cfg.TranscribeMode {
			case plaud.TranscribeModeQueue:
				doTranscribe = true
				log.Printf("[plaud] %s: no transcript, requesting server transcription (queue mode)", recID)
			case plaud.TranscribeModeLazy:
				tags = "todo.transcribe," + tags
				log.Printf("[plaud] %s: no transcript, tagged todo.transcribe (lazy mode)", recID)
			case plaud.TranscribeModeOff:
				log.Printf("[plaud] %s: no transcript: transcription off, audio only", recID)
			}
		}

		// 5. Upload to ER1.
		if onProgress != nil {
			onProgress(menubar.BulkProgressEvent{
				Event: "ITEM_PHASE", Item: itemName, Index: i + 1,
				Total: summary.Total, Phase: menubar.BulkPhaseUpload, CurrentFile: itemName,
			})
		}
		payload := &er1.UploadPayload{
			AudioData:     audioData,
			AudioFilename: fmt.Sprintf("plaud_%s.%s", recID, audioFmt),
			ImageData:     er1.PlaudLogoPNG(),
			ImageFilename: "plaud-logo.png",
			Tags:          tags,
			ContentType:   cfg.ContentType,
			DoTranscribe:  doTranscribe,
			CurrentTime:   er1.FormatCaptureTime(rec.CreatedAt), // position at real recording time
		}
		// Only send transcript when Plaud provided one.
		if hasPlaudTranscript {
			payload.TranscriptData = []byte(strings.TrimSpace(compositeDoc) + "\n")
			payload.TranscriptFilename = fmt.Sprintf("fieldnote_%s.txt", now.Format("20060102_150405"))
		}
		// Force mode: overwrite existing ER1 document if known.
		if force {
			if docID, ok := existingDocIDs[recID]; ok {
				payload.DocID = docID
				log.Printf("[plaud] force: overwriting doc_id=%s", docID)
			}
		}

		resp, upErr := er1.Upload(er1Cfg, payload)
		if upErr != nil {
			log.Printf("[plaud] upload %s FAIL: %v: saving locally", recID, upErr)
			// Fallback: save to ~/plaud-sync/<recID>/ for later re-upload.
			localErr := savePlaudLocally(recID, rec, audioData, audioFmt, compositeDoc, transcriptText, tags)
			if localErr != nil {
				log.Printf("[plaud] local save also FAIL: %v", localErr)
				summary.Failed++
				emitPlaudItemDone(onProgress, itemName, i+1, summary, upErr.Error())
				continue
			}
			log.Printf("[plaud] saved locally to ~/plaud-sync/%s/", recID[:8])
			// Record in tracking DB as locally saved.
			audioHash := fmt.Sprintf("%x", sha256.Sum256(audioData))
			plaudPath := "plaud://" + recID
			_, _ = filesDB.RecordFile(plaudPath, audioHash, int64(len(audioData)), "plaud", "")
			_ = filesDB.RecordTranscript(audioHash, "plaud", strings.TrimSpace(transcriptText), "")
			summary.Success++
			if onProgress != nil {
				onProgress(menubar.BulkProgressEvent{
					Event: "ITEM_DONE", Item: itemName, Index: i + 1,
					Total: summary.Total, Outcome: "ok",
					Done: i + 1, Success: summary.Success, Failed: summary.Failed,
					CurrentFile: itemName, Phase: menubar.BulkPhaseDone,
				})
			}
			continue
		}
		log.Printf("[plaud] upload %s DONE doc_id=%s", recID, resp.DocID)

		// 6. Record in tracking DB.
		audioHash := fmt.Sprintf("%x", sha256.Sum256(audioData))
		plaudPath := "plaud://" + recID
		_, _ = filesDB.RecordFile(plaudPath, audioHash, int64(len(audioData)), "plaud", "")
		_ = filesDB.RecordTranscript(audioHash, "plaud", strings.TrimSpace(transcriptText), "")
		_ = filesDB.RecordUploadSuccess(audioHash, "plaud", resp.DocID)

		// Register mapping on server (SPEC-0117)
		if syncAPI != nil && serverSyncAvailable {
			mapErr := syncAPI.RegisterMapping(plaud.SyncMapping{
				PlaudAccountID:    plaudAccountID,
				PlaudRecordingID:  recID,
				ER1DocID:          resp.DocID,
				ER1ContextID:      er1Cfg.ContextID,
				RecordingTitle:    rec.Title,
				RecordingDuration: rec.Duration,
				AudioFormat:       audioFmt,
				AudioSizeBytes:    len(audioData),
				TranscriptLength:  len(transcriptText),
			})
			if mapErr != nil {
				log.Printf("[plaud] server mapping failed (non-fatal): %v", mapErr)
			}
		}

		summary.Success++
		if onProgress != nil {
			onProgress(menubar.BulkProgressEvent{
				Event: "ITEM_DONE", Item: itemName, Index: i + 1,
				Total: summary.Total, Outcome: "ok",
				Done: i + 1, Success: summary.Success, Failed: summary.Failed,
				CurrentFile: itemName, Phase: menubar.BulkPhaseDone,
				DocID: resp.DocID, // back-fill the doc_id into the panel row
			})
		}
	}

	// Device pairing + heartbeat (SPEC-0126).
	if summary.Success > 0 {
		pairBaseURL := er1BaseURL(er1Cfg.APIURL)
		if pairBaseURL != "" {
			hostname, _ := os.Hostname()
			// Pair Plaud device on first sync.
			_ = er1.PairDevice(context.Background(), pairBaseURL, er1Cfg.APIKey, er1.PairRequest{
				DeviceType:    "plaud",
				DeviceID:      hostname,
				DeviceName:    "Plaud.ai Recorder",
				ClientVersion: version,
			})
			// Heartbeat with sync count.
			if hbErr := er1.DeviceHeartbeat(context.Background(), pairBaseURL, er1Cfg.APIKey, er1.HeartbeatRequest{
				DeviceType:       "plaud",
				DeviceID:         hostname,
				ItemsSyncedDelta: summary.Success,
				ClientVersion:    version,
			}); hbErr != nil {
				log.Printf("[device] plaud heartbeat failed (non-fatal): %v", hbErr)
			}
		}
	}

	return summary, nil
}

// savePlaudLocally saves all captured data for a Plaud recording to ~/plaud-sync/<recID>/
// so it can be re-uploaded to ER1 later.
func savePlaudLocally(recID string, rec *plaud.Recording, audioData []byte, audioFmt string, compositeDoc string, transcriptText string, tags string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home dir: %w", err)
	}
	dir, err := plaud.LocalSyncDir(home, recID)
	if err != nil {
		return fmt.Errorf("local save: %w", err)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}

	// Save audio.
	audioPath := filepath.Join(dir, fmt.Sprintf("audio.%s", audioFmt))
	if err := os.WriteFile(audioPath, audioData, 0600); err != nil {
		return fmt.Errorf("write audio: %w", err)
	}

	// Save composite document.
	docPath := filepath.Join(dir, "fieldnote.txt")
	if err := os.WriteFile(docPath, []byte(compositeDoc), 0600); err != nil {
		return fmt.Errorf("write doc: %w", err)
	}

	// Save raw transcript.
	if transcriptText != "" {
		txPath := filepath.Join(dir, "transcript.txt")
		if err := os.WriteFile(txPath, []byte(transcriptText), 0600); err != nil {
			return fmt.Errorf("write transcript: %w", err)
		}
	}

	// Save metadata.
	meta := map[string]interface{}{
		"recording_id": recID,
		"title":        rec.Title,
		"duration":     rec.Duration,
		"created_at":   rec.CreatedAt.Format(time.RFC3339),
		"synced_at":    time.Now().Format(time.RFC3339),
		"tags":         tags,
		"audio_file":   filepath.Base(audioPath),
		"audio_format": audioFmt,
		"audio_size":   len(audioData),
	}
	metaJSON, _ := json.MarshalIndent(meta, "", "  ")
	metaPath := filepath.Join(dir, "metadata.json")
	if err := os.WriteFile(metaPath, metaJSON, 0600); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}

	return nil
}

func emitPlaudItemDone(onProgress func(menubar.BulkProgressEvent), item string, index int, summary *plaudSyncSummary, errMsg string) {
	if onProgress != nil {
		onProgress(menubar.BulkProgressEvent{
			Event: "ITEM_DONE", Item: item, Index: index,
			Total: summary.Total, Outcome: "failed", Error: errMsg,
			Done: index, Success: summary.Success, Failed: summary.Failed,
			CurrentFile: item, Phase: menubar.BulkPhaseFailed,
		})
	}
}

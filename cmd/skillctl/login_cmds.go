package main

// `skillctl login` + the device-token autoload bootstrap — FR-0043.
//
// Problem (the reported bug): `m3c-tools login` persisted a device token, but
// skillctl only ever read ER1_DEVICE_TOKEN from the environment, so a user who
// had logged in still got 401s unless they manually `export ER1_DEVICE_TOKEN`.
//
// Fix, two halves:
//   - login:    `skillctl login` runs the browser device-pairing flow itself
//               (so a box with only the skillctl binary — e.g. Eric's — is
//               self-sufficient) and persists the token via pkg/auth.
//   - autoload: before any ER1-bound command, if ER1_DEVICE_TOKEN is unset, load
//               the persisted token and export it for the process — mirroring
//               what cmd/m3c-tools/main.go already does for the product binary.

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/auth"
	"github.com/kamir/m3c-tools/pkg/er1login"
)

// networkCommands are the subcommands that talk to ER1 and therefore need a
// device token. Only these trigger autoloadDeviceToken — so offline commands
// (version, keygen, sign, verify-sig, trust, …) never touch the OS keychain.
var networkCommands = map[string]bool{
	"publish":   true,
	"pull":      true,
	"registry":  true,
	"attest":    true,
	"revoke":    true,
	"awareness": true,
	"session":   true,
	"room":      true,
	"runbook":   true,
	"install":   true,
}

// autoloadDeviceToken implements the read-back half of FR-0043. If
// ER1_DEVICE_TOKEN is already set it is left untouched (explicit wins). The
// keychain backend ignores the userID; the encrypted-file backend derives its
// key from it, so we pass ER1_USER_ID — or the sub parsed from ER1_CONTEXT_ID —
// as a best-effort hint for headless/file-backed hosts.
func autoloadDeviceToken(stderr io.Writer) {
	if os.Getenv("ER1_DEVICE_TOKEN") != "" {
		return
	}
	uid := strings.TrimSpace(os.Getenv("ER1_USER_ID"))
	if uid == "" {
		if ctx := os.Getenv("ER1_CONTEXT_ID"); ctx != "" {
			uid = strings.SplitN(ctx, "___", 2)[0]
		}
	}
	token, expired := auth.PersistedBearer(uid)
	switch {
	case token != "":
		_ = os.Setenv("ER1_DEVICE_TOKEN", token)
	case expired:
		fmt.Fprintln(stderr, "[skillctl] your saved device token has expired — run 'skillctl login' to refresh.")
	}
}

// publicER1Base is the default login target. `skillctl login` is the publisher
// pairing flow against the public SaaS — NOT the local dev server. A local
// developer overrides via --base-url or by setting ER1_API_URL.
const publicER1Base = "https://onboarding.guide"

// resolveLoginBase picks the /v2/signin host: explicit --base-url wins, then a
// set ER1_API_URL (upload URL → stripped to its root), else the public SaaS.
func resolveLoginBase(baseFlag, apiURLEnv string) string {
	if b := strings.TrimSpace(baseFlag); b != "" {
		return strings.TrimRight(b, "/")
	}
	if a := strings.TrimSpace(apiURLEnv); a != "" {
		return er1login.BaseURL(a)
	}
	return publicER1Base
}

func runLogin(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(stderr)
	noBrowser := fs.Bool("no-browser", false, "Print the login URL but do not open a browser (headless/SSH).")
	timeout := fs.Duration("timeout", 5*time.Minute, "How long to wait for the browser callback.")
	baseFlag := fs.String("base-url", "", "ER1 server base URL. Default: public SaaS (https://onboarding.guide), or ER1_API_URL if set.")
	logout := fs.Bool("logout", false, "Remove the stored device token and exit.")
	status := fs.Bool("status", false, "Report whether a (non-expired) device token is stored, and exit.")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl login [--no-browser] [--timeout 5m] [--base-url URL]")
		fmt.Fprintln(stderr, "       skillctl login --status | --logout")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *status {
		if auth.HasStoredToken() {
			tok, expired := auth.PersistedBearer(strings.SplitN(os.Getenv("ER1_CONTEXT_ID"), "___", 2)[0])
			if tok != "" {
				fmt.Fprintf(stdout, "Logged in — device token stored (%s).\n", auth.ActiveStoreName())
				return 0
			}
			if expired {
				fmt.Fprintln(stdout, "A device token is stored but has expired — run 'skillctl login'.")
				return 0
			}
		}
		fmt.Fprintln(stdout, "Not logged in — run 'skillctl login'.")
		return 0
	}

	if *logout {
		if err := auth.Clear(); err != nil {
			fmt.Fprintf(stderr, "logout: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "Logged out — device token removed.")
		return 0
	}

	base := resolveLoginBase(*baseFlag, os.Getenv("ER1_API_URL"))
	if base == "" {
		fmt.Fprintln(stderr, "login: cannot determine ER1 base URL — set ER1_API_URL or pass --base-url.")
		return 1
	}

	res, err := er1login.DeviceLogin(base, !*noBrowser, stdout, *timeout)
	if err != nil {
		fmt.Fprintf(stderr, "login failed: %v\n", err)
		return 1
	}
	if res.DeviceToken == "" {
		fmt.Fprintln(stderr, "login failed: the server returned no device token (is device-token issuance enabled on this ER1?).")
		return 1
	}

	dt := &auth.DeviceToken{
		Token:     res.DeviceToken,
		UserID:    res.UserID,
		ContextID: res.ContextID,
		UserName:  res.UserName,
		UserEmail: res.UserEmail,
		DeviceID:  auth.DeviceID(),
		SavedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	if err := auth.Save(dt); err != nil {
		fmt.Fprintf(stderr, "login: token received but could not be saved: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "✓ Logged in as %s — device token saved (%s). skillctl will use it automatically.\n",
		firstNonEmpty(res.UserEmail, res.UserID, res.ContextID, "unknown"), auth.ActiveStoreName())
	return 0
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

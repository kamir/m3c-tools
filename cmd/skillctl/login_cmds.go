package main

// Login persists a native token for consumers that validate its saved origin.

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

// publicER1Base is the default login target. `skillctl login` is the publisher
// pairing flow against the public SaaS, NOT the local dev server. A local
// developer overrides via --base-url or by setting ER1_API_URL.
const publicER1Base = "https://onboarding.guide"

// resolveLoginBase picks the /v2/signin host: explicit --base-url wins, then a
// set ER1_API_URL (upload URL → stripped to its root), else the public SaaS.
func resolveLoginBase(baseFlag, apiURLEnv string) string {
	if b := strings.TrimSpace(baseFlag); b != "" {
		return strings.TrimRight(b, "/")
	}
	if a := strings.TrimSpace(apiURLEnv); a != "" {
		base, err := er1login.LoginBase(a)
		if err != nil {
			return a
		}
		return base
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
				fmt.Fprintf(stdout, "Logged in, device token stored (%s).\n", auth.ActiveStoreName())
				return 0
			}
			if expired {
				fmt.Fprintln(stdout, "A device token is stored but has expired, run 'skillctl login'.")
				return 0
			}
		}
		fmt.Fprintln(stdout, "Not logged in: run 'skillctl login'.")
		return 0
	}

	if *logout {
		if err := auth.Clear(); err != nil {
			fmt.Fprintf(stderr, "logout: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "Logged out: device token removed.")
		return 0
	}

	base := resolveLoginBase(*baseFlag, os.Getenv("ER1_API_URL"))
	binding, err := auth.NewLoginBinding(base)
	if err != nil {
		fmt.Fprintln(stderr, "login: invalid login target; use an HTTPS URL without credentials, query or fragment.")
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
		Binding:   binding,
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
	fmt.Fprintf(stdout, "✓ Logged in as %s: device token saved (%s). Bound consumers can use it; legacy commands require explicit external credentials.\n",
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

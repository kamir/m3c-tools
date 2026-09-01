// token_cmd.go — "m3c-tools token" device-token inspection + emission.
//
// SPEC-0267 FR-0267.12 follow-up: the /plm-export skill (and any shell tooling)
// needs the Bearer device token to call PLM endpoints, but the token is stored
// encrypted at rest with no way to retrieve it for `curl`. `m3c-tools token
// --print` emits just the token so a skill can do:
//
//	export ER1_DEVICE_TOKEN=$(m3c-tools token --print)
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/kamir/m3c-tools/pkg/auth"
	"github.com/kamir/m3c-tools/pkg/er1"
)

// cmdToken implements `m3c-tools token [--print]`.
//
//	(no flag)  human-readable status (configured? user, expiry) — never prints
//	           the raw token.
//	--print    emits ONLY the Bearer token value to stdout (nothing else), for
//	           shell capture. Exit 0 only when a non-expired token exists.
func cmdToken(args []string) {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	doPrint := fs.Bool("print", false, "emit only the Bearer device token to stdout (for shell capture)")
	_ = fs.Parse(args)

	userPart := strings.SplitN(er1.LoadConfig().ContextID, "___", 2)[0]
	token, expired := auth.PersistedBearer(userPart)

	if *doPrint {
		if token == "" {
			if expired {
				fmt.Fprintln(os.Stderr, "device token expired — run: m3c-tools login")
			} else {
				fmt.Fprintln(os.Stderr, "no device token — run: m3c-tools login")
			}
			os.Exit(1)
		}
		fmt.Println(token) // ONLY the token on stdout
		return
	}

	// Status mode — metadata only, never the raw token.
	switch {
	case token != "":
		fmt.Println("device token: configured")
		if dt, err := auth.Load(auth.DeviceID(), userPart); err == nil && dt != nil {
			if dt.UserID != "" {
				fmt.Printf("  user:    %s\n", dt.UserID)
			}
			if dt.ExpiresAt != "" {
				fmt.Printf("  expires: %s\n", dt.ExpiresAt)
			}
		}
		fmt.Println("  capture: export ER1_DEVICE_TOKEN=$(m3c-tools token --print)")
	case expired:
		fmt.Fprintln(os.Stderr, "device token: EXPIRED — run: m3c-tools login")
		os.Exit(1)
	default:
		fmt.Fprintln(os.Stderr, "device token: not configured — run: m3c-tools login")
		os.Exit(1)
	}
}

// token_cmd.go: "m3c-tools token" device-token inspection + emission.
//
// Explicit export requires a matching destination, independent pin and saved binding.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/kamir/m3c-tools/pkg/auth"
	"github.com/kamir/m3c-tools/pkg/er1"
	"github.com/kamir/m3c-tools/pkg/httpsafe"
)

// cmdToken implements `m3c-tools token [--print]`.
//
//	(no flag)  human-readable status (configured? user, expiry): never prints
//	           the raw token.
//	--print    emits ONLY the Bearer token value to stdout (nothing else), for
//	           shell capture. Exit 0 requires a matching destination, pin and non-expired record.
func cmdToken(args []string) {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	doPrint := fs.Bool("print", false, "emit only the Bearer device token to stdout (for shell capture)")
	_ = fs.Parse(args)

	if *doPrint {
		base, pin := os.Getenv("ER1_API_URL"), os.Getenv("ER1_DEVICE_TOKEN_ORIGIN")
		resolved, err := httpsafe.ResolveCredential(base, false, httpsafe.DeferredSecret{
			Binding: httpsafe.CredentialBinding{Version: httpsafe.CredentialBindingVersion, Kind: httpsafe.CredentialDeviceBearer, Origin: pin, Source: "explicit-token-export"},
			Read: func() ([]byte, error) {
				value, err := auth.BoundBearerReadOnly(pin, "")
				return []byte(value), err
			},
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "token export refused: require matching ER1_API_URL, ER1_DEVICE_TOKEN_ORIGIN and a bound, non-expired native token; run login again for legacy entries.")
			os.Exit(1)
		}
		fmt.Println(string(resolved.Secret))
		return
	}
	userPart := strings.SplitN(er1.LoadConfig().ContextID, "___", 2)[0]
	token, expired := auth.PersistedBearer(userPart)

	// Status mode: metadata only, never the raw token.
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
		fmt.Fprintln(os.Stderr, "device token: EXPIRED, run: m3c-tools login")
		os.Exit(1)
	default:
		fmt.Fprintln(os.Stderr, "device token: not configured, run: m3c-tools login")
		os.Exit(1)
	}
}

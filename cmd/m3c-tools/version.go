// version.go — Build metadata injected via ldflags at release time.
//
// No build tags: compiles on all platforms (darwin + !darwin).
//
// Usage (ldflags):
//
//	go build -ldflags "-X main.version=1.5.0 -X main.commit=abc123 -X main.date=2026-04-02"
package main

import "fmt"

// version, commit, and date are set by goreleaser or release.sh via ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func printVersion() {
	fmt.Printf("m3c-tools %s (commit=%s, built=%s)\n", version, commit, date)
}

// bannerArt is the "M3C" ANSI-shadow logo shown at menu-bar / tray startup.
const bannerArt = `
  ███╗   ███╗ ██████╗  ██████╗
  ████╗ ████║ ╚════██╗██╔════╝
  ██╔████╔██║  █████╔╝██║
  ██║╚██╔╝██║  ╚═══██╗██║
  ██║ ╚═╝ ██║ ██████╔╝╚██████╗
  ╚═╝     ╚═╝ ╚═════╝  ╚═════╝
`

// startupBanner prints the logo, tagline, and build version when the app starts.
func startupBanner() {
	fmt.Print(bannerArt)
	fmt.Println("  m3c-tools · Multi-Modal-Memory Capture")
	fmt.Printf("  version %s  ·  commit %s  ·  built %s\n\n", version, commit, date)
}

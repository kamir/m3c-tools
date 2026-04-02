// config_cmd.go — "m3c-tools config" subcommand implementation.
//
// This file has no build tags so it compiles on both darwin and non-darwin platforms.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/kamir/m3c-tools/pkg/config"
)

// cmdConfig dispatches config subcommands: list, show, switch, create, test, import.
func cmdConfig(args []string) {
	if len(args) == 0 {
		printConfigUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		cmdConfigList()
	case "show":
		name := ""
		if len(args) > 1 {
			name = args[1]
		}
		cmdConfigShow(name)
	case "switch":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: m3c-tools config switch <name>")
			os.Exit(1)
		}
		cmdConfigSwitch(args[1])
	case "create":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: m3c-tools config create <name>")
			os.Exit(1)
		}
		cmdConfigCreate(args[1])
	case "test":
		name := ""
		if len(args) > 1 {
			name = args[1]
		}
		cmdConfigTest(name)
	case "import":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: m3c-tools config import <file.env>")
			os.Exit(1)
		}
		cmdConfigImport(args[1])
	case "delete":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: m3c-tools config delete <name>")
			os.Exit(1)
		}
		cmdConfigDelete(args[1])
	default:
		fmt.Fprintf(os.Stderr, "Unknown config subcommand: %s\n", args[0])
		printConfigUsage()
		os.Exit(1)
	}
}

func printConfigUsage() {
	fmt.Println(`m3c-tools config — Configuration profile management

Subcommands:
  list                 List all profiles with active marker
  show [name]          Show profile details (API key masked)
  switch <name>        Switch active profile
  create <name>        Create a new profile from template
  test [name]          Test ER1 connectivity for a profile
  import <file.env>    Import a .env file as a new profile
  delete <name>        Delete a profile (cannot delete active)`)
}

func cmdConfigList() {
	pm := config.NewProfileManager()
	profiles, err := pm.ListProfiles()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing profiles: %v\n", err)
		os.Exit(1)
	}

	active := pm.ActiveProfileName()

	if len(profiles) == 0 {
		fmt.Println("No profiles found.")
		return
	}

	// Print header.
	fmt.Printf("  %-14s  %-26s  %s\n", "PROFILE", "DESCRIPTION", "ER1 URL")

	for _, p := range profiles {
		marker := " "
		if p.Name == active {
			marker = "*"
		}
		desc := p.Description
		if len(desc) > 26 {
			desc = desc[:23] + "..."
		}
		er1URL := p.Vars["ER1_API_URL"]
		if len(er1URL) > 50 {
			er1URL = er1URL[:47] + "..."
		}
		fmt.Printf("%s %-14s  %-26s  %s\n", marker, p.Name, desc, er1URL)
	}
}

func cmdConfigShow(name string) {
	pm := config.NewProfileManager()

	var p *config.Profile
	var err error
	if name == "" {
		p, err = pm.ActiveProfile()
		if err != nil {
			fmt.Fprintf(os.Stderr, "No active profile. Specify a profile name or run: m3c-tools config switch <name>\n")
			os.Exit(1)
		}
	} else {
		p, err = pm.GetProfile(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading profile %q: %v\n", name, err)
			os.Exit(1)
		}
	}

	active := pm.ActiveProfileName()
	activeMarker := ""
	if p.Name == active {
		activeMarker = " (active)"
	}

	fmt.Printf("Profile: %s%s\n", p.Name, activeMarker)
	if p.Description != "" {
		fmt.Printf("Description: %s\n", p.Description)
	}
	fmt.Printf("File: %s\n", p.Path)
	fmt.Println()

	// Print vars, masking API key.
	knownKeys := []string{
		"ER1_API_URL", "ER1_API_KEY", "ER1_CONTEXT_ID", "ER1_CONTENT_TYPE",
		"ER1_UPLOAD_TIMEOUT", "ER1_VERIFY_SSL", "ER1_RETRY_INTERVAL", "ER1_MAX_RETRIES",
		"PLAUD_DEFAULT_TAGS",
	}
	printed := map[string]bool{}
	for _, k := range knownKeys {
		if v, ok := p.Vars[k]; ok {
			display := v
			if strings.Contains(strings.ToUpper(k), "KEY") || strings.Contains(strings.ToUpper(k), "SECRET") {
				display = config.MaskAPIKey(v)
			}
			fmt.Printf("  %s=%s\n", k, display)
			printed[k] = true
		}
	}
	for k, v := range p.Vars {
		if printed[k] {
			continue
		}
		display := v
		if strings.Contains(strings.ToUpper(k), "KEY") || strings.Contains(strings.ToUpper(k), "SECRET") {
			display = config.MaskAPIKey(v)
		}
		fmt.Printf("  %s=%s\n", k, display)
	}
}

func cmdConfigSwitch(name string) {
	pm := config.NewProfileManager()
	if err := pm.SwitchProfile(name); err != nil {
		fmt.Fprintf(os.Stderr, "Error switching profile: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Switched to profile: %s\n", name)

	p, _ := pm.GetProfile(name)
	if p != nil {
		fmt.Printf("  ER1 URL: %s\n", p.Vars["ER1_API_URL"])
	}
}

func cmdConfigCreate(name string) {
	pm := config.NewProfileManager()

	// Check if profile already exists.
	if _, err := pm.GetProfile(name); err == nil {
		fmt.Fprintf(os.Stderr, "Profile %q already exists. Delete it first or choose a different name.\n", name)
		os.Exit(1)
	}

	// Create with sensible defaults.
	vars := map[string]string{
		"ER1_API_URL":        "https://127.0.0.1:8081/upload_2",
		"ER1_API_KEY":        "",
		"ER1_CONTEXT_ID":     "",
		"ER1_CONTENT_TYPE":   "YouTube-Video-Impression",
		"ER1_UPLOAD_TIMEOUT": "600",
		"ER1_VERIFY_SSL":     "true",
		"ER1_RETRY_INTERVAL": "300",
		"ER1_MAX_RETRIES":    "10",
	}

	if err := pm.CreateProfile(name, fmt.Sprintf("Profile %s", name), vars); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating profile: %v\n", err)
		os.Exit(1)
	}

	p, _ := pm.GetProfile(name)
	fmt.Printf("Created profile: %s\n", name)
	if p != nil {
		fmt.Printf("  File: %s\n", p.Path)
	}
	fmt.Printf("  Edit the .env file to set your ER1 credentials, then switch to it:\n")
	fmt.Printf("  m3c-tools config switch %s\n", name)
}

func cmdConfigTest(name string) {
	pm := config.NewProfileManager()

	var p *config.Profile
	var err error
	if name == "" {
		p, err = pm.ActiveProfile()
		if err != nil {
			fmt.Fprintf(os.Stderr, "No active profile. Specify a profile name.\n")
			os.Exit(1)
		}
	} else {
		p, err = pm.GetProfile(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading profile %q: %v\n", name, err)
			os.Exit(1)
		}
	}

	fmt.Printf("Testing profile: %s\n", p.Name)
	fmt.Printf("  ER1 URL: %s\n", p.Vars["ER1_API_URL"])
	fmt.Printf("  API Key: %s\n", config.MaskAPIKey(p.Vars["ER1_API_KEY"]))

	if err := pm.TestConnection(p); err != nil {
		fmt.Fprintf(os.Stderr, "  Connection: FAILED — %v\n", err)
		os.Exit(1)
	}
	fmt.Println("  Connection: OK")
}

func cmdConfigImport(filePath string) {
	pm := config.NewProfileManager()

	// Derive profile name from filename.
	name := filePath
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		name = name[idx+1:]
	}
	if idx := strings.LastIndex(name, "\\"); idx >= 0 {
		name = name[idx+1:]
	}
	name = strings.TrimSuffix(name, ".env")
	// Clean the name: replace non-alphanumeric with hyphens.
	cleaned := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			cleaned = append(cleaned, c)
		} else {
			cleaned = append(cleaned, '-')
		}
	}
	name = string(cleaned)

	if err := pm.ImportProfile(name, filePath); err != nil {
		fmt.Fprintf(os.Stderr, "Error importing profile: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Imported profile: %s\n", name)
	fmt.Printf("  Source: %s\n", filePath)
	fmt.Printf("  Switch to it: m3c-tools config switch %s\n", name)
}

func cmdConfigDelete(name string) {
	pm := config.NewProfileManager()
	if err := pm.DeleteProfile(name); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Deleted profile: %s\n", name)
}

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

// cmdPack implements `skillctl pack` per SPEC-0188 §3 — produce a deterministic
// `.skb` archive from a local skill directory. Phase 1: packing only.
func cmdPack(args []string) {
	skillDir := ""
	outFile := ""
	m := skillbundle.BundleManifest{}
	var dependsOn []string

	take := func(args []string, i int, flag string) string {
		if i >= len(args) {
			fmt.Fprintf(os.Stderr, "Error: %s requires a value\n", flag)
			os.Exit(1)
		}
		return args[i]
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--skill":
			i++
			skillDir = take(args, i, "--skill")
		case "-o", "--output":
			i++
			outFile = take(args, i, "--output")
		case "--name":
			i++
			m.Name = take(args, i, "--name")
		case "--version":
			i++
			m.Version = take(args, i, "--version")
		case "--summary":
			i++
			m.Summary = take(args, i, "--summary")
		case "--source-repo":
			i++
			m.SourceRepo = take(args, i, "--source-repo")
		case "--source-commit":
			i++
			m.SourceCommit = take(args, i, "--source-commit")
		case "--source-path":
			i++
			m.SourcePath = take(args, i, "--source-path")
		case "--governance-level":
			i++
			m.GovernanceLevel = take(args, i, "--governance-level")
		case "--governance-rationale":
			i++
			m.GovernanceRationale = take(args, i, "--governance-rationale")
		case "--compatibility":
			i++
			m.Compatibility = take(args, i, "--compatibility")
		case "--depends-on":
			i++
			dependsOn = append(dependsOn, take(args, i, "--depends-on"))
		default:
			fmt.Fprintf(os.Stderr, "Unknown flag: %s\n", args[i])
			printPackUsage()
			os.Exit(1)
		}
	}

	if skillDir == "" || outFile == "" || m.Name == "" || m.Version == "" {
		fmt.Fprintln(os.Stderr, "Error: --skill, --output, --name, and --version are required.")
		printPackUsage()
		os.Exit(1)
	}

	deps, err := parseDependencies(dependsOn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	m.DependsOn = deps

	digest, err := skillbundle.Pack(skillDir, outFile, skillbundle.PackOptions{
		Manifest: m,
		BuiltBy:  fmt.Sprintf("skillctl/%s", m.Version),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "pack failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("bundle_digest: %s\n", digest)
	fmt.Printf("output:        %s\n", outFile)
}

// parseDependencies parses repeated `--depends-on kind:name:constraint` flags.
// The constraint can itself contain colons (`>=2.31`), so we split on the first
// two only.
func parseDependencies(specs []string) ([]skillbundle.Dependency, error) {
	out := make([]skillbundle.Dependency, 0, len(specs))
	for _, raw := range specs {
		first := strings.Index(raw, ":")
		if first < 0 {
			return nil, fmt.Errorf("invalid --depends-on %q: want kind:name:constraint", raw)
		}
		rest := raw[first+1:]
		second := strings.Index(rest, ":")
		if second < 0 {
			return nil, fmt.Errorf("invalid --depends-on %q: want kind:name:constraint", raw)
		}
		out = append(out, skillbundle.Dependency{
			Kind:       raw[:first],
			Name:       rest[:second],
			Constraint: rest[second+1:],
		})
	}
	return out, nil
}

func printPackUsage() {
	fmt.Fprintln(os.Stderr, `Usage:
  skillctl pack --skill <dir> -o <out.skb> --name <n> --version <v> [options]

Required:
  --skill <dir>            Skill directory containing SKILL.md
  -o, --output <path>      Output .skb file
  --name <s>               Skill name (manifest field)
  --version <s>            Skill version (manifest field)

Optional manifest fields:
  --summary <s>
  --source-repo <s>        e.g. kamir/m3c-tools-maintenance
  --source-commit <sha>
  --source-path <s>
  --governance-level <s>   green | yellow | red
  --governance-rationale <s>
  --compatibility <s>
  --depends-on kind:name:constraint   Repeatable, e.g. python:requests:>=2.31`)
}

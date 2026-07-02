package main

// SPEC-0246 §7 — `skillctl room` maps already-published bundles into (or out
// of) a SPEC-0096 co-learning room by adding/removing the room's bare
// room_label tag on their ER1 event items. Publishing fresh? Prefer
// `skillctl publish --share-room <label>` (stamps at admit time). This verb is
// the back-fill for bundles that are already in the registry.
//
//   skillctl room share   <skill> --room <label> [--digest sha256:..|--all]
//   skillctl room unshare <skill> --room <label> [--digest sha256:..|--all]
//        [--registry self] [--er1-target prod|stage|local] [--er1-context <ctx>]
//        [--dry-run] [--yes]

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

func runRoom(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "Usage: skillctl room <share|unshare> <skill> --room <label> [flags]")
		return 2
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "share":
		return runRoomShare(rest, stdout, stderr, false)
	case "unshare":
		return runRoomShare(rest, stdout, stderr, true)
	default:
		fmt.Fprintf(stderr, "room: unknown subcommand %q (want: share | unshare)\n", sub)
		return 2
	}
}

func runRoomShare(args []string, stdout, stderr io.Writer, unshare bool) int {
	verb := "share"
	if unshare {
		verb = "unshare"
	}
	fs := flag.NewFlagSet("room "+verb, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		room       = fs.String("room", "", "Room label to map into/out of (e.g. aims-basics). Required.")
		skill      = fs.String("skill", "", "Skill name to (un)map. Or pass it as the positional arg.")
		digest     = fs.String("digest", "", "Map only the bundle with this sha256:<hex> digest.")
		all        = fs.Bool("all", false, "Map every m3c-skill-bundle item in the context.")
		registryNm = fs.String("registry", "self", "Registry spec. Only \"self\" / \"er1://...\" are handled here.")
		er1Target  = fs.String("er1-target", envOr("ER1_TARGET", "prod"), "ER1 target: prod | stage | local.")
		er1Context = fs.String("er1-context", envOr("ER1_CONTEXT", "skills"), "ER1 context the bundles live in.")
		dryRun     = fs.Bool("dry-run", false, "Show what would change; do not POST.")
		yes        = fs.Bool("yes", false, "Skip the confirm pause.")
	)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: skillctl room %s [<skill>] --room <label> [--digest sha256:..|--all] [flags]\n", verb)
		fs.PrintDefaults()
	}
	if err := fs.Parse(reorderFlagArgs(fs, args)); err != nil {
		return 2
	}
	// BUG-0165: prefix a bare ER1 context (no "___") with the logged-in owner id,
	// so `room share ... --er1-context skills` targets the canonical <sub>___skills
	// registry instead of the un-owned bare namespace (which finds no items).
	*er1Context = ownerPrefixedContext(*er1Context)
	if !registry.IsER1Registry(*registryNm) {
		fmt.Fprintf(stderr, "room: only ER1 registries (\"self\"/\"er1://...\") are supported; got %q\n", *registryNm)
		return 2
	}
	if *room == "" {
		fmt.Fprintln(stderr, "room: --room <label> required")
		return 2
	}
	skillName := *skill
	if skillName == "" && fs.NArg() >= 1 {
		skillName = fs.Arg(0)
	}
	sel := registry.RoomShareSelector{SkillName: skillName, Digest: *digest, All: *all}
	if !*all && *digest == "" && skillName == "" {
		fmt.Fprintln(stderr, "room: need a skill name (positional or --skill), --digest, or --all")
		return 2
	}

	cfg, err := resolveER1Config(*er1Target)
	if err != nil {
		fmt.Fprintf(stderr, "room: resolve ER1 config: %v\n", err)
		return 1
	}

	what := skillName
	if *all {
		what = "all bundles"
	} else if *digest != "" {
		what = *digest
	}
	fmt.Fprintf(stdout, "==> room %s (%s) room=%q target=%s context=%s\n", verb, what, *room, *er1Target, *er1Context)

	if *dryRun {
		// Resolve the match set read-only so the operator sees the blast radius.
		var extra []string
		if unshare {
			extra = []string{*room} // unshare only touches items already in the room
		}
		preview, perr := registry.MatchRoomItems(cfg, *er1Context, sel, extra...)
		if perr != nil {
			fmt.Fprintf(stderr, "room %s --dry-run: %v\n", verb, perr)
			return 1
		}
		fmt.Fprintf(stdout, "    --dry-run: would %s %d item(s)", verb, len(preview.ItemIDs))
		if len(preview.Skills) > 0 {
			fmt.Fprintf(stdout, " across skills: %s", strings.Join(preview.Skills, ", "))
		}
		fmt.Fprintln(stdout, "\n    re-run without --dry-run to apply.")
		return 0
	}
	if !*yes {
		if !promptYesNo(stdout, fmt.Sprintf("Proceed to %s %q in room %q?", verb, what, *room)) {
			fmt.Fprintln(stdout, "aborted.")
			return 0
		}
	}

	var res *registry.RoomShareResult
	if unshare {
		res, err = registry.UnshareFromRoom(cfg, *er1Context, *room, sel)
	} else {
		res, err = registry.ShareToRoom(cfg, *er1Context, *room, sel)
	}
	if err != nil {
		fmt.Fprintf(stderr, "room %s: %v\n", verb, err)
		return 1
	}
	if res == nil || len(res.ItemIDs) == 0 {
		fmt.Fprintln(stdout, "    no matching items found — nothing changed.")
		return 0
	}
	fmt.Fprintf(stdout, "    %sed %d item(s) %s room %q\n", verb, len(res.ItemIDs),
		map[bool]string{true: "from", false: "into"}[unshare], *room)
	if len(res.Skills) > 0 {
		fmt.Fprintf(stdout, "    skills: %s\n", strings.Join(res.Skills, ", "))
	}
	return 0
}

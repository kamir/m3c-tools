package main

import "strings"

func parseSetupVerb(args []string, platformDefault string) (verb string, rest []string, unknown bool) {
	if len(args) == 0 || strings.HasPrefix(args[0], "--") {
		return platformDefault, args, false
	}
	switch args[0] {
	case "whisper", "er1", "pocket-key":
		return args[0], args[1:], false
	default:
		return args[0], args[1:], true
	}
}

//go:build windows && !allow_home_override_test

package homeroot

// CompiledIn is false for a normal (shipping) Windows build: $HOME is NEVER
// honored for the per-user security paths there. %USERPROFILE% (via
// os.UserHomeDir()) is the only per-user root, fail-closed. The override is
// compiled in only under the `allow_home_override_test` tag (see compiled_on.go),
// which the dev/quickstart sandbox and the windows-latest test surface use.
// WIN-T8 / WIN-09.
const CompiledIn = false

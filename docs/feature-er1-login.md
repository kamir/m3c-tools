# ER1 Browser Login Linking (Feature Track)

## Goal
Replace manual `ER1_CONTEXT_ID` entry in menu-bar workflows with account-based login linking.

## UX
1. User clicks `Login to ER1...` in the M3C menu.
2. App opens `<ER1 base>/login/multi?next=<local-callback-url>` in Chrome.
3. After browser login redirect reaches local callback, app links runtime account context.
4. Menu shows `Account: <context_id>` and all menu uploads use this linked context.
5. User can click `Logout from ER1` to clear runtime link and fall back to `.env` context.

## State Model
- Runtime-only app state (not persisted):
  - `loggedIn` bool
  - `contextID` string
- Logout clears both values.
- Relogin overwrites previous context.
- Optional persistence behind `M3C_ER1_SESSION_PERSIST=true`:
  - Stores context in `~/.m3c-tools/er1_session.json` (or `M3C_ER1_SESSION_FILE`)
  - Restored on app startup
  - Cleared on logout

## Detection Strategy
- Primary: local callback query params (`context_id`, `user_id`, `uid`).
- Fallback: inspect open Chrome tabs on ER1 host and parse context from `/memory/<context_id>/<doc_id>`.

## Current Implementation Scope
- Menu items: Login / Logout / Account status line.
- Browser open through existing Chrome-preferred `openURL` helper.
- Runtime context override applied to menu ER1 upload paths.
- Logging added under `[auth]` and `[tabs]` for diagnostics.

## Known Limitations
- Callback currently depends on ER1 preserving `next` redirect.
- Context extraction fallback needs open ER1 pages in Chrome with `/memory/<context>/...` pattern.
- Persistence is context-id based and currently does not verify session freshness with the server.

## Next Hardening Steps
1. Add explicit callback signature/token validation.
2. Add optional encrypted-at-rest session file.
3. Add integration tests for callback parsing and URL/context extraction.
4. Add explicit menu command to open ER1 profile page for session verification.

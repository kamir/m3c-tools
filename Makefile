# m3c-tools — Multi-Modal-Memory Tools
# Makefile for building, testing, and running e2e tests

BINARY   = m3c-tools
CMD_DIR  = ./cmd/m3c-tools
BUILD_DIR = ./build
APP_NAME = M3C-Tools
APP_BUNDLE = $(BUILD_DIR)/$(APP_NAME).app
APP_ID   = com.kamir.m3c-tools
APP_VERSION ?= $(shell git tag --list 'v*' --sort=-v:refname | head -1 | sed 's/^v//' 2>/dev/null || echo "0.0.0")
ICON_SRC = maindset_icon.png

# Build metadata stamped into the binaries via ldflags (version.go's
# main.version / main.commit / main.date). Local `make build` gets real values
# too — not just the release CI. Release/CI overrides these with the clean tag.
GIT_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo dev)
GIT_COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_DATE  ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GO_LDFLAGS   = -X main.version=$(GIT_VERSION) -X main.commit=$(GIT_COMMIT) -X main.date=$(BUILD_DATE)

# Default: build the CLI
.PHONY: all
all: build

# Install all system dependencies (Homebrew + Python)
.PHONY: deps
deps:
	@echo "Installing system dependencies via Homebrew..."
	brew install pkg-config portaudio ffmpeg
	@echo ""
	@echo "Installing Whisper via pip..."
	python3 -m pip install openai-whisper
	@echo ""
	@echo "All dependencies installed. Run 'make install' to build and install m3c-tools."

# Check that required build/runtime dependencies are available
.PHONY: check-deps
check-deps:
	@missing=""; \
	command -v pkg-config >/dev/null 2>&1 || missing="$$missing pkg-config"; \
	command -v ffmpeg >/dev/null 2>&1     || missing="$$missing ffmpeg"; \
	command -v whisper >/dev/null 2>&1    || missing="$$missing whisper"; \
	if [ -n "$$missing" ]; then \
		echo "ERROR: Missing required dependencies:$$missing"; \
		echo ""; \
		echo "Install them with:"; \
		echo "  make deps"; \
		echo ""; \
		echo "Or manually:"; \
		echo "  brew install pkg-config portaudio ffmpeg"; \
		echo "  python3 -m pip install openai-whisper"; \
		exit 1; \
	fi; \
	echo "All dependencies found."

# Build the main CLI binary
.PHONY: build
build: check-deps
	@echo "Building $(BINARY)... (version $(GIT_VERSION))"
	go build -ldflags="$(GO_LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) $(CMD_DIR)

# Build skillctl scanner
.PHONY: build-skillctl
build-skillctl:
	@echo "Building skillctl..."
	go build -ldflags="$(GO_LDFLAGS)" -o $(BUILD_DIR)/skillctl ./cmd/skillctl

# Build the skillctl-demo tool. It shells out to skillctl (auto-resolved from
# ./build/skillctl first), so build that too.
.PHONY: build-skillctl-demo
build-skillctl-demo: build-skillctl
	@echo "Building skillctl-demo..."
	go build -ldflags="$(GO_LDFLAGS)" -o $(BUILD_DIR)/skillctl-demo ./cmd/skillctl-demo
	@echo "Built $(BUILD_DIR)/skillctl-demo — run: $(BUILD_DIR)/skillctl-demo (or --selftest)"

# Build all commands (including POCs)
.PHONY: build-all
build-all: build build-skillctl build-skillctl-demo
	@echo "Building POCs..."
	go build -o $(BUILD_DIR)/poc-transcript ./cmd/poc-transcript
	go build -o $(BUILD_DIR)/poc-menubar ./cmd/poc-menubar
	go build -o $(BUILD_DIR)/poc-whisper ./cmd/poc-whisper
	go build -o $(BUILD_DIR)/poc-recorder ./cmd/poc-recorder

# Run all e2e tests (verbose, enables YT API calls)
.PHONY: e2e
e2e:
	@echo "Running e2e tests..."
	M3C_YT_CALLS_ENFORCE_ALL=1 go test -v -count=1 ./e2e/ -run TestTranscript
	M3C_YT_CALLS_ENFORCE_ALL=1 go test -v -count=1 ./e2e/ -run TestThumbnail
	go test -v -count=1 ./e2e/ -run TestComposite
	go test -v -count=1 ./e2e/ -run TestBuild
	go test -v -count=1 ./e2e/ -run TestParseTagLine
	go test -v -count=1 ./e2e/ -run TestER1Config
	go test -v -count=1 ./e2e/ -run TestER1Queue
	go test -v -count=1 ./e2e/ -run TestWhisper
	go test -v -count=1 ./e2e/ -run TestRecorderEncodeWAV
	go test -v -count=1 ./e2e/ -run TestRecorderStats

# Fast tests — no network, no hardware, no server
.PHONY: test-unit
test-unit:
	@echo "Running unit tests (offline)..."
	go test -v -count=1 ./e2e/ -run "TestComposite|TestBuild|TestParseTagLine|TestER1Config|TestER1Queue|TestER1EnqueueFailure|TestUploadFailure|TestRecorderEncodeWAV|TestRecorderStats|TestExportsDB|TestFilesDB|TestHashFile|TestFormatterLoader|TestPrettyPrint|TestFormatTranscript|TestFormatSnippet|TestFormatKeyValue|TestFormatTable|TestFormatSection|TestFormatStatusLine|TestBuildApp|TestTranslateFlagParsing|TestTranslateNotTranslatable|TestTranslateTranslatable|TestRetryQueue|TestRetryBackoffTiming|TestRetryBackoffCustomBase|TestRetryProcessingOrder|TestRetryPartialFailure|TestRetryMaxRetriesDropsEntry|TestRetryDropCallback|TestRetryRespectsBackoffDelay|TestRetryProcessesAfterBackoffElapsed|TestRetryGracefulShutdownOnCancel|TestRetryRunStopsOnContextCancel|TestRetryRunProcessesMultipleCycles|TestRetryEmptyQueue|TestRetryOnRetryCallback|TestTranscriptFilterExcludeGenerated|TestTranscriptFilterExcludeManuallyCreated|TestTranscriptFilterBothExcludes|TestTranscriptFilterEmptyList|TestTranscriptFilterAllSameType|TestProxyBuildURL|TestProxyGetTransport|TestProxyNewWithProxy|TestProxyHTTPIntegration|TestProxyWebshare|TestProxySocks5URL|TestRetryRunnerProcessOnce|TestRetryRunnerDropExceedMaxRetries|TestRetryRunnerBackoff|TestRetryRunnerRunLoop|TestRetryRunnerBackoffSkip|TestBackgroundRetryStartsAndProcesses|TestBackgroundRetryStopsGracefully|TestBackgroundRetryHandlesFailures|TestBackgroundRetryEmptyQueue|TestBackgroundRetryLogging|TestTranscriptImportFromSnippets|TestTranscriptImportPreservesMetadata|TestTranscriptListSearchByLanguage|TestTranscriptListSearchGenerated|TestTranscriptListSearchManual|TestTranscriptSearchNotFound|TestTranscriptExportText|TestTranscriptExportSRT|TestTranscriptExportJSON|TestTranscriptExportWebVTT|TestTranscriptExportPretty|TestTranscriptExportAllFormats|TestTranscriptExportToFile|TestTranscriptListString|TestTranscriptListStringEmpty|TestMenubarIntegrationFullLifecycle|TestMenubarIntegrationTranscriptFetcherWired|TestMenubarIntegrationStatusDuringFetch|TestMenubarIntegrationMenuItemsComplete|TestMenubarIntegrationConcurrentStatusUpdates|TestMenubarIntegrationHistoryInMenuUpdates|TestAppBundleLaunchHelp|TestAppBundleLaunchUnknownCommand|TestAppBundleLaunchNoArgs|TestAppBundleRetryGracefulShutdown|TestAppBundleRetryExitsOnSIGINT|TestAppBundleMenubarFlagParsing|TestAppBundleExecPermissions|TestAppBundleInfoPlistLSUIElement|TestScheduleCommand|TestScheduleCommandDuplicate|TestScheduleCommandMissingTranscript|TestStatusCommand|TestStatusCommandEntryNotFound|TestCancelCommand|TestCancelCommandNotFound|TestScheduleStatusCancelWorkflow|TestCLIHelp|TestCLIUnknownCommand|TestCLINoArgs|TestRepoRoot|TestWriteFixture|TestWriteFixtureBytes|TestFixtureDir|TestTempDataDir|TestWithEnv|TestCLIResultAssertions|TestRunCLIWithEnv|TestScreenshotModeConstants|TestScreenshotClipboardImageTypes|TestScreenshotCLIHelpOutput|TestImporterScanDir|TestImporterScanDirEmpty|TestImporterScanDirNotExist|TestImporterScanDirNotDirectory|TestImporterIsAudioFile|TestImporterExtensionList|TestImporterScanDirHiddenSkip|TestImporterScanDirCaseInsensitive|TestImporterScanDirAbsPath|TestImporterScanDirDeepNesting|TestImporterExtensionCoverage|TestImporterCLIExtensions|TestImporterCLIScanDir|TestImporterCLIEmptyDir|TestImporterCLINonexistentDir|TestImporterCLINoArgs|TestFieldnoteCompositeDoc|TestFieldnoteCompositeDocWithNotes|TestFieldnoteTags|TestBuildFieldnoteTags|TestPlaudConfigDefaults|TestPlaudTokenRoundTrip|TestPlaudFormatDuration"

# Network tests — require internet
# By default only runs TestTranscript (lightweight, no thumbnail API calls).
# To include thumbnail + translated transcript tests (higher API load):
#   make test-network M3C_TEST_FULL_NETWORK=1
.PHONY: test-network
test-network:
ifdef M3C_TEST_FULL_NETWORK
	@echo "Running full network tests (transcript + thumbnail + translate)..."
	M3C_YT_CALLS_ENFORCE_ALL=1 go test -v -count=1 ./e2e/ -run "TestTranscript|TestThumbnail|TestTranscriptFetchTranslated"
else
	@echo "Running network tests (transcript only — set M3C_TEST_FULL_NETWORK=1 for all)..."
	M3C_YT_CALLS_ENFORCE_ALL=1 go test -v -count=1 ./e2e/ -run "TestTranscriptList|TestTranscriptFetch|TestTranscriptFormatters|TestTranscriptInvalidVideoID"
endif

# ER1 tests — require running ER1 server
.PHONY: test-er1
test-er1:
	@echo "Running ER1 tests..."
	go test -v -count=1 ./e2e/ -run "TestER1Reachable|TestER1Upload"

# Whisper tests — require whisper binary
.PHONY: test-whisper
test-whisper:
	@echo "Running whisper tests..."
	go test -v -count=1 ./e2e/ -run TestWhisper

# Recorder tests — require PortAudio + microphone
.PHONY: test-recorder
test-recorder:
	@echo "Running recorder tests..."
	go test -v -count=1 ./e2e/ -run TestRecorder

# Build macOS .app bundle
.PHONY: build-app
build-app: build
	@if [ -e "$(APP_BUNDLE)" ] && [ ! -w "$(APP_BUNDLE)" ]; then \
		echo "ERROR: '$(APP_BUNDLE)' exists but is not writable — most likely root-owned"; \
		echo "  from an earlier 'sudo make'. Remove it once (this is the ONLY sudo needed):"; \
		echo "      sudo rm -rf $(APP_BUNDLE)"; \
		echo "  then rebuild WITHOUT sudo:  make build-app   (or: make menubar-app)"; \
		exit 1; \
	fi
	@echo "Building $(APP_NAME).app bundle..."
	@rm -rf $(APP_BUNDLE)
	@mkdir -p $(APP_BUNDLE)/Contents/MacOS
	@mkdir -p $(APP_BUNDLE)/Contents/Resources
	@cp $(BUILD_DIR)/$(BINARY) $(APP_BUNDLE)/Contents/MacOS/$(BINARY)
	@if [ -f "$(ICON_SRC)" ]; then \
		cp $(ICON_SRC) $(APP_BUNDLE)/Contents/Resources/icon.png; \
		if command -v sips >/dev/null 2>&1 && command -v iconutil >/dev/null 2>&1; then \
			ICONSET=$$(mktemp -d)/icon.iconset && \
			mkdir -p "$$ICONSET" && \
			sips -z 16 16     $(ICON_SRC) --out "$$ICONSET/icon_16x16.png"      >/dev/null 2>&1; \
			sips -z 32 32     $(ICON_SRC) --out "$$ICONSET/icon_16x16@2x.png"   >/dev/null 2>&1; \
			sips -z 32 32     $(ICON_SRC) --out "$$ICONSET/icon_32x32.png"      >/dev/null 2>&1; \
			sips -z 64 64     $(ICON_SRC) --out "$$ICONSET/icon_32x32@2x.png"   >/dev/null 2>&1; \
			sips -z 128 128   $(ICON_SRC) --out "$$ICONSET/icon_128x128.png"    >/dev/null 2>&1; \
			sips -z 256 256   $(ICON_SRC) --out "$$ICONSET/icon_128x128@2x.png" >/dev/null 2>&1; \
			sips -z 256 256   $(ICON_SRC) --out "$$ICONSET/icon_256x256.png"    >/dev/null 2>&1; \
			sips -z 512 512   $(ICON_SRC) --out "$$ICONSET/icon_256x256@2x.png" >/dev/null 2>&1; \
			sips -z 512 512   $(ICON_SRC) --out "$$ICONSET/icon_512x512.png"    >/dev/null 2>&1; \
			sips -z 1024 1024 $(ICON_SRC) --out "$$ICONSET/icon_512x512@2x.png" >/dev/null 2>&1; \
			iconutil -c icns "$$ICONSET" -o $(APP_BUNDLE)/Contents/Resources/icon.icns 2>/dev/null \
				&& echo "  Generated icon.icns" || true; \
			rm -rf "$$(dirname $$ICONSET)"; \
		fi; \
	fi
	@printf '<?xml version="1.0" encoding="UTF-8"?>\n\
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n\
<plist version="1.0">\n\
<dict>\n\
	<key>CFBundleName</key>\n\
	<string>$(APP_NAME)</string>\n\
	<key>CFBundleIdentifier</key>\n\
	<string>$(APP_ID)</string>\n\
	<key>CFBundleVersion</key>\n\
	<string>$(APP_VERSION)</string>\n\
	<key>CFBundleShortVersionString</key>\n\
	<string>$(APP_VERSION)</string>\n\
	<key>CFBundleExecutable</key>\n\
	<string>$(BINARY)</string>\n\
	<key>CFBundleDisplayName</key>\n\
	<string>$(APP_NAME)</string>\n\
	<key>CFBundleIconFile</key>\n\
	<string>icon</string>\n\
	<key>CFBundlePackageType</key>\n\
	<string>APPL</string>\n\
	<key>LSUIElement</key>\n\
	<true/>\n\
	<key>NSHighResolutionCapable</key>\n\
	<true/>\n\
	<key>NSMicrophoneUsageDescription</key>\n\
	<string>M3C Tools needs microphone access to record voice impressions.</string>\n\
	<key>NSScreenCaptureUsageDescription</key>\n\
	<string>M3C Tools needs screen capture access for screenshot observations.</string>\n\
</dict>\n\
</plist>\n' > $(APP_BUNDLE)/Contents/Info.plist
	@echo "Built $(APP_BUNDLE)"

# Create Python venv and install whisper
.PHONY: setup-venv
setup-venv:
	@./scripts/setup-venv.sh

# Recreate Python venv from scratch
.PHONY: setup-venv-force
setup-venv-force:
	@./scripts/setup-venv.sh --force

# Build macOS DMG installer
.PHONY: dmg
dmg: build-app
	@./scripts/make-dmg.sh $(APP_VERSION)

# Install CLI to /usr/local/bin and .app to /Applications
.PHONY: install
install: build-app
	@echo "Installing $(BINARY) to /usr/local/bin/$(BINARY)..."
	@cp $(BUILD_DIR)/$(BINARY) /usr/local/bin/$(BINARY)
	@chmod 755 /usr/local/bin/$(BINARY)
	@echo "Installing $(APP_NAME).app to /Applications/..."
	@rm -rf /Applications/$(APP_NAME).app
	@cp -r $(APP_BUNDLE) /Applications/$(APP_NAME).app
	@mkdir -p $(HOME)/.m3c-tools
	@echo "Installed:"
	@echo "  CLI:  /usr/local/bin/$(BINARY)"
	@echo "  App:  /Applications/$(APP_NAME).app"
	@echo "  Data: ~/.m3c-tools/"
	@echo ""
	@echo "Run 'make permissions' to configure macOS privacy settings."

# Grant macOS privacy permissions for Screen Recording, Microphone,
# Accessibility, and Input Monitoring. Opens System Settings panes
# one at a time — waits for user to press Enter before opening the next.
.PHONY: permissions
permissions:
	@echo "=== macOS Permissions for $(APP_NAME) ($(APP_ID)) ==="
	@echo ""
	@echo "The app requires these permissions:"
	@echo "  1. Screen Recording  — screenshot capture"
	@echo "  2. Microphone        — voice recording"
	@echo "  3. Accessibility     — window/app interaction"
	@echo "  4. Input Monitoring  — keystroke capture"
	@echo ""
	@echo "Toggle ON '$(APP_NAME)' in each pane (add with '+' if not listed)."
	@echo "Close System Settings before pressing Enter for the next step."
	@echo ""
	@bash -c '\
		panes=( \
			"Privacy_ScreenCapture:Screen Recording" \
			"Privacy_Microphone:Microphone" \
			"Privacy_Accessibility:Accessibility" \
			"Privacy_ListenEvent:Input Monitoring" \
		); \
		for i in $${!panes[@]}; do \
			IFS=":" read -r pane label <<< "$${panes[$$i]}"; \
			step=$$((i+1)); \
			echo "[$$step/4] $$label"; \
			open "x-apple.systempreferences:com.apple.preference.security?$$pane" 2>/dev/null || \
				open "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?$$pane" 2>/dev/null || true; \
			if [ $$step -lt 4 ]; then \
				read -p "  Press Enter after enabling $$label... " dummy; \
			fi; \
		done; \
		echo ""; \
		echo "All permissions configured. Restart $(APP_NAME):"; \
		echo "  open /Applications/$(APP_NAME).app"; \
	'

# Uninstall CLI and .app
.PHONY: uninstall
uninstall:
	@echo "Uninstalling $(BINARY)..."
	@rm -f /usr/local/bin/$(BINARY)
	@rm -rf /Applications/$(APP_NAME).app
	@echo "Removed /usr/local/bin/$(BINARY) and /Applications/$(APP_NAME).app"
	@echo "Note: ~/.m3c-tools/ data directory preserved. Remove manually if desired."

# Run the CLI
.PHONY: run
run: build
	$(BUILD_DIR)/$(BINARY) $(ARGS)

# Run the menu bar app (foreground: live stdout logs, Ctrl-C to quit).
# menuet unconditionally touches [UNUserNotificationCenter currentNotificationCenter]
# at startup (createAndRunApplication -> initNotifications). On macOS 14+ that API
# HARD-ASSERTS ("bundleProxyForCurrentProcess is nil") unless the running executable
# lives inside a .app bundle — so the old bare-binary run ($(BUILD_DIR)/$(BINARY))
# aborts on launch. Running the bundle's INNER executable directly gives a valid
# bundle proxy (verified: notification init succeeds) while keeping the foreground
# stdout dev workflow — unlike `menubar-app`, which detaches via `open`.
.PHONY: menubar
menubar: check-not-root build-app
	@echo "Running $(APP_NAME).app (foreground; Ctrl-C to quit). Logs also at: ~/.m3c-tools/m3c-tools.log"
	$(APP_BUNDLE)/Contents/MacOS/$(BINARY) menubar $(ARGS)

# Guard: the menu bar app MUST run as the logged-in user, never as root. A GUI
# menu-bar app launched via `sudo` renders a broken menu — no Quit, no Sign-In
# (BUG-0192). This runs before build-app so a `sudo make menubar-app` fails
# fast without creating root-owned artifacts.
.PHONY: check-not-root
check-not-root:
	@if [ "$$(id -u)" = "0" ]; then \
		echo "ERROR: do NOT run this with sudo."; \
		echo "  The menu bar app must run as your login user, or macOS renders a broken"; \
		echo "  menu (no Quit / no Sign-In — BUG-0192)."; \
		echo "  If '$(APP_BUNDLE)' is root-owned from an earlier sudo run, remove it once:"; \
		echo "      sudo rm -rf $(APP_BUNDLE)"; \
		echo "  then run WITHOUT sudo:  make menubar-app"; \
		exit 1; \
	fi

# Build + launch the BUNDLED menu bar app (.app). Unlike `make menubar` (which
# runs the bare binary), this runs inside a proper application bundle — which is
# what macOS needs to reliably render the menu bar icon AND show notifications.
# Prefer this over `make menubar` for anything but quick CLI-style debugging.
# MUST be run WITHOUT sudo (see check-not-root / BUG-0192).
.PHONY: menubar-app
menubar-app: check-not-root build-app
	@echo "Launching $(APP_BUNDLE) (bundled — menu bar icon + notifications work here)..."
	@open $(APP_BUNDLE)
	@echo "Running as a menu bar app. Logs: ~/.m3c-tools/m3c-tools.log"
	@echo "Quit from the menu bar's Quit item, or: pkill -f '$(APP_NAME).app/Contents/MacOS/$(BINARY)'"

# Clean build artifacts
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

# Create a new git worktree under wt/ following the project convention.
# Usage: make worktree SPEC=spec-0195 STEP=awareness-S2.1 BRANCH=s2-m1/awareness-sync [BASE=origin/master]
#
# Convention enforced:
#   - directory:  ../wt/<SPEC>/<STEP>
#   - branch:     <BRANCH> (created from BASE if it doesn't exist)
#   - one branch per worktree, one worktree per active branch
#
# After creation, run `git wta` from any worktree to see the full inventory.
.PHONY: worktree
worktree:
	@if [ -z "$(SPEC)" ] || [ -z "$(STEP)" ] || [ -z "$(BRANCH)" ]; then \
		echo "Usage: make worktree SPEC=spec-XXXX STEP=name BRANCH=feat/name [BASE=origin/master]"; \
		exit 2; \
	fi
	@base=$${BASE:-origin/master}; \
	wtpath="../wt/$(SPEC)/$(STEP)"; \
	if [ -e "$$wtpath" ]; then echo "$$wtpath already exists"; exit 2; fi; \
	if git show-ref --verify --quiet "refs/heads/$(BRANCH)"; then \
		echo "Branch $(BRANCH) exists — attaching worktree to it"; \
		git worktree add "$$wtpath" "$(BRANCH)"; \
	else \
		echo "Creating branch $(BRANCH) from $$base"; \
		git worktree add -b "$(BRANCH)" "$$wtpath" "$$base"; \
	fi
	@echo "✓ worktree created at $$wtpath on branch $(BRANCH)"

# Audit all worktrees: which branch, how old, how dirty.
# Mirrors the `git wta` global alias for users who haven't installed it.
.PHONY: branches-audit
branches-audit:
	@printf "%-50s %-30s %-15s %s\n" "PATH" "BRANCH" "AGE" "DIRTY"
	@git worktree list --porcelain | awk '/^worktree/{print $$2}' | while read -r wt; do \
		cd "$$wt" 2>/dev/null || continue; \
		branch=$$(git branch --show-current 2>/dev/null); \
		age=$$(git log -1 --format='%cr' HEAD 2>/dev/null); \
		dirty=$$(git status --porcelain 2>/dev/null | wc -l | tr -d ' '); \
		flag=""; [ "$$dirty" -gt 0 ] && flag=" ⚠"; \
		printf "%-50s %-30s %-15s %s%s\n" "$$wt" "$$branch" "$$age" "$$dirty" "$$flag"; \
	done

# Check all packages compile
.PHONY: vet
vet:
	go vet ./...

# Pre-release code review (build, vet, tests, secrets, dead code, deps)
.PHONY: code-review
code-review:
	@./scripts/code-review.sh

# Check documentation consistency with implementation
.PHONY: check-docs
check-docs:
	@./scripts/check-docs.sh

# Release targets — code review + docs check run before release
#
# `release` LEITET die Stufe aus den Commits ab (scripts/derive-bump.sh), statt
# sie zu raten. Vorher war es fest `release-patch` verdrahtet: deshalb ist der
# Fleet-Kill-Switch (FR-0045) als v2.8.1 ausgeliefert worden — eine Patch-Nummer
# fuer ein Feature. Gegenprobe an der Historie: die Regel haette genau diesen
# Fall gefangen und stimmt sonst mit den menschlichen Entscheidungen ueberein.
#
# MAJOR wird nie automatisch vergeben. "Breaking" ist eine Aussage ueber die
# AUFRUFER, und die sieht kein Diff — bei drei ueber HTTP verdrahteten Systemen
# ist das keine Formalie. Der Ableiter bricht dann ab und verlangt die
# ausdrueckliche Handlung `make release-major`.
.PHONY: release release-auto release-patch release-minor release-major
release: code-review check-docs release-auto

release-auto:
	@lvl=$$(./scripts/derive-bump.sh); \
	echo "abgeleitete Stufe aus den Commits: $$lvl"; \
	if [ "$$lvl" = "major" ]; then \
	  echo ""; \
	  echo "  Die Commits enthalten eine Breaking Change (! oder BREAKING CHANGE:)."; \
	  echo "  Ein Major-Release wird nicht automatisch vergeben."; \
	  echo "  Bewusst ausloesen mit:  make release-major"; \
	  exit 1; \
	fi; \
	./scripts/release.sh "$$lvl"

release-patch:
	@./scripts/release.sh patch

release-minor: code-review check-docs
	@./scripts/release.sh minor

release-major: code-review check-docs
	@./scripts/release.sh major

# ── skillctl release chain (docs/releasing.md · skill: /release-skillctl) ──────
# skillctl is a SEPARATE, tag-driven line (skillctl/vX.Y.Z → skillctl-release.yml);
# `release-skillctl` runs every PRE-TAG gate for it, then prints the derived
# version context + the next step. It deliberately does NOT tag — tagging
# origin/master BY HASH is the confirmed manual step (the point of no return).
.PHONY: release-skillctl skillctl-smoke
release-skillctl: build-skillctl build-skillctl-demo vet lint check-docs
	@echo "→ skillctl pre-tag gates (race tests + boundary)…"
	@go test -race -count=1 ./cmd/skillctl/... ./pkg/skillctl/...
	@./tools/boundary-gate.sh
	@last=$$(git tag --list 'skillctl/v*' --sort=-v:refname | head -1); \
	 echo ""; \
	 echo "  last skillctl tag : $$last"; \
	 echo "  commits since     : $$(git rev-list --count $$last..origin/master 2>/dev/null) on origin/master"; \
	 echo ""; \
	 echo "  ✓ pre-tag gates green. Next: sync CHANGELOG, then tag origin/master BY HASH"; \
	 echo "    (skillctl/vX.Y.Z) + push — see docs/releasing.md / the /release-skillctl skill."

# Smoke-test a PUBLISHED skillctl release build (Phase 4). VERSION defaults to latest tag.
#   make skillctl-smoke                     # smoke the latest published skillctl/v*
#   make skillctl-smoke VERSION=skillctl/v0.4.0
skillctl-smoke:
	@./scripts/skillctl-smoke.sh $(VERSION)

# Build with GoReleaser (snapshot, no publish — for local testing)
.PHONY: snapshot
snapshot:
	goreleaser release --snapshot --clean

# Generate checksums for local builds
.PHONY: checksums
checksums:
	@cd $(BUILD_DIR) && shasum -a 256 * > checksums.txt
	@echo "Checksums written to $(BUILD_DIR)/checksums.txt"
	@cat $(BUILD_DIR)/checksums.txt

# Run CI checks locally (mirrors .github/workflows/ci.yml)
.PHONY: ci
ci: vet lint test-unit build
	@echo ""
	@echo "CI passed: vet ✓  lint ✓  test ✓  build ✓"

# Run golangci-lint
.PHONY: lint
lint:
	@echo "Running golangci-lint..."
	golangci-lint run --timeout=5m

# SPEC-0280 trust-layer evaluation harness (E1–E10).
# `eval` runs the full measured harness and regenerates results/RESULTS.{csv,md}.
# `eval-fast` runs only the correctness drivers (E4 real corpus + E10 matrix),
# which also run in plain CI and fail on a safety/threshold regression.
.PHONY: eval eval-fast
eval:
	@echo "Running SPEC-0280 evaluation harness (RUN_EVAL=1)..."
	RUN_EVAL=1 go test ./evaluation/ -run 'TestE|TestZZZ' -v -timeout 30m
	EVAL_CPU="$${EVAL_CPU:-$$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)}" \
		go run ./evaluation/cmd/results-md evaluation/results

eval-fast:
	@echo "Running SPEC-0280 correctness drivers (E4 + E10)..."
	go test ./evaluation/ -run 'TestE4|TestE10' -v

# Windows dev test gate (SPEC-0128): vet + cross-compile + Windows-safe tests + smoke
.PHONY: test-gate-windows
test-gate-windows:
	@./scripts/test-gate-windows.sh

# Same as above but skip the test phase (just compile check)
.PHONY: test-gate-windows-quick
test-gate-windows-quick:
	@./scripts/test-gate-windows.sh --quick

# Cross-compile for Windows (amd64, no CGO)
.PHONY: build-windows
build-windows:
	@echo "Cross-compiling for Windows (amd64)..."
	@mkdir -p $(BUILD_DIR)/windows
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w $(GO_LDFLAGS)" -o $(BUILD_DIR)/windows/m3c-tools.exe $(CMD_DIR)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w $(GO_LDFLAGS)" -o $(BUILD_DIR)/windows/skillctl.exe ./cmd/skillctl
	cp design/icons/menubar-icon.png $(BUILD_DIR)/windows/
	@echo "Windows binaries in $(BUILD_DIR)/windows/"

# Build NSIS installer for Windows (requires: brew install nsis)
.PHONY: installer-windows
installer-windows: build-windows
	@echo "Building NSIS installer..."
	makensis scripts/installer.nsi
	@echo "Installer: $(BUILD_DIR)/M3C-Tools-Setup.exe"

# -----------------------------------------------------------------------------
# Thinking Engine (SPEC-0167) — Phase 1 Week 1 scaffold
# -----------------------------------------------------------------------------

THINKING_BIN        = thinking-engine
THINKING_CMD_DIR    = ./cmd/thinking-engine
THINKING_COMPOSE    = deploy/thinking-engine/docker-compose.yml
THINKING_DOCKERFILE = deploy/thinking-engine/Dockerfile
THINKING_IMAGE      = m3c/thinking-engine
ENGINE_TAG         ?= dev

# Build the thinking-engine binary. Pure Go, no CGO.
.PHONY: thinking-build
thinking-build:
	@echo "Building $(THINKING_BIN)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -o $(BUILD_DIR)/$(THINKING_BIN) $(THINKING_CMD_DIR)

# Run unit tests for the thinking packages only (no Kafka required).
.PHONY: thinking-test
thinking-test:
	@echo "Running thinking-engine unit tests (offline, -short)..."
	go test -short -count=1 ./internal/thinking/...

# Run the tagged unit tests for the franz-go driver. These still do
# NOT need a broker — they exercise the isolation guard and
# consumer-group naming logic with no network I/O.
.PHONY: thinking-test-tagged
thinking-test-tagged:
	@echo "Running thinking-engine tagged unit tests (thinking_kafka, no broker needed)..."
	go test -tags thinking_kafka -count=1 ./internal/thinking/kafka/...

# Run the real-broker integration test. Requires M3C_KAFKA_URL.
# Automatically skipped in the test file if the env var is empty.
.PHONY: thinking-test-integration
thinking-test-integration:
	@if [ -z "$$M3C_KAFKA_URL" ]; then \
		echo "thinking-test-integration: M3C_KAFKA_URL not set — skipping."; \
		echo "To run against a local broker:"; \
		echo "  make thinking-up CTX_HASH=<hash>"; \
		echo "  M3C_KAFKA_URL=localhost:9092 make thinking-test-integration"; \
		exit 0; \
	fi
	go test -tags thinking_kafka -count=1 -v ./e2e/thinking/...

# Build the Thinking Engine Docker image locally. Tag defaults to
# ENGINE_TAG=dev; override for versioned builds. Compose's
# `profiles: [engine]` slot picks up this image once it exists.
.PHONY: thinking-image
thinking-image:
	@echo "Building $(THINKING_IMAGE):$(ENGINE_TAG) ..."
	docker build \
		-f $(THINKING_DOCKERFILE) \
		-t $(THINKING_IMAGE):$(ENGINE_TAG) \
		--build-arg VERSION=$(ENGINE_TAG) \
		.
	@echo ""
	@echo "Image built. To run via compose:"
	@echo "  CTX_HASH=<hash> M3C_USER_CONTEXT_ID=<id> THINKING_ENGINE_SECRET=<s> \\"
	@echo "    docker compose -f $(THINKING_COMPOSE) --profile engine up -d"

# Bring up the per-user cp-all-in-one stack. CTX_HASH must be set
# (or sourced from deploy/thinking-engine/.env).
.PHONY: thinking-up
thinking-up:
	@echo "Bringing up cp-all-in-one for CTX_HASH=$${CTX_HASH:?set CTX_HASH}..."
	docker compose -f $(THINKING_COMPOSE) up -d zookeeper broker schema-registry control-center

.PHONY: thinking-down
thinking-down:
	docker compose -f $(THINKING_COMPOSE) down

.PHONY: thinking-logs
thinking-logs:
	docker compose -f $(THINKING_COMPOSE) logs -f --tail=200

# Create all 8 topics for the current CTX_HASH.
.PHONY: thinking-topics
thinking-topics:
	@bash deploy/thinking-engine/topic-bootstrap.sh --ctx-hash $${CTX_HASH:?set CTX_HASH}

# Show help
.PHONY: help
help:
	@echo "m3c-tools — Multi-Modal-Memory Tools"
	@echo ""
	@echo "Targets:"
	@echo "  deps           Install all system dependencies (Homebrew + pip)"
	@echo "  check-deps     Verify required dependencies are installed"
	@echo "  build          Build the main CLI binary"
	@echo "  build-skillctl Build skillctl skill inventory scanner"
	@echo "  build-skillctl-demo Build the offline skillctl-demo (+ skillctl)"
	@echo "  build-all      Build all binaries (CLI + POCs + skillctl + demo)"
	@echo "  build-app      Build macOS .app bundle"
	@echo "  dmg            Build macOS DMG installer"
	@echo "  setup-venv     Create Python venv and install whisper"
	@echo "  e2e            Run all e2e tests"
	@echo "  test-unit      Run offline unit tests only"
	@echo "  test-network   Run transcript tests requiring internet"
	@echo "                   M3C_TEST_FULL_NETWORK=1 to include thumbnail + translate tests"
	@echo "  test-er1       Run tests requiring ER1 server"
	@echo "  test-whisper   Run tests requiring whisper binary"
	@echo "  test-recorder  Run tests requiring microphone"
	@echo "  install        Install CLI to /usr/local/bin and .app to /Applications"
	@echo "  permissions    Open macOS Privacy settings to grant Screen/Mic/Accessibility"
	@echo "  uninstall      Remove installed CLI and .app"
	@echo "  vet            Run go vet on all packages"
	@echo "  clean          Remove build artifacts"
	@echo "  code-review    Run pre-release code review checks"
	@echo "  check-docs     Check documentation consistency with implementation"
	@echo "  release        Release; bump level DERIVED from commits (code-review + check-docs first)"
	@echo "  release-auto   Same derivation without the pre-checks"
	@echo "  release-patch  Release with patch version bump"
	@echo "  release-minor  Release with minor version bump"
	@echo "  release-major  Release with major version bump"
	@echo "  menubar        Build + run the menu bar .app in the FOREGROUND (stdout logs, Ctrl-C)"
	@echo "  menubar-app    Build + launch the .app DETACHED via 'open' (background, quit from menu)"
	@echo "  build-windows  Cross-compile CLI + tray for Windows (amd64)"
	@echo "  installer-windows  Build NSIS installer (requires nsis)"
	@echo "  snapshot       Build with GoReleaser (local snapshot, no publish)"
	@echo "  checksums      Generate SHA-256 checksums for build/ artifacts"
	@echo "  ci             Run full CI locally (vet + lint + test + build)"
	@echo "  lint           Run golangci-lint"
	@echo "  test-gate-windows  Windows dev test gate: vet + cross-compile + tests (SPEC-0128)"
	@echo "  test-gate-windows-quick  Same but skip test phase (compile check only)"
	@echo ""
	@echo "Thinking Engine (SPEC-0167):"
	@echo "  thinking-build            Build ./build/thinking-engine"
	@echo "  thinking-image            Build local Docker image m3c/thinking-engine:\$$ENGINE_TAG"
	@echo "  thinking-test             Run internal/thinking unit tests (-short)"
	@echo "  thinking-test-tagged      Run franz-go driver unit tests (-tags thinking_kafka)"
	@echo "  thinking-test-integration Run e2e tests against real broker (needs M3C_KAFKA_URL)"
	@echo "  thinking-up               docker compose up for cp-all-in-one stack (needs CTX_HASH)"
	@echo "  thinking-down             docker compose down"
	@echo "  thinking-logs             docker compose logs -f"
	@echo "  thinking-topics           Create 8 topics for CTX_HASH"
	@echo ""
	@echo "Skill Trust-Plane containers (SPEC-0354):"
	@echo "  skillctl-image        Build distroless $(SKILLCTL_IMAGE):\$$SKILLCTL_TAG image (D1)"
	@echo "  skillctl-image-smoke  Smoke-test the image (version, non-root user, size)"
	@echo "  publish-skb           Publish a .skb as an OCI artifact via ORAS+cosign (D2):"
	@echo "                        make publish-skb SKB=x@1.0.0.skb REGISTRY=ghcr.io/kamir"
	@echo ""
	@echo "  help           Show this help"

# -----------------------------------------------------------------------------
# Skill Trust-Plane containerization (SPEC-0354)
# -----------------------------------------------------------------------------

# Engine-agnostic: docker OR podman (identical CLI surface for these targets).
CONTAINER_ENGINE    ?= docker
SKILLCTL_DOCKERFILE  = deploy/skillctl/Dockerfile
SKILLCTL_IMAGE       = m3c/skillctl
SKILLCTL_TAG        ?= $(GIT_VERSION)

# D1: build the skillctl container image (distroless, static, CGO=0).
.PHONY: skillctl-image
skillctl-image:
	@echo "Building $(SKILLCTL_IMAGE):$(SKILLCTL_TAG) with $(CONTAINER_ENGINE) ..."
	$(CONTAINER_ENGINE) build \
		-f $(SKILLCTL_DOCKERFILE) \
		-t $(SKILLCTL_IMAGE):$(SKILLCTL_TAG) \
		--build-arg VERSION=$(SKILLCTL_TAG) \
		.
	@echo ""
	@echo "Built $(SKILLCTL_IMAGE):$(SKILLCTL_TAG). Smoke-test with: make skillctl-image-smoke"

# D1 acceptance: version prints, image user is non-root, image is small.
# (distroless has no shell, so we inspect the image config rather than
# exec-ing into it.)
.PHONY: skillctl-image-smoke
skillctl-image-smoke:
	@echo "== skillctl version (from inside the image) =="
	@$(CONTAINER_ENGINE) run --rm $(SKILLCTL_IMAGE):$(SKILLCTL_TAG) version
	@echo "== image user (must be non-root) =="
	@$(CONTAINER_ENGINE) image inspect --format 'User={{.Config.User}}' $(SKILLCTL_IMAGE):$(SKILLCTL_TAG)
	@echo "== image size =="
	@$(CONTAINER_ENGINE) image inspect --format 'Size={{.Size}} bytes' $(SKILLCTL_IMAGE):$(SKILLCTL_TAG)

# D2: publish a .skb bundle as a signed OCI artifact. SKB + REGISTRY required;
# pass extra flags via PUBLISH_ARGS (e.g. PUBLISH_ARGS="--dry-run").
.PHONY: publish-skb
publish-skb:
	@scripts/publish-skb.sh --skb "$(SKB)" --registry "$(REGISTRY)" $(PUBLISH_ARGS)

# m3c-tools — Multi-Modal-Memory Tools
# Makefile for building, testing, and running e2e tests

BINARY   = m3c-tools
CMD_DIR  = ./cmd/m3c-tools
BUILD_DIR = ./build
APP_NAME = M3C-Tools
APP_BUNDLE = $(BUILD_DIR)/$(APP_NAME).app
APP_ID   = com.kamir.m3c-tools
APP_VERSION = 1.4.4
ICON_SRC = maindset_icon.png

# Default: build the CLI
.PHONY: all
all: build

# Build the main CLI binary
.PHONY: build
build:
	@echo "Building $(BINARY)..."
	go build -o $(BUILD_DIR)/$(BINARY) $(CMD_DIR)

# Build all commands (including POCs)
.PHONY: build-all
build-all: build
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
	go test -v -count=1 ./e2e/ -run "TestComposite|TestBuild|TestParseTagLine|TestER1Config|TestER1Queue|TestER1EnqueueFailure|TestUploadFailure|TestRecorderEncodeWAV|TestRecorderStats|TestExportsDB|TestFilesDB|TestHashFile|TestFormatterLoader|TestPrettyPrint|TestFormatTranscript|TestFormatSnippet|TestFormatKeyValue|TestFormatTable|TestFormatSection|TestFormatStatusLine|TestBuildApp|TestTranslateFlagParsing|TestTranslateNotTranslatable|TestTranslateTranslatable|TestRetryQueue|TestRetryBackoffTiming|TestRetryBackoffCustomBase|TestRetryProcessingOrder|TestRetryPartialFailure|TestRetryMaxRetriesDropsEntry|TestRetryDropCallback|TestRetryRespectsBackoffDelay|TestRetryProcessesAfterBackoffElapsed|TestRetryGracefulShutdownOnCancel|TestRetryRunStopsOnContextCancel|TestRetryRunProcessesMultipleCycles|TestRetryEmptyQueue|TestRetryOnRetryCallback|TestTranscriptFilterExcludeGenerated|TestTranscriptFilterExcludeManuallyCreated|TestTranscriptFilterBothExcludes|TestTranscriptFilterEmptyList|TestTranscriptFilterAllSameType|TestProxyBuildURL|TestProxyGetTransport|TestProxyNewWithProxy|TestProxyHTTPIntegration|TestProxyWebshare|TestProxySocks5URL|TestRetryRunnerProcessOnce|TestRetryRunnerDropExceedMaxRetries|TestRetryRunnerBackoff|TestRetryRunnerRunLoop|TestRetryRunnerBackoffSkip|TestBackgroundRetryStartsAndProcesses|TestBackgroundRetryStopsGracefully|TestBackgroundRetryHandlesFailures|TestBackgroundRetryEmptyQueue|TestBackgroundRetryLogging|TestTranscriptImportFromSnippets|TestTranscriptImportPreservesMetadata|TestTranscriptListSearchByLanguage|TestTranscriptListSearchGenerated|TestTranscriptListSearchManual|TestTranscriptSearchNotFound|TestTranscriptExportText|TestTranscriptExportSRT|TestTranscriptExportJSON|TestTranscriptExportWebVTT|TestTranscriptExportPretty|TestTranscriptExportAllFormats|TestTranscriptExportToFile|TestTranscriptListString|TestTranscriptListStringEmpty|TestMenubarIntegrationFullLifecycle|TestMenubarIntegrationTranscriptFetcherWired|TestMenubarIntegrationStatusDuringFetch|TestMenubarIntegrationMenuItemsComplete|TestMenubarIntegrationConcurrentStatusUpdates|TestMenubarIntegrationHistoryInMenuUpdates|TestAppBundleLaunchHelp|TestAppBundleLaunchUnknownCommand|TestAppBundleLaunchNoArgs|TestAppBundleRetryGracefulShutdown|TestAppBundleRetryExitsOnSIGINT|TestAppBundleMenubarFlagParsing|TestAppBundleExecPermissions|TestAppBundleInfoPlistLSUIElement|TestScheduleCommand|TestScheduleCommandDuplicate|TestScheduleCommandMissingTranscript|TestStatusCommand|TestStatusCommandEntryNotFound|TestCancelCommand|TestCancelCommandNotFound|TestScheduleStatusCancelWorkflow|TestCLIHelp|TestCLIUnknownCommand|TestCLINoArgs|TestRepoRoot|TestWriteFixture|TestWriteFixtureBytes|TestFixtureDir|TestTempDataDir|TestWithEnv|TestCLIResultAssertions|TestRunCLIWithEnv|TestScreenshotModeConstants|TestScreenshotClipboardImageTypes|TestScreenshotCLIHelpOutput|TestImporterScanDir|TestImporterScanDirEmpty|TestImporterScanDirNotExist|TestImporterScanDirNotDirectory|TestImporterIsAudioFile|TestImporterExtensionList|TestImporterScanDirHiddenSkip|TestImporterScanDirCaseInsensitive|TestImporterScanDirAbsPath|TestImporterScanDirDeepNesting|TestImporterExtensionCoverage|TestImporterCLIExtensions|TestImporterCLIScanDir|TestImporterCLIEmptyDir|TestImporterCLINonexistentDir|TestImporterCLINoArgs"

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

# Run the menu bar app
.PHONY: menubar
menubar: build
	$(BUILD_DIR)/$(BINARY) menubar $(ARGS)

# Clean build artifacts
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

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
.PHONY: release release-patch release-minor release-major
release: code-review check-docs release-patch

release-patch:
	@./scripts/release.sh patch

release-minor: code-review check-docs
	@./scripts/release.sh minor

release-major: code-review check-docs
	@./scripts/release.sh major

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

# Show help
.PHONY: help
help:
	@echo "m3c-tools — Multi-Modal-Memory Tools"
	@echo ""
	@echo "Targets:"
	@echo "  build          Build the main CLI binary"
	@echo "  build-all      Build all binaries (CLI + POCs)"
	@echo "  build-app      Build macOS .app bundle"
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
	@echo "  release        Release with patch bump (runs code-review + check-docs first)"
	@echo "  release-patch  Release with patch version bump"
	@echo "  release-minor  Release with minor version bump"
	@echo "  release-major  Release with major version bump"
	@echo "  menubar        Build and launch the menu bar app"
	@echo "  ci             Run full CI locally (vet + lint + test + build)"
	@echo "  lint           Run golangci-lint"
	@echo "  help           Show this help"

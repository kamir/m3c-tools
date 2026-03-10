// observation_darwin.go — Native macOS Observation Window via Cocoa/cgo.
//
// Creates an NSWindow with an NSTabView containing 3 tabs:
//   - Record: displays a captured image (NSImageView), VU meter with dB readout, & controls
//   - Review: metadata header (source, duration, date, file info) + scrollable transcript
//   - Tags:   editable tag fields pre-filled per channel type before ER1 upload / draft save
//
// The image in the Record tab is scaled to fit max 50% of screen width/height.
// This file must be built on macOS (darwin) with cgo enabled.
package menubar

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa -framework ApplicationServices

#import <Cocoa/Cocoa.h>
#import <ApplicationServices/ApplicationServices.h>
#import <CoreGraphics/CoreGraphics.h>
#import <float.h>

// ---------- Review Tab State ----------

static NSTextView *g_reviewTextView = nil; // The transcript text view in the Review tab.

// updateReviewTranscript sets the transcript text in the Review tab.
// Thread-safe: dispatches to the main thread.
static void updateReviewTranscript(const char *text) {
	if (text == NULL) return;
	NSString *nsText = [NSString stringWithUTF8String:text];
	dispatch_async(dispatch_get_main_queue(), ^{
		if (g_reviewTextView != nil) {
			[g_reviewTextView setString:nsText];
			// Scroll to top after setting new text.
			[g_reviewTextView scrollRangeToVisible:NSMakeRange(0, 0)];
		}
	});
}

// ---------- Elapsed Timer State (Record Tab) ----------

static NSTextField *g_timerLabel = nil;   // The MM:SS label in the Record tab.
static NSTimer     *g_elapsedTimer = nil; // Repeating 1-second timer.
static NSInteger    g_elapsedSeconds = 0; // Seconds elapsed since recording started.

// updateTimerLabel formats g_elapsedSeconds as MM:SS into g_timerLabel.
static void updateTimerLabel(void) {
	if (g_timerLabel == nil) return;
	NSInteger mins = g_elapsedSeconds / 60;
	NSInteger secs = g_elapsedSeconds % 60;
	NSString *text = [NSString stringWithFormat:@"%02ld:%02ld", (long)mins, (long)secs];
	[g_timerLabel setStringValue:text];
}

// timerTick is called every second by g_elapsedTimer.
static void timerTick(NSTimer *timer) {
	(void)timer;
	g_elapsedSeconds++;
	updateTimerLabel();
}

// startRecordingTimer starts (or restarts) the elapsed timer from 00:00.
// Must be called from the main thread.
static void startRecordingTimer(void) {
	dispatch_async(dispatch_get_main_queue(), ^{
		// Invalidate any existing timer.
		if (g_elapsedTimer != nil) {
			[g_elapsedTimer invalidate];
			g_elapsedTimer = nil;
		}
		g_elapsedSeconds = 0;
		updateTimerLabel();
		g_elapsedTimer = [NSTimer scheduledTimerWithTimeInterval:1.0
														repeats:YES
														  block:^(NSTimer *t) {
			timerTick(t);
		}];
	});
}

// stopRecordingTimer stops the elapsed timer, leaving the final value displayed.
static void stopRecordingTimer(void) {
	dispatch_async(dispatch_get_main_queue(), ^{
		if (g_elapsedTimer != nil) {
			[g_elapsedTimer invalidate];
			g_elapsedTimer = nil;
		}
	});
}

// resetRecordingTimer stops the timer and resets the display to 00:00.
static void resetRecordingTimer(void) {
	dispatch_async(dispatch_get_main_queue(), ^{
		if (g_elapsedTimer != nil) {
			[g_elapsedTimer invalidate];
			g_elapsedTimer = nil;
		}
		g_elapsedSeconds = 0;
		updateTimerLabel();
	});
}

// getElapsedSeconds returns the current elapsed seconds value.
static int getElapsedSeconds(void) {
	return (int)g_elapsedSeconds;
}

// ---------- VU Meter ----------

// Static references for the VU meter views, updated from Go via updateVUMeterLevel.
static NSView      *g_vuFillView  = nil;  // The colored fill bar inside the track.
static NSView      *g_vuTrackView = nil;  // The background track container.
static NSTextField *g_vuLabel     = nil;  // The dB readout label beside the meter.

// updateVUMeterLevel sets the VU meter fill width proportional to level (0.0–1.0).
// Color coding: green (< 0.6), yellow (0.6–0.85), red (>= 0.85).
// Safe to call from any thread — dispatches to main thread internally.
static void updateVUMeterLevel(float level) {
	if (level < 0.0f) level = 0.0f;
	if (level > 1.0f) level = 1.0f;
	dispatch_async(dispatch_get_main_queue(), ^{
		if (g_vuFillView == nil || g_vuTrackView == nil) return;

		NSRect trackBounds = [g_vuTrackView bounds];
		CGFloat fillW = trackBounds.size.width * level;

		// Update fill width.
		NSRect fillRect = NSMakeRect(0, 0, fillW, trackBounds.size.height);
		[g_vuFillView setFrame:fillRect];

		// Color coding based on level.
		NSColor *fillColor;
		if (level < 0.6f) {
			fillColor = [NSColor systemGreenColor];
		} else if (level < 0.85f) {
			fillColor = [NSColor systemYellowColor];
		} else {
			fillColor = [NSColor systemRedColor];
		}

		[g_vuFillView setWantsLayer:YES];
		[[g_vuFillView layer] setBackgroundColor:[fillColor CGColor]];

		// Update dB label.
		if (g_vuLabel != nil) {
			if (level <= 0.0f) {
				[g_vuLabel setStringValue:@"-∞ dB"];
			} else {
				float dB = 20.0f * log10f(level);
				[g_vuLabel setStringValue:
					[NSString stringWithFormat:@"%.1f dB", dB]];
			}
		}
	});
}

// resetVUMeter resets the VU meter fill to zero.
static void resetVUMeter(void) {
	updateVUMeterLevel(0.0f);
}

// ---------- Review Tab Metadata ----------

// ReviewMeta holds metadata displayed in the Review tab header.
typedef struct {
	const char *source;        // e.g. "Screenshot", "YouTube", "Microphone"
	const char *language;      // e.g. "English", "—"
	int         snippetCount;  // number of transcript snippets
	int         charCount;     // total character count
	const char *duration;      // e.g. "1m 23s", "—"
	const char *fileSize;      // e.g. "42 KB", "—"
	const char *date;          // e.g. "2026-03-10 14:23:05"
	const char *filePath;      // e.g. "/tmp/recording.wav"
} ReviewMeta;

// safeNSString converts a C string to NSString, returning fallback if NULL/empty.
static NSString *safeNSString(const char *s, NSString *fallback) {
	if (s == NULL || strlen(s) == 0) return fallback;
	return [NSString stringWithUTF8String:s];
}

// makeReadOnlyLabel creates a non-editable, non-selectable label.
static NSTextField *makeReadOnlyLabel(NSRect frame, NSString *text, CGFloat fontSize, BOOL bold) {
	NSTextField *label = [[NSTextField alloc] initWithFrame:frame];
	[label setStringValue:text];
	[label setBezeled:NO];
	[label setDrawsBackground:NO];
	[label setEditable:NO];
	[label setSelectable:NO];
	if (bold) {
		[label setFont:[NSFont systemFontOfSize:fontSize weight:NSFontWeightMedium]];
	} else {
		[label setFont:[NSFont systemFontOfSize:fontSize]];
	}
	return label;
}

// makeMetaValueLabel creates a secondary-colored value label (selectable for copy).
static NSTextField *makeMetaValueLabel(NSRect frame, NSString *text, CGFloat fontSize) {
	NSTextField *label = makeReadOnlyLabel(frame, text, fontSize, NO);
	[label setTextColor:[NSColor secondaryLabelColor]];
	[label setSelectable:YES];
	return label;
}

// ---------- Long Transcript Performance ----------

// Threshold (in chars) above which transcript text is loaded in chunks.
static const NSUInteger kLargeTranscriptThreshold = 28000;
// Chunk size for incremental text loading (8 KB).
static const NSUInteger kChunkSize = 8192;

// setReviewTranscript sets the transcript text on the Review tab's NSTextView.
// For texts larger than kLargeTranscriptThreshold, text is loaded incrementally
// in kChunkSize chunks dispatched to the main thread with small delays between
// them, keeping the UI responsive and avoiding scroll-jank.
// statusText updates the review status label (tag 1001) during loading.
static void setReviewTranscript(const char *text, const char *statusText) {
	if (g_reviewTextView == nil || text == NULL) return;

	NSString *fullText = [NSString stringWithUTF8String:text];
	NSString *status = statusText ? [NSString stringWithUTF8String:statusText] : nil;

	dispatch_async(dispatch_get_main_queue(), ^{
		// Find the review status label (tag 1001) to update progress.
		NSView *reviewView = [[g_reviewTextView enclosingScrollView] superview];
		NSTextField *reviewStatusLabel = [reviewView viewWithTag:1001];

		if ([fullText length] < kLargeTranscriptThreshold) {
			// Small transcript: set all at once - no chunking needed.
			[g_reviewTextView setString:fullText];
			if (reviewStatusLabel && status) {
				[reviewStatusLabel setStringValue:status];
			}
			return;
		}

		// Large transcript (28K+ chars): load in chunks for smooth scrolling.
		// Clear existing content and show loading indicator.
		[g_reviewTextView setString:@""];
		if (reviewStatusLabel) {
			[reviewStatusLabel setStringValue:@"Loading transcript…"];
		}

		// Enable non-contiguous layout for large text scroll performance.
		NSLayoutManager *layoutManager = [g_reviewTextView layoutManager];
		[layoutManager setAllowsNonContiguousLayout:YES];

		NSTextStorage *storage = [g_reviewTextView textStorage];
		NSDictionary *attrs = @{
			NSFontAttributeName: [NSFont monospacedSystemFontOfSize:12
															weight:NSFontWeightRegular]
		};

		NSUInteger totalLen = [fullText length];
		__block NSUInteger offset = 0;

		// Recursive block that appends one chunk, then schedules the next.
		__block void (^appendChunk)(void);
		appendChunk = [^{
			if (offset >= totalLen) {
				// Done - update final status.
				if (reviewStatusLabel && status) {
					[reviewStatusLabel setStringValue:status];
				}
				appendChunk = nil; // break retain cycle
				return;
			}

			NSUInteger chunkLen = kChunkSize;
			if (offset + chunkLen > totalLen) {
				chunkLen = totalLen - offset;
			}
			NSString *chunk = [fullText substringWithRange:
				NSMakeRange(offset, chunkLen)];
			NSAttributedString *attrChunk = [[NSAttributedString alloc]
				initWithString:chunk attributes:attrs];

			[storage beginEditing];
			[storage appendAttributedString:attrChunk];
			[storage endEditing];

			offset += chunkLen;

			// Update progress in status label.
			if (reviewStatusLabel) {
				NSUInteger pct = (offset * 100) / totalLen;
				[reviewStatusLabel setStringValue:
					[NSString stringWithFormat:@"Loading transcript… %lu%%",
						(unsigned long)pct]];
			}

			// Schedule next chunk with a tiny delay (5 ms) to let the run loop
			// process scroll events and redraws between chunks.
			dispatch_after(
				dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_MSEC)),
				dispatch_get_main_queue(),
				appendChunk
			);
		} copy]; // copy block to heap so it survives async dispatch

		// Kick off the first chunk.
		appendChunk();
	});
}

// Forward declarations (defined in Global Window State section below).
static NSTextField *g_recordSourceLabel;
static NSProgressIndicator *g_whisperProgress;
static NSPanel *g_captureHintPanel;
static NSTextField *g_captureHintTitleLabel;
static NSTextField *g_captureHintDetailLabel;
static NSTextField *g_recordStatusLabel;
static NSButton *g_recordStopButton;
static id getOrCreateCaptureHintHandler(void);
static volatile int g_captureHintCancelled = 0;

// ---------- Whisper Progress Bar ----------

// showWhisperProgress shows and starts animating the indeterminate progress bar
// in the Review tab. Call when whisper transcription begins.
static void showWhisperProgress(void) {
	dispatch_async(dispatch_get_main_queue(), ^{
		if (g_whisperProgress != nil) {
			[g_whisperProgress setHidden:NO];
			[g_whisperProgress startAnimation:nil];
		}
	});
}

// hideWhisperProgress stops and hides the progress bar. Call when whisper finishes.
static void hideWhisperProgress(void) {
	dispatch_async(dispatch_get_main_queue(), ^{
		if (g_whisperProgress != nil) {
			[g_whisperProgress stopAnimation:nil];
			[g_whisperProgress setHidden:YES];
		}
	});
}

// ---------- Capture Hint Panel ----------

// showCaptureHintWindow displays a small non-activating floating panel with
// instructions while waiting for clipboard-based screenshot capture.
static void showCaptureHintWindow(const char *title, const char *detail) {
	NSString *nsTitle = (title != NULL && strlen(title) > 0)
		? [NSString stringWithUTF8String:title]
		: @"Waiting for screenshot…";
	NSString *nsDetail = (detail != NULL && strlen(detail) > 0)
		? [NSString stringWithUTF8String:detail]
		: @"Press Cmd+Ctrl+Shift+4";

	dispatch_async(dispatch_get_main_queue(), ^{
		g_captureHintCancelled = 0;
		if (g_captureHintPanel == nil) {
			NSScreen *screen = [NSScreen mainScreen];
			NSRect visible = [screen visibleFrame];
			CGFloat w = 480;
			CGFloat h = 118;
			NSRect rect = NSMakeRect(
				visible.origin.x + (visible.size.width - w) / 2.0,
				visible.origin.y + visible.size.height * 0.72,
				w,
				h
			);

			NSPanel *panel = [[NSPanel alloc]
				initWithContentRect:rect
				styleMask:(NSWindowStyleMaskTitled |
						   NSWindowStyleMaskNonactivatingPanel)
				backing:NSBackingStoreBuffered
				defer:NO];
			[panel setReleasedWhenClosed:NO];
			[panel setFloatingPanel:YES];
			[panel setHidesOnDeactivate:NO];
			[panel setLevel:NSFloatingWindowLevel];
			[panel setCollectionBehavior:(NSWindowCollectionBehaviorCanJoinAllSpaces |
										  NSWindowCollectionBehaviorTransient)];
			[panel setTitle:@"M3C Screenshot"];

			NSView *content = [panel contentView];

			NSTextField *titleLabel = [[NSTextField alloc]
				initWithFrame:NSMakeRect(16, 62, w - 32, 28)];
			[titleLabel setBezeled:NO];
			[titleLabel setDrawsBackground:NO];
			[titleLabel setEditable:NO];
			[titleLabel setSelectable:NO];
			[titleLabel setFont:[NSFont systemFontOfSize:18 weight:NSFontWeightSemibold]];
			[titleLabel setAlignment:NSTextAlignmentCenter];
			[content addSubview:titleLabel];

			NSTextField *detailLabel = [[NSTextField alloc]
				initWithFrame:NSMakeRect(16, 28, w - 32, 24)];
			[detailLabel setBezeled:NO];
			[detailLabel setDrawsBackground:NO];
			[detailLabel setEditable:NO];
			[detailLabel setSelectable:NO];
			[detailLabel setFont:[NSFont systemFontOfSize:13 weight:NSFontWeightRegular]];
			[detailLabel setTextColor:[NSColor secondaryLabelColor]];
			[detailLabel setAlignment:NSTextAlignmentCenter];
			[content addSubview:detailLabel];

			NSButton *cancelBtn = [NSButton buttonWithTitle:@"Cancel"
													 target:getOrCreateCaptureHintHandler()
													 action:@selector(captureHintCancelClicked:)];
			[cancelBtn setFrame:NSMakeRect((w / 2.0) + 8, 6, 88, 24)];
			[cancelBtn setBezelStyle:NSBezelStyleRounded];
			[cancelBtn setAutoresizingMask:(NSViewMinXMargin | NSViewMaxXMargin | NSViewMaxYMargin)];
			[content addSubview:cancelBtn];

			NSButton *captureBtn = [NSButton buttonWithTitle:@"Capture"
													  target:getOrCreateCaptureHintHandler()
													  action:@selector(captureHintContinueClicked:)];
			[captureBtn setFrame:NSMakeRect((w / 2.0) - 96, 6, 88, 24)];
			[captureBtn setBezelStyle:NSBezelStyleRounded];
			[captureBtn setAutoresizingMask:(NSViewMinXMargin | NSViewMaxXMargin | NSViewMaxYMargin)];
			[content addSubview:captureBtn];

			g_captureHintPanel = panel;
			g_captureHintTitleLabel = titleLabel;
			g_captureHintDetailLabel = detailLabel;
		}

		[g_captureHintTitleLabel setStringValue:nsTitle];
		[g_captureHintDetailLabel setStringValue:nsDetail];
		[g_captureHintPanel orderFrontRegardless];
	});
}

// hideCaptureHintWindow hides the floating screenshot hint panel.
static void hideCaptureHintWindow(void) {
	dispatch_async(dispatch_get_main_queue(), ^{
		if (g_captureHintPanel != nil) {
			[g_captureHintPanel orderOut:nil];
		}
	});
}

// triggerClipboardRegionScreenshotHotkey posts Cmd+Ctrl+Shift+4 via CGEvent.
// Returns 1 on posted events, 0 on failure.
static int triggerClipboardRegionScreenshotHotkey(void) {
	CGEventSourceRef src = CGEventSourceCreate(kCGEventSourceStateHIDSystemState);
	if (src == NULL) return 0;

	// ANSI keycode for "4" on macOS US layout.
	CGKeyCode key4 = (CGKeyCode)21;
	CGEventRef down = CGEventCreateKeyboardEvent(src, key4, true);
	CGEventRef up = CGEventCreateKeyboardEvent(src, key4, false);
	if (down == NULL || up == NULL) {
		if (down != NULL) CFRelease(down);
		if (up != NULL) CFRelease(up);
		CFRelease(src);
		return 0;
	}

	CGEventFlags flags = kCGEventFlagMaskCommand |
		kCGEventFlagMaskControl |
		kCGEventFlagMaskShift;
	CGEventSetFlags(down, flags);
	CGEventSetFlags(up, flags);

	CGEventPost(kCGHIDEventTap, down);
	CGEventPost(kCGHIDEventTap, up);

	CFRelease(down);
	CFRelease(up);
	CFRelease(src);
	return 1;
}

// captureHintWasCancelled returns 1 if user clicked Cancel on the hint panel.
static int captureHintWasCancelled(void) {
	return g_captureHintCancelled ? 1 : 0;
}

// resetCaptureHintCancelled clears the hint-panel cancel state.
static void resetCaptureHintCancelled(void) {
	g_captureHintCancelled = 0;
}

// ---------- Record Tab Source Label ----------

// setRecordSourceLabel sets a label over the image in the Record tab
// (e.g. "from clipboard" or "snapshot at 08:15:30").
static void setRecordSourceLabel(const char *text) {
	if (text == NULL) return;
	NSString *nsText = [NSString stringWithUTF8String:text];
	dispatch_async(dispatch_get_main_queue(), ^{
		if (g_recordSourceLabel != nil) {
			[g_recordSourceLabel setStringValue:nsText];
			[g_recordSourceLabel setHidden:NO];
			// Size to fit the text content.
			[g_recordSourceLabel sizeToFit];
			// Add horizontal padding.
			NSRect f = [g_recordSourceLabel frame];
			f.size.width += 12;
			f.origin.x = 15;
			f.origin.y = 82;
			[g_recordSourceLabel setFrame:f];
		}
	});
}

// ---------- Frontmost App Tracking ----------

// Track the last active non-M3C app so we can restore it before screencapture.
static NSRunningApplication *g_lastNonSelfActiveApp = nil;
static id g_appActivateObserver = nil;

// initFrontmostAppTracker installs a workspace activation observer once.
// Must run on main thread.
static void initFrontmostAppTracker(void) {
	if (g_appActivateObserver != nil) return;

	NSWorkspace *ws = [NSWorkspace sharedWorkspace];
	NSRunningApplication *selfApp = [NSRunningApplication currentApplication];
	NSRunningApplication *front = [ws frontmostApplication];
	if (front != nil && [front processIdentifier] != [selfApp processIdentifier]) {
		g_lastNonSelfActiveApp = front;
	}

	g_appActivateObserver = [[ws notificationCenter]
		addObserverForName:NSWorkspaceDidActivateApplicationNotification
					object:nil
					 queue:[NSOperationQueue mainQueue]
				usingBlock:^(NSNotification *note) {
		NSRunningApplication *app = note.userInfo[NSWorkspaceApplicationKey];
		if (app == nil) return;
		if ([app processIdentifier] == [[NSRunningApplication currentApplication] processIdentifier]) {
			return;
		}
		g_lastNonSelfActiveApp = app;
	}];
}

// startFrontmostAppTracker initializes workspace activation tracking so the
// last active non-self app is known before screenshot menu actions run.
static void startFrontmostAppTracker(void) {
	if ([NSThread isMainThread]) {
		initFrontmostAppTracker();
	} else {
		dispatch_sync(dispatch_get_main_queue(), ^{
			initFrontmostAppTracker();
		});
	}
}

// hasScreenCaptureAccess returns 1 if Screen Recording permission is granted.
static int hasScreenCaptureAccess(void) {
	return CGPreflightScreenCaptureAccess() ? 1 : 0;
}

// requestScreenCaptureAccess requests Screen Recording permission from macOS.
// Returns 1 if already granted or granted by the user, else 0.
static int requestScreenCaptureAccess(void) {
	return CGRequestScreenCaptureAccess() ? 1 : 0;
}

// clipboardChangeCount returns NSPasteboard.generalPasteboard.changeCount.
// Useful for low-overhead clipboard-change monitoring loops.
static int clipboardChangeCount(void) {
	NSPasteboard *pb = [NSPasteboard generalPasteboard];
	if (pb == nil) return 0;
	return (int)[pb changeCount];
}

// prepareForInteractiveCapture hides/deactivates the menu-bar app so the
// previously frontmost app can be visible again before screencapture starts.
// Safe to call from any goroutine.
static void prepareForInteractiveCapture(void) {
	void (^handoff)(void) = ^{
		if (NSApp == nil) return;
		initFrontmostAppTracker();
		[NSApp hide:nil];
		[NSApp deactivate];
		if (g_lastNonSelfActiveApp != nil && ![g_lastNonSelfActiveApp isTerminated]) {
			[g_lastNonSelfActiveApp activateWithOptions:NSApplicationActivateAllWindows];
		}
	};
	if ([NSThread isMainThread]) {
		handoff();
	} else {
		dispatch_sync(dispatch_get_main_queue(), handoff);
	}
}

// ---------- Memo Text Retrieval ----------

// getReviewMemoText returns a copy of the current text in the Review tab's
// editable text view. The caller must free() the returned string.
// Returns NULL if the text view does not exist.
static char *getReviewMemoText(void) {
	__block char *result = NULL;
	dispatch_sync(dispatch_get_main_queue(), ^{
		if (g_reviewTextView != nil) {
			NSString *text = [[g_reviewTextView string] copy];
			result = strdup([text UTF8String]);
		}
	});
	return result;
}

// ---------- Channel Type Helpers for Tags Tab ----------

// Channel type constants (must match Go ChannelType iota).
enum ObsChannelType {
	ObsChannelProgress  = 0,  // Channel A: YouTube video
	ObsChannelIdea      = 1,  // Channel B: Screenshot
	ObsChannelImpulse   = 2,  // Channel C: Quick note
	ObsChannelImport    = 3,  // Channel D: Batch audio import
};

// defaultTagsForChannel returns the pre-filled comma-separated tags for the given channel.
static NSString* defaultTagsForChannel(int channelType) {
	switch (channelType) {
		case ObsChannelProgress: return @"youtube";
		case ObsChannelIdea:     return @"idea, screenshot";
		case ObsChannelImpulse:  return @"impulse";
		case ObsChannelImport:   return @"import, audio-import";
		default:                 return @"observation";
	}
}

// contentTypeLabelForChannel returns the ER1 content-type label for the channel.
static NSString* contentTypeLabelForChannel(int channelType) {
	switch (channelType) {
		case ObsChannelProgress: return @"YouTube-Video-Impression";
		case ObsChannelIdea:     return @"Screenshot-Observation";
		case ObsChannelImpulse:  return @"Quick-Impulse";
		case ObsChannelImport:   return @"Audio-Import";
		default:                 return @"Observation";
	}
}

// channelDisplayName returns a human-readable channel identifier.
static NSString* channelDisplayName(int channelType) {
	switch (channelType) {
		case ObsChannelProgress: return @"Channel A \u2014 Progress (YouTube)";
		case ObsChannelIdea:     return @"Channel B \u2014 Idea (Screenshot)";
		case ObsChannelImpulse:  return @"Channel C \u2014 Impulse";
		case ObsChannelImport:   return @"Channel D \u2014 Import (Audio)";
		default:                 return @"Unknown Channel";
	}
}

// notesPlaceholderForChannel returns placeholder text for the notes area.
static NSString* notesPlaceholderForChannel(int channelType) {
	switch (channelType) {
		case ObsChannelProgress: return @"Add notes about this video observation...";
		case ObsChannelIdea:     return @"Describe what this screenshot captures...";
		case ObsChannelImpulse:  return @"Capture your quick thought or impulse...";
		case ObsChannelImport:   return @"Notes about this audio import batch...";
		default:                 return @"Add notes about this observation...";
	}
}

// ---------- Global Window State ----------

// Global references to the observation window and key UI elements,
// used by button callbacks to read field values and close the window.
static NSWindow    *g_obsWindow      = nil;  // The observation window itself.
static NSTextField *g_obsTagsField   = nil;  // Tags text field in Tags tab.
static NSTextField *g_obsExtraField  = nil;  // Extra tags text field in Tags tab.
static NSTextField *g_obsTitleField  = nil;  // Title text field in Tags tab.
static NSTextView  *g_obsSummaryText = nil;  // Summary/notes text view in Tags tab.
static NSTextField *g_obsCtValue     = nil;  // Content type label in Tags tab.
static NSTabView   *g_obsTabView     = nil;  // The tab view for switching tabs.
static char        *g_obsImagePath   = NULL; // Screenshot path stored for draft saving.
static NSTextField *g_recordSourceLabel = nil; // "from clipboard" / "snapshot at ..." label.
static NSTextField *g_recordStatusLabel = nil; // Record tab status label.
static NSButton    *g_recordStopButton = nil;  // Record tab stop button.

// Forward declaration of the Go callbacks (exported from Go via //export).
// Note: Go's cgo exports use char* (not const char*).
extern void goObservationCancelCallback(char *tags, char *notes,
                                         char *contentType, char *imagePath);
extern void goObservationStoreCallback(char *tags, char *notes,
                                        char *contentType, char *imagePath);
extern void goObservationStopCallback(int elapsedSeconds);

// ---------- Tab Switching ----------

// switchToTab switches the NSTabView to the given tab index (0=Record, 1=Review, 2=Tags).
// Safe to call from any thread — dispatches to the main thread.
static void switchToTab(int tabIndex) {
	dispatch_async(dispatch_get_main_queue(), ^{
		if (g_obsTabView != nil) {
			NSInteger count = [g_obsTabView numberOfTabViewItems];
			if (tabIndex >= 0 && tabIndex < count) {
				[g_obsTabView selectTabViewItemAtIndex:tabIndex];
			}
		}
	});
}

// ---------- Tags Field Update ----------

// setObservationTags updates the tags text field in the Tags tab.
// Thread-safe: dispatches to the main thread.
static void setObservationTags(const char *tags) {
	if (tags == NULL) return;
	NSString *nsTags = [NSString stringWithUTF8String:tags];
	dispatch_async(dispatch_get_main_queue(), ^{
		if (g_obsTagsField != nil) {
			[g_obsTagsField setStringValue:nsTags];
		}
	});
}

// setObservationTitle updates the title text field in the Tags tab.
// Thread-safe: dispatches to the main thread.
static void setObservationTitle(const char *title) {
	if (title == NULL) return;
	NSString *nsTitle = [NSString stringWithUTF8String:title];
	dispatch_async(dispatch_get_main_queue(), ^{
		if (g_obsTitleField != nil) {
			[g_obsTitleField setStringValue:nsTitle];
		}
	});
}

// ---------- Helper: read UI fields ----------

// Helper that reads the current tags, notes, contentType, and imagePath from
// the observation window UI controls. Called by both Store and Cancel handlers.
static void readObsFields(NSString **outTags, NSString **outNotes,
                           NSString **outContentType, NSString **outImgPath) {
	// Combine main tags and extra tags.
	NSString *mainTags = (g_obsTagsField != nil) ? [g_obsTagsField stringValue] : @"";
	NSString *extraTags = (g_obsExtraField != nil) ? [g_obsExtraField stringValue] : @"";
	if ([extraTags length] > 0 && [mainTags length] > 0) {
		*outTags = [NSString stringWithFormat:@"%@, %@", mainTags, extraTags];
	} else if ([extraTags length] > 0) {
		*outTags = extraTags;
	} else {
		*outTags = mainTags;
	}
	*outNotes = (g_obsSummaryText != nil) ? [[g_obsSummaryText string] copy] : @"";
	*outContentType = (g_obsCtValue != nil) ? [g_obsCtValue stringValue] : @"";
	*outImgPath = (g_obsImagePath != NULL)
		? [NSString stringWithUTF8String:g_obsImagePath] : @"";
}

// Helper that resets all global observation window state and closes the window.
static void closeObsWindow(void) {
	if (g_obsWindow != nil) {
		[g_obsWindow close];
		g_obsWindow = nil;
	}
	// Revert to menu-bar-only mode (hide from Cmd+Tab and dock).
	[NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
	g_obsTagsField = nil;
	g_obsExtraField = nil;
	g_obsTitleField = nil;
	g_obsSummaryText = nil;
	g_obsCtValue = nil;
	g_obsTabView = nil;
	g_reviewTextView = nil;
	g_recordSourceLabel = nil;
	g_recordStatusLabel = nil;
	g_recordStopButton = nil;
	g_whisperProgress = nil;
	if (g_obsImagePath != NULL) {
		free(g_obsImagePath);
		g_obsImagePath = NULL;
	}
	stopRecordingTimer();
	resetVUMeter();
}

// ---------- Button Handlers via ObjC Runtime ----------
//
// We register handler classes dynamically using the ObjC runtime API to avoid
// duplicate symbol errors. When cgo has //export directives, the C preamble
// gets compiled into multiple object files; @interface/@implementation would
// create duplicate ObjC class symbols at link time. Dynamic registration
// via objc_allocateClassPair ensures each class is defined exactly once.

#import <objc/runtime.h>

// cancelClickedIMP is the IMP for the Cancel button's action method.
static void cancelClickedIMP(id self, SEL _cmd, id sender) {
	(void)self; (void)_cmd; (void)sender;
	NSString *tags, *notes, *contentType, *imgPath;
	readObsFields(&tags, &notes, &contentType, &imgPath);

	goObservationCancelCallback(
		(char *)[tags UTF8String],
		(char *)[notes UTF8String],
		(char *)[contentType UTF8String],
		(char *)[imgPath UTF8String]
	);
	closeObsWindow();
}

// stopClickedIMP is the IMP for the Stop Recording button's action method.
// Stops the elapsed timer, resets the VU meter, switches to the Review tab,
// and notifies Go via goObservationStopCallback with the elapsed seconds.
static void stopClickedIMP(id self, SEL _cmd, id sender) {
	(void)self; (void)_cmd; (void)sender;
	int elapsed = getElapsedSeconds();
	stopRecordingTimer();
	resetVUMeter();
	if (g_recordStatusLabel != nil) {
		[g_recordStatusLabel setStringValue:@"● Stopped"];
	}
	if (g_recordStopButton != nil) {
		[g_recordStopButton setTitle:@"⏹ Stopped"];
		[g_recordStopButton setEnabled:NO];
	}
	switchToTab(1); // Switch to Review tab
	goObservationStopCallback(elapsed);
}

// storeClickedIMP is the IMP for the Store button's action method.
static void storeClickedIMP(id self, SEL _cmd, id sender) {
	(void)self; (void)_cmd; (void)sender;
	NSString *tags, *notes, *contentType, *imgPath;
	readObsFields(&tags, &notes, &contentType, &imgPath);

	goObservationStoreCallback(
		(char *)[tags UTF8String],
		(char *)[notes UTF8String],
		(char *)[contentType UTF8String],
		(char *)[imgPath UTF8String]
	);
	closeObsWindow();
}

// captureHintCancelClickedIMP is the IMP for the screenshot hint panel's
// Cancel button. It marks capture cancelled and hides the hint panel.
static void captureHintCancelClickedIMP(id self, SEL _cmd, id sender) {
	(void)self; (void)_cmd; (void)sender;
	g_captureHintCancelled = 1;
	if (g_captureHintPanel != nil) {
		[g_captureHintPanel orderOut:nil];
	}
}

// captureHintContinueClickedIMP is the IMP for the screenshot hint panel's
// Capture button. It hides the hint panel and keeps capture flow active.
static void captureHintContinueClickedIMP(id self, SEL _cmd, id sender) {
	(void)self; (void)_cmd; (void)sender;
	if (g_captureHintPanel != nil) {
		[g_captureHintPanel orderOut:nil];
	}
	(void)triggerClipboardRegionScreenshotHotkey();
}

// Singleton handler instances for buttons and window delegate (dynamically registered).
static id g_cancelHandler   = nil;
static id g_storeHandler    = nil;
static id g_stopHandler     = nil;
static id g_windowDelegate  = nil;
static id g_captureHintHandler = nil;

// ---------- Window Delegate: close (red X) interception ----------

// windowShouldCloseIMP intercepts the window close button (red X).
// It stops any active recording, then shows a Keep/Discard confirmation dialog.
// Keep  → saves draft via goObservationCancelCallback, then closes.
// Discard → closes the window without saving.
// Returns NO to prevent immediate close; the handler closes the window itself.
static BOOL windowShouldCloseIMP(id self, SEL _cmd, id sender) {
	(void)self; (void)_cmd; (void)sender;

	// Stop any active recording timer and VU meter first.
	stopRecordingTimer();
	resetVUMeter();

	// Build a Keep/Discard confirmation alert.
	NSAlert *alert = [[NSAlert alloc] init];
	[alert setMessageText:@"Close Observation Window?"];
	[alert setInformativeText:@"Would you like to keep your work as a draft, or discard it?"];
	[alert setAlertStyle:NSAlertStyleWarning];
	[alert addButtonWithTitle:@"Keep as Draft"];   // NSAlertFirstButtonReturn
	[alert addButtonWithTitle:@"Discard"];          // NSAlertSecondButtonReturn

	NSModalResponse response = [alert runModal];

	if (response == NSAlertFirstButtonReturn) {
		// Keep: read fields, save draft via the cancel callback, then close.
		NSString *tags, *notes, *contentType, *imgPath;
		readObsFields(&tags, &notes, &contentType, &imgPath);

		goObservationCancelCallback(
			(char *)[tags UTF8String],
			(char *)[notes UTF8String],
			(char *)[contentType UTF8String],
			(char *)[imgPath UTF8String]
		);
	}
	// Both Keep and Discard: close the window and clean up.
	closeObsWindow();
	return NO; // We already closed it; prevent double-close.
}

// ensureHandlerClasses registers ObsCancelHandler, ObsStoreHandler,
// ObsStopHandler, and ObsWindowDelegate classes with the ObjC runtime
// if they haven't been registered yet.
static void ensureHandlerClasses(void) {
	static BOOL registered = NO;
	if (registered) return;
	registered = YES;

	// Register ObsCancelHandler class with cancelClicked: method.
	Class cancelCls = objc_allocateClassPair([NSObject class], "ObsCancelHandler", 0);
	if (cancelCls != Nil) {
		class_addMethod(cancelCls, @selector(cancelClicked:),
			(IMP)cancelClickedIMP, "v@:@");
		objc_registerClassPair(cancelCls);
	}

	// Register ObsStoreHandler class with storeClicked: method.
	Class storeCls = objc_allocateClassPair([NSObject class], "ObsStoreHandler", 0);
	if (storeCls != Nil) {
		class_addMethod(storeCls, @selector(storeClicked:),
			(IMP)storeClickedIMP, "v@:@");
		objc_registerClassPair(storeCls);
	}

	// Register ObsStopHandler class with stopClicked: method.
	Class stopCls = objc_allocateClassPair([NSObject class], "ObsStopHandler", 0);
	if (stopCls != Nil) {
		class_addMethod(stopCls, @selector(stopClicked:),
			(IMP)stopClickedIMP, "v@:@");
		objc_registerClassPair(stopCls);
	}

	// Register ObsWindowDelegate class implementing NSWindowDelegate's
	// windowShouldClose: to intercept the red X close button.
	Class delegateCls = objc_allocateClassPair([NSObject class], "ObsWindowDelegate", 0);
	if (delegateCls != Nil) {
		Protocol *winDelegateProto = @protocol(NSWindowDelegate);
		if (winDelegateProto != nil) {
			class_addProtocol(delegateCls, winDelegateProto);
		}
		class_addMethod(delegateCls, @selector(windowShouldClose:),
			(IMP)windowShouldCloseIMP, "c@:@");
		objc_registerClassPair(delegateCls);
	}

	// Register ObsCaptureHintHandler class with captureHintCancelClicked: method.
	Class captureHintCls = objc_allocateClassPair([NSObject class], "ObsCaptureHintHandler", 0);
	if (captureHintCls != Nil) {
		class_addMethod(captureHintCls, @selector(captureHintContinueClicked:),
			(IMP)captureHintContinueClickedIMP, "v@:@");
		class_addMethod(captureHintCls, @selector(captureHintCancelClicked:),
			(IMP)captureHintCancelClickedIMP, "v@:@");
		objc_registerClassPair(captureHintCls);
	}
}

// getOrCreateCancelHandler returns the singleton cancel handler instance.
static id getOrCreateCancelHandler(void) {
	ensureHandlerClasses();
	if (g_cancelHandler == nil) {
		Class cls = objc_getClass("ObsCancelHandler");
		g_cancelHandler = [[cls alloc] init];
	}
	return g_cancelHandler;
}

// getOrCreateStoreHandler returns the singleton store handler instance.
static id getOrCreateStoreHandler(void) {
	ensureHandlerClasses();
	if (g_storeHandler == nil) {
		Class cls = objc_getClass("ObsStoreHandler");
		g_storeHandler = [[cls alloc] init];
	}
	return g_storeHandler;
}

// getOrCreateStopHandler returns the singleton stop handler instance.
static id getOrCreateStopHandler(void) {
	ensureHandlerClasses();
	if (g_stopHandler == nil) {
		Class cls = objc_getClass("ObsStopHandler");
		g_stopHandler = [[cls alloc] init];
	}
	return g_stopHandler;
}

// getOrCreateWindowDelegate returns the singleton window delegate instance.
static id getOrCreateWindowDelegate(void) {
	ensureHandlerClasses();
	if (g_windowDelegate == nil) {
		Class cls = objc_getClass("ObsWindowDelegate");
		g_windowDelegate = [[cls alloc] init];
	}
	return g_windowDelegate;
}

// getOrCreateCaptureHintHandler returns the singleton hint cancel handler.
static id getOrCreateCaptureHintHandler(void) {
	ensureHandlerClasses();
	if (g_captureHintHandler == nil) {
		Class cls = objc_getClass("ObsCaptureHintHandler");
		g_captureHintHandler = [[cls alloc] init];
	}
	return g_captureHintHandler;
}

// ---------- Observation Window (Cocoa) ----------

// showObservationWindow creates and shows a native NSWindow with 3 tabs.
// imagePath may be NULL or empty to skip image display.
// meta may be NULL for default placeholder metadata in the Review tab.
// Returns 1 on success, 0 on failure.
static int showObservationWindow(const char *title, const char *imagePath, const ReviewMeta *meta, int channelType) {
	// Must run on main thread for Cocoa UI.
	// dispatch_sync (not async) because the Go caller uses defer C.free()
	// on the string arguments — async would use-after-free the pointers.
	dispatch_sync(dispatch_get_main_queue(), ^{
		// ---- Screen geometry for sizing ----
		NSScreen *screen = [NSScreen mainScreen];
		NSRect screenFrame = [screen visibleFrame];
		CGFloat maxW = screenFrame.size.width  * 0.5;
		CGFloat maxH = screenFrame.size.height * 0.5;

		// Window is 50% of screen in each dimension (min 480x360).
		CGFloat winW = (maxW > 480) ? maxW : 480;
		CGFloat winH = (maxH > 360) ? maxH : 360;

		NSRect winRect = NSMakeRect(
			screenFrame.origin.x + (screenFrame.size.width  - winW) / 2,
			screenFrame.origin.y + (screenFrame.size.height - winH) / 2,
			winW, winH
		);

		NSWindow *window = [[NSWindow alloc]
			initWithContentRect:winRect
			styleMask:(NSWindowStyleMaskTitled |
					   NSWindowStyleMaskClosable |
					   NSWindowStyleMaskResizable |
					   NSWindowStyleMaskMiniaturizable)
			backing:NSBackingStoreBuffered
			defer:NO];

		NSString *nsTitle = title ? [NSString stringWithUTF8String:title]
								  : @"Observation Window";
		[window setTitle:nsTitle];
		[window setReleasedWhenClosed:NO];
		[window setHidesOnDeactivate:NO];

		// Make the app appear in Cmd+Tab while the observation window is open.
		[NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];

		// Set window delegate to intercept close (red X) button.
		[window setDelegate:getOrCreateWindowDelegate()];

		// Store global window reference.
		g_obsWindow = window;

		// Store image path for draft saving.
		if (g_obsImagePath != NULL) {
			free(g_obsImagePath);
			g_obsImagePath = NULL;
		}
		if (imagePath != NULL && strlen(imagePath) > 0) {
			g_obsImagePath = strdup(imagePath);
		}

		// ---- Tab View ----
		NSTabView *tabView = [[NSTabView alloc] initWithFrame:
			NSMakeRect(0, 0, winW, winH)];
		[tabView setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
		g_obsTabView = tabView;

		// ======== Tab 1: Record ========
		NSTabViewItem *recordTab = [[NSTabViewItem alloc] initWithIdentifier:@"record"];
		[recordTab setLabel:@"Record"];

		NSView *recordView = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, winW, winH - 60)];
		[recordView setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];

		// -- Image view (scaled to max 50% screen w/h) --
		NSImageView *imageView = [[NSImageView alloc]
			initWithFrame:NSMakeRect(10, 80, winW - 20, winH - 160)];
		[imageView setImageScaling:NSImageScaleProportionallyDown];
		[imageView setImageAlignment:NSImageAlignCenter];
		[imageView setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
		[imageView setImageFrameStyle:NSImageFrameNone];
		[imageView setWantsLayer:YES];
		[[imageView layer] setBackgroundColor:[[NSColor clearColor] CGColor]];

		if (imagePath != NULL && strlen(imagePath) > 0) {
			NSString *nsPath = [NSString stringWithUTF8String:imagePath];
			NSImage *image = [[NSImage alloc] initWithContentsOfFile:nsPath];
			if (image != nil) {
				// Compute scaled size: fit within maxW x maxH.
				NSSize origSize = [image size];
				CGFloat scale = 1.0;
				if (origSize.width > maxW) {
					scale = maxW / origSize.width;
				}
				if (origSize.height * scale > maxH) {
					scale = maxH / origSize.height;
				}
				NSSize scaledSize = NSMakeSize(origSize.width * scale,
											   origSize.height * scale);
				[image setSize:scaledSize];
				[imageView setImage:image];
			}
		}
		[recordView addSubview:imageView];

		// -- Source label overlaid on bottom-left of image --
		NSTextField *sourceLabel = [[NSTextField alloc]
			initWithFrame:NSMakeRect(15, 82, 300, 22)];
		[sourceLabel setStringValue:@""];
		[sourceLabel setBezeled:NO];
		[sourceLabel setDrawsBackground:YES];
		[sourceLabel setBackgroundColor:[NSColor colorWithCalibratedWhite:0.0 alpha:0.55]];
		[sourceLabel setTextColor:[NSColor whiteColor]];
		[sourceLabel setEditable:NO];
		[sourceLabel setSelectable:NO];
		[sourceLabel setFont:[NSFont systemFontOfSize:11 weight:NSFontWeightMedium]];
		[sourceLabel setAutoresizingMask:(NSViewMaxXMargin | NSViewMaxYMargin)];
		[sourceLabel setHidden:YES]; // shown when source text is set
		[recordView addSubview:sourceLabel];
		g_recordSourceLabel = sourceLabel;

		// -- VU Meter (track + fill + dB label) --
		// Track: dark background container with rounded corners.
		CGFloat vuTrackW = winW - 100; // leave room for dB label
		NSView *vuTrack = [[NSView alloc]
			initWithFrame:NSMakeRect(10, 50, vuTrackW, 20)];
		[vuTrack setWantsLayer:YES];
		[[vuTrack layer] setBackgroundColor:
			[[NSColor colorWithCalibratedWhite:0.2 alpha:1.0] CGColor]];
		[[vuTrack layer] setCornerRadius:4.0];
		[vuTrack setAutoresizingMask:(NSViewWidthSizable | NSViewMinYMargin)];
		g_vuTrackView = vuTrack;

		// Fill: colored bar inside the track, starts at zero width.
		NSView *vuFill = [[NSView alloc]
			initWithFrame:NSMakeRect(0, 0, 0, 20)];
		[vuFill setWantsLayer:YES];
		[[vuFill layer] setBackgroundColor:
			[[NSColor systemGreenColor] CGColor]];
		[[vuFill layer] setCornerRadius:4.0];
		[vuFill setAutoresizingMask:(NSViewMaxXMargin | NSViewHeightSizable)];
		g_vuFillView = vuFill;
		[vuTrack addSubview:vuFill];
		[recordView addSubview:vuTrack];

		// dB readout label to the right of the track.
		NSTextField *vuLabel = [[NSTextField alloc]
			initWithFrame:NSMakeRect(winW - 80, 50, 70, 20)];
		[vuLabel setStringValue:@"-∞ dB"];
		[vuLabel setBezeled:NO];
		[vuLabel setDrawsBackground:NO];
		[vuLabel setEditable:NO];
		[vuLabel setSelectable:NO];
		[vuLabel setAlignment:NSTextAlignmentRight];
		[vuLabel setFont:[NSFont monospacedDigitSystemFontOfSize:11 weight:NSFontWeightRegular]];
		[vuLabel setTextColor:[NSColor secondaryLabelColor]];
		[vuLabel setAutoresizingMask:(NSViewMinXMargin | NSViewMinYMargin)];
		g_vuLabel = vuLabel;
		[recordView addSubview:vuLabel];

		// -- Status label --
		NSTextField *statusLabel = [[NSTextField alloc]
			initWithFrame:NSMakeRect(10, 10, winW - 310, 30)];
		[statusLabel setStringValue:@"● Ready to record"];
		[statusLabel setBezeled:NO];
		[statusLabel setDrawsBackground:NO];
		[statusLabel setEditable:NO];
		[statusLabel setSelectable:NO];
		[statusLabel setFont:[NSFont systemFontOfSize:13]];
		[statusLabel setAutoresizingMask:(NSViewWidthSizable | NSViewMaxYMargin)];
		[recordView addSubview:statusLabel];
		g_recordStatusLabel = statusLabel;

		// -- Elapsed timer label (MM:SS) --
		NSTextField *timerLabel = [[NSTextField alloc]
			initWithFrame:NSMakeRect(winW - 290, 10, 100, 30)];
		[timerLabel setStringValue:@"00:00"];
		[timerLabel setBezeled:NO];
		[timerLabel setDrawsBackground:NO];
		[timerLabel setEditable:NO];
		[timerLabel setSelectable:NO];
		[timerLabel setAlignment:NSTextAlignmentCenter];
		[timerLabel setFont:[NSFont monospacedDigitSystemFontOfSize:18 weight:NSFontWeightMedium]];
		[timerLabel setTextColor:[NSColor secondaryLabelColor]];
		[timerLabel setAutoresizingMask:(NSViewMinXMargin | NSViewMaxYMargin)];
		[recordView addSubview:timerLabel];

		// Store reference to timer label for global timer functions.
		g_timerLabel = timerLabel;
		g_elapsedSeconds = 0;

		// -- Stop Recording button (wired to ObsStopHandler) --
		NSButton *stopBtn = [NSButton buttonWithTitle:@"⏹ Stop Recording"
											   target:getOrCreateStopHandler()
											   action:@selector(stopClicked:)];
		[stopBtn setFrame:NSMakeRect(winW - 170, 10, 150, 30)];
		[stopBtn setAutoresizingMask:(NSViewMinXMargin | NSViewMaxYMargin)];
		[stopBtn setEnabled:YES];
		[recordView addSubview:stopBtn];
		g_recordStopButton = stopBtn;

		[recordTab setView:recordView];
		[tabView addTabViewItem:recordTab];

		// ======== Tab 2: Review ========
		NSTabViewItem *reviewTab = [[NSTabViewItem alloc] initWithIdentifier:@"review"];
		[reviewTab setLabel:@"Review"];

		CGFloat rvH = winH - 60; // content height inside tab
		NSView *reviewView = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, winW, rvH)];
		[reviewView setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];

		// ---- Metadata header (NSBox with key-value grid) ----
		// 4 rows x 2 columns showing recording metadata at the top of the tab.
		CGFloat headerH = 100;
		CGFloat headerY = rvH - headerH - 10; // 10px top margin

		NSBox *metaBox = [[NSBox alloc]
			initWithFrame:NSMakeRect(10, headerY, winW - 20, headerH)];
		[metaBox setBoxType:NSBoxCustom];
		[metaBox setFillColor:[NSColor colorWithCalibratedWhite:0.95 alpha:1.0]];
		[metaBox setBorderColor:[NSColor separatorColor]];
		[metaBox setBorderWidth:0.5];
		[metaBox setCornerRadius:6.0];
		[metaBox setTitlePosition:NSNoTitle];
		[metaBox setAutoresizingMask:(NSViewWidthSizable | NSViewMinYMargin)];

		// Resolve metadata values from the ReviewMeta struct (with safe fallbacks).
		NSString *metaSource   = meta ? safeNSString(meta->source, @"\xe2\x80\x94")   : @"\xe2\x80\x94";
		NSString *metaLang     = meta ? safeNSString(meta->language, @"\xe2\x80\x94") : @"\xe2\x80\x94";
		NSString *metaDuration = meta ? safeNSString(meta->duration, @"\xe2\x80\x94") : @"\xe2\x80\x94";
		NSString *metaFileSize = meta ? safeNSString(meta->fileSize, @"\xe2\x80\x94") : @"\xe2\x80\x94";
		NSString *metaDate     = meta ? safeNSString(meta->date, @"\xe2\x80\x94")     : @"\xe2\x80\x94";
		NSString *metaFilePath = meta ? safeNSString(meta->filePath, @"\xe2\x80\x94") : @"\xe2\x80\x94";
		int metaSnippets = meta ? meta->snippetCount : 0;
		int metaChars    = meta ? meta->charCount    : 0;

		// Layout constants: 2 columns, 4 rows inside the header box.
		CGFloat boxW = winW - 20;
		CGFloat colW = (boxW - 30) / 2;
		CGFloat rowH2 = 18;
		CGFloat labelW = 70;
		CGFloat valW = colW - labelW - 5;

		CGFloat row0Y = headerH - rowH2 - 8;
		CGFloat row1Y = row0Y - rowH2 - 2;
		CGFloat row2Y = row1Y - rowH2 - 2;
		CGFloat row3Y = row2Y - rowH2 - 2;

		CGFloat col0X = 10;
		CGFloat col0VX = col0X + labelW;
		CGFloat col1X = 10 + colW + 10;
		CGFloat col1VX = col1X + labelW;

		// Row 0: Source / Language
		[metaBox addSubview:makeReadOnlyLabel(NSMakeRect(col0X, row0Y, labelW, rowH2), @"Source:", 11, YES)];
		[metaBox addSubview:makeMetaValueLabel(NSMakeRect(col0VX, row0Y, valW, rowH2), metaSource, 11)];
		[metaBox addSubview:makeReadOnlyLabel(NSMakeRect(col1X, row0Y, labelW, rowH2), @"Language:", 11, YES)];
		[metaBox addSubview:makeMetaValueLabel(NSMakeRect(col1VX, row0Y, valW, rowH2), metaLang, 11)];

		// Row 1: Duration / File Size
		[metaBox addSubview:makeReadOnlyLabel(NSMakeRect(col0X, row1Y, labelW, rowH2), @"Duration:", 11, YES)];
		[metaBox addSubview:makeMetaValueLabel(NSMakeRect(col0VX, row1Y, valW, rowH2), metaDuration, 11)];
		[metaBox addSubview:makeReadOnlyLabel(NSMakeRect(col1X, row1Y, labelW, rowH2), @"File Size:", 11, YES)];
		[metaBox addSubview:makeMetaValueLabel(NSMakeRect(col1VX, row1Y, valW, rowH2), metaFileSize, 11)];

		// Row 2: Snippets / Characters
		NSString *snippetStr = [NSString stringWithFormat:@"%d", metaSnippets];
		NSString *charStr    = [NSString stringWithFormat:@"%d", metaChars];
		[metaBox addSubview:makeReadOnlyLabel(NSMakeRect(col0X, row2Y, labelW, rowH2), @"Snippets:", 11, YES)];
		[metaBox addSubview:makeMetaValueLabel(NSMakeRect(col0VX, row2Y, valW, rowH2), snippetStr, 11)];
		[metaBox addSubview:makeReadOnlyLabel(NSMakeRect(col1X, row2Y, labelW, rowH2), @"Chars:", 11, YES)];
		[metaBox addSubview:makeMetaValueLabel(NSMakeRect(col1VX, row2Y, valW, rowH2), charStr, 11)];

		// Row 3: Date / File Path
		[metaBox addSubview:makeReadOnlyLabel(NSMakeRect(col0X, row3Y, labelW, rowH2), @"Date:", 11, YES)];
		[metaBox addSubview:makeMetaValueLabel(NSMakeRect(col0VX, row3Y, valW, rowH2), metaDate, 11)];
		[metaBox addSubview:makeReadOnlyLabel(NSMakeRect(col1X, row3Y, labelW, rowH2), @"File:", 11, YES)];
		NSTextField *fileLabel = makeMetaValueLabel(NSMakeRect(col1VX, row3Y, valW, rowH2), metaFilePath, 10);
		[fileLabel setLineBreakMode:NSLineBreakByTruncatingMiddle];
		[fileLabel setToolTip:metaFilePath];
		[metaBox addSubview:fileLabel];

		[reviewView addSubview:metaBox];

		// ---- Scrollable transcript text view ----
		CGFloat scrollTop = headerY - 10;
		CGFloat scrollBottom = 50;
		CGFloat scrollH = scrollTop - scrollBottom;

		NSScrollView *scrollView = [[NSScrollView alloc]
			initWithFrame:NSMakeRect(10, scrollBottom, winW - 20, scrollH)];
		[scrollView setHasVerticalScroller:YES];
		[scrollView setHasHorizontalScroller:NO];
		[scrollView setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
		[scrollView setBorderType:NSBezelBorder];
		[scrollView setAutohidesScrollers:YES];

		// Content size is the drawable area inside the scroll view borders.
		NSSize contentSize = [scrollView contentSize];

		NSTextView *textView = [[NSTextView alloc]
			initWithFrame:NSMakeRect(0, 0, contentSize.width, contentSize.height)];

		// -- Proper scroll container setup for long transcripts --
		// Allow the text view to grow vertically without limit so content scrolls.
		[textView setMaxSize:NSMakeSize(FLT_MAX, FLT_MAX)];
		[textView setMinSize:NSMakeSize(0, contentSize.height)];
		[textView setVerticallyResizable:YES];
		[textView setHorizontallyResizable:NO];

		// Text container: wrap at scroll view width, grow vertically unbounded.
		[[textView textContainer] setContainerSize:NSMakeSize(contentSize.width, FLT_MAX)];
		[[textView textContainer] setWidthTracksTextView:YES];

		// Text inset for comfortable reading margin.
		[textView setTextContainerInset:NSMakeSize(4, 6)];

		// Appearance — editable so user can refine the memo text.
		[textView setEditable:YES];
		[textView setSelectable:YES];
		[textView setRichText:NO];
		[textView setFont:[NSFont monospacedSystemFontOfSize:12 weight:NSFontWeightRegular]];
		[textView setString:@"Memo text will appear here after recording is processed..."];
		[textView setBackgroundColor:[NSColor textBackgroundColor]];
		[textView setTextColor:[NSColor textColor]];

		// Autoresizing: width tracks scroll view, height managed by scroll container.
		[textView setAutoresizingMask:NSViewWidthSizable];

		// Performance: enable non-contiguous layout from the start so the
		// layout manager only computes glyphs for the visible portion.
		// This is critical for smooth scrolling with 28K+ char transcripts.
		[[textView layoutManager] setAllowsNonContiguousLayout:YES];

		// Performance: track text view width so wrapping is stable during scroll.
		[[textView textContainer] setWidthTracksTextView:YES];

		[scrollView setDocumentView:textView];
		[reviewView addSubview:scrollView];

		// Store global reference for setReviewTranscript().
		g_reviewTextView = textView;

		// -- Whisper progress bar (indeterminate, hidden initially) --
		NSProgressIndicator *whisperBar = [[NSProgressIndicator alloc]
			initWithFrame:NSMakeRect(10, 35, winW - 20, 10)];
		[whisperBar setStyle:NSProgressIndicatorStyleBar];
		[whisperBar setIndeterminate:YES];
		[whisperBar setDisplayedWhenStopped:NO];
		[whisperBar setHidden:YES];
		[whisperBar setAutoresizingMask:(NSViewWidthSizable | NSViewMaxYMargin)];
		[reviewView addSubview:whisperBar];
		g_whisperProgress = whisperBar;

		// Status bar at bottom.
		NSTextField *reviewStatus = [[NSTextField alloc]
			initWithFrame:NSMakeRect(10, 10, winW - 20, 30)];
		[reviewStatus setStringValue:@"Waiting for recording..."];
		[reviewStatus setBezeled:NO];
		[reviewStatus setDrawsBackground:NO];
		[reviewStatus setEditable:NO];
		[reviewStatus setSelectable:NO];
		[reviewStatus setFont:[NSFont systemFontOfSize:13]];
		[reviewStatus setAutoresizingMask:(NSViewWidthSizable | NSViewMaxYMargin)];
		[reviewStatus setTag:1001];
		[reviewView addSubview:reviewStatus];

		[reviewTab setView:reviewView];
		[tabView addTabViewItem:reviewTab];

		// ======== Tab 3: Tags (pre-filled per channel type) ========
		NSTabViewItem *tagsTab = [[NSTabViewItem alloc] initWithIdentifier:@"tags"];
		[tagsTab setLabel:@"Tags"];

		NSView *tagsView = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, winW, winH - 60)];
		[tagsView setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];

		// Layout constants for the Tags tab form fields.
		CGFloat tLabelW  = 90;   // width of left-column labels
		CGFloat fieldX   = 100;  // x-origin for text fields
		CGFloat fieldW   = winW - fieldX - 10; // text field width (fills remaining)
		CGFloat tRowH     = 30;   // row height
		CGFloat tPadY     = 8;    // vertical padding between rows

		// -- Row 1: Channel (read-only display) --
		CGFloat tRow1Y = winH - 110;

		NSTextField *channelLabel = makeReadOnlyLabel(
			NSMakeRect(10, tRow1Y, tLabelW, 20), @"Channel:", 13, YES);
		[channelLabel setAutoresizingMask:(NSViewMinYMargin)];
		[tagsView addSubview:channelLabel];

		NSTextField *channelValue = makeMetaValueLabel(
			NSMakeRect(fieldX, tRow1Y - 2, fieldW, 24),
			channelDisplayName(channelType), 13);
		[channelValue setAutoresizingMask:(NSViewWidthSizable | NSViewMinYMargin)];
		[tagsView addSubview:channelValue];

		// -- Row 2: Content Type (read-only, from channel) --
		CGFloat tRow2Y = tRow1Y - tRowH - tPadY;

		NSTextField *ctLabel = makeReadOnlyLabel(
			NSMakeRect(10, tRow2Y, tLabelW, 20), @"Type:", 13, YES);
		[ctLabel setAutoresizingMask:(NSViewMinYMargin)];
		[tagsView addSubview:ctLabel];

		NSTextField *ctValue = makeMetaValueLabel(
			NSMakeRect(fieldX, tRow2Y - 2, fieldW, 24),
			contentTypeLabelForChannel(channelType), 13);
		[ctValue setAutoresizingMask:(NSViewWidthSizable | NSViewMinYMargin)];
		[tagsView addSubview:ctValue];
		g_obsCtValue = ctValue;

		// -- Row 3: Title (editable) --
		CGFloat tRow3Y = tRow2Y - tRowH - tPadY;

		NSTextField *titleLabel = makeReadOnlyLabel(
			NSMakeRect(10, tRow3Y, tLabelW, 20), @"Title:", 13, YES);
		[titleLabel setAutoresizingMask:(NSViewMinYMargin)];
		[tagsView addSubview:titleLabel];

		NSTextField *titleField = [[NSTextField alloc]
			initWithFrame:NSMakeRect(fieldX, tRow3Y - 2, fieldW, 24)];
		[titleField setStringValue:@""];
		[titleField setEditable:YES];
		[titleField setFont:[NSFont systemFontOfSize:13]];
		[titleField setPlaceholderString:@"Observation title (optional)"];
		[titleField setAutoresizingMask:(NSViewWidthSizable | NSViewMinYMargin)];
		[tagsView addSubview:titleField];
		g_obsTitleField = titleField;

		// -- Row 4: Tags (editable, pre-filled per channel) --
		CGFloat tRow4Y = tRow3Y - tRowH - tPadY;

		NSTextField *tagsLabel = makeReadOnlyLabel(
			NSMakeRect(10, tRow4Y, tLabelW, 20), @"Tags:", 13, YES);
		[tagsLabel setAutoresizingMask:(NSViewMinYMargin)];
		[tagsView addSubview:tagsLabel];

		NSTextField *tagsField = [[NSTextField alloc]
			initWithFrame:NSMakeRect(fieldX, tRow4Y - 2, fieldW, 24)];
		[tagsField setStringValue:defaultTagsForChannel(channelType)];
		[tagsField setEditable:YES];
		[tagsField setFont:[NSFont systemFontOfSize:13]];
		[tagsField setPlaceholderString:@"Comma-separated tags"];
		[tagsField setAutoresizingMask:(NSViewWidthSizable | NSViewMinYMargin)];
		[tagsView addSubview:tagsField];
		g_obsTagsField = tagsField;

		// -- Row 5: Extra Tags (editable, user can add more) --
		CGFloat tRow5Y = tRow4Y - tRowH - tPadY;

		NSTextField *extraLabel = makeReadOnlyLabel(
			NSMakeRect(10, tRow5Y, tLabelW, 20), @"Extra Tags:", 13, YES);
		[extraLabel setAutoresizingMask:(NSViewMinYMargin)];
		[tagsView addSubview:extraLabel];

		NSTextField *extraField = [[NSTextField alloc]
			initWithFrame:NSMakeRect(fieldX, tRow5Y - 2, fieldW, 24)];
		[extraField setStringValue:@""];
		[extraField setEditable:YES];
		[extraField setFont:[NSFont systemFontOfSize:13]];
		[extraField setPlaceholderString:@"Additional comma-separated tags"];
		[extraField setAutoresizingMask:(NSViewWidthSizable | NSViewMinYMargin)];
		[tagsView addSubview:extraField];
		g_obsExtraField = extraField;

		// -- Notes / Summary text area (below the form fields, above buttons) --
		NSTextField *notesLabel = makeReadOnlyLabel(
			NSMakeRect(10, tRow5Y - tRowH - tPadY, tLabelW, 20), @"Notes:", 13, YES);
		[notesLabel setAutoresizingMask:(NSViewMinYMargin)];
		[tagsView addSubview:notesLabel];

		CGFloat notesTop = tRow5Y - tRowH - tPadY - 5;
		CGFloat notesBot = 60; // leave room for buttons
		CGFloat notesH   = notesTop - notesBot;
		if (notesH < 60) notesH = 60;

		NSScrollView *summaryScroll = [[NSScrollView alloc]
			initWithFrame:NSMakeRect(fieldX, notesBot, fieldW, notesH)];
		[summaryScroll setHasVerticalScroller:YES];
		[summaryScroll setBorderType:NSBezelBorder];
		[summaryScroll setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];

		NSTextView *summaryText = [[NSTextView alloc]
			initWithFrame:NSMakeRect(0, 0, fieldW - 20, notesH)];
		[summaryText setEditable:YES];
		[summaryText setFont:[NSFont systemFontOfSize:12]];
		[summaryText setString:notesPlaceholderForChannel(channelType)];
		[summaryText setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
		[summaryScroll setDocumentView:summaryText];
		[tagsView addSubview:summaryScroll];
		g_obsSummaryText = summaryText;

		// Store and Cancel buttons (using dynamically-registered ObjC classes).
		NSButton *cancelBtn = [NSButton buttonWithTitle:@"Cancel (Save Draft)"
												 target:getOrCreateCancelHandler()
												 action:@selector(cancelClicked:)];
		[cancelBtn setFrame:NSMakeRect(10, 10, 160, 40)];
		[cancelBtn setAutoresizingMask:(NSViewMaxXMargin | NSViewMaxYMargin)];
		[tagsView addSubview:cancelBtn];

		NSButton *storeBtn = [NSButton buttonWithTitle:@"Store → ER1"
												target:getOrCreateStoreHandler()
												action:@selector(storeClicked:)];
		[storeBtn setFrame:NSMakeRect(winW - 170, 10, 150, 40)];
		[storeBtn setBezelStyle:NSBezelStyleRounded];
		[storeBtn setKeyEquivalent:@"\r"]; // Enter key
		[storeBtn setAutoresizingMask:(NSViewMinXMargin | NSViewMaxYMargin)];
		[tagsView addSubview:storeBtn];

		[tagsTab setView:tagsView];
		[tabView addTabViewItem:tagsTab];

		// ---- Assemble window ----
		[[window contentView] addSubview:tabView];
		[window makeKeyAndOrderFront:nil];
		[NSApp activateIgnoringOtherApps:YES];
	});

	return 1;
}
*/
import "C"
import (
	"fmt"
	"log"
	"strings"
	"sync"
	"unsafe"

	"github.com/kamir/m3c-tools/pkg/draft"
)

// CancelCallback is called when the user clicks "Cancel (Save Draft)" in
// the Observation Window. The draft has already been saved to disk; the
// callback receives the saved file path. Set via SetObservationCancelCallback.
type CancelCallback func(draftPath string)

// StoreCallback is called when the user clicks "Store → ER1" in the
// Observation Window. It receives the tags, notes, content type, and
// image path from the Tags tab fields.
type StoreCallback func(tags, notes, contentType, imagePath string)

// StopRecordingCallback is called when the user clicks "Stop Recording" in
// the Record tab. It receives the elapsed recording time in seconds. The
// callback should stop any active audio recording and initiate whisper
// transcription. The UI has already switched to the Review tab.
type StopRecordingCallback func(elapsedSeconds int)

var (
	cancelMu       sync.Mutex
	cancelCallback CancelCallback
	storeMu        sync.Mutex
	storeCallback  StoreCallback
	stopMu         sync.Mutex
	stopCallback   StopRecordingCallback
)

// SetObservationCancelCallback registers a function that is called after
// a draft is saved via the Cancel button. The App can use this to update
// its status back to idle.
func SetObservationCancelCallback(cb CancelCallback) {
	cancelMu.Lock()
	defer cancelMu.Unlock()
	cancelCallback = cb
}

// SetObservationStoreCallback registers a function that is called when
// the user clicks "Store → ER1". The callback receives the tags, notes,
// content type, and image path from the observation window fields.
func SetObservationStoreCallback(cb StoreCallback) {
	storeMu.Lock()
	defer storeMu.Unlock()
	storeCallback = cb
}

// SetStopRecordingCallback registers a function that is called when the
// user clicks "Stop Recording" in the Record tab. The callback receives
// the elapsed recording time in seconds and should stop the active
// recording, then start whisper transcription. The UI has already
// switched to the Review tab when this callback fires.
func SetStopRecordingCallback(cb StopRecordingCallback) {
	stopMu.Lock()
	defer stopMu.Unlock()
	stopCallback = cb
}

//export goObservationCancelCallback
func goObservationCancelCallback(cTags, cNotes, cContentType, cImagePath *C.char) {
	tags := C.GoString(cTags)
	notes := C.GoString(cNotes)
	contentType := C.GoString(cContentType)
	imagePath := C.GoString(cImagePath)

	// Determine channel from content type.
	channel := draft.ChannelScreenshot
	ctLower := strings.ToLower(contentType)
	switch {
	case strings.Contains(ctLower, "impulse"):
		channel = draft.ChannelImpulse
	case strings.Contains(ctLower, "progress"), strings.Contains(ctLower, "transcript"):
		channel = draft.ChannelTranscript
	case strings.Contains(ctLower, "import"):
		channel = draft.ChannelImport
	}

	// Parse comma-separated tags.
	var tagSlice []string
	for _, t := range strings.Split(tags, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			tagSlice = append(tagSlice, t)
		}
	}

	d := &draft.Draft{
		Channel:        channel,
		Tags:           tagSlice,
		Notes:          notes,
		ScreenshotPath: imagePath,
		ContentType:    contentType,
	}

	path, err := draft.SaveToDefault(d)
	if err != nil {
		log.Printf("[observation] FAIL save draft: %v", err)
		return
	}
	log.Printf("[observation] draft saved: %s", path)

	// Notify the registered callback.
	cancelMu.Lock()
	cb := cancelCallback
	cancelMu.Unlock()
	if cb != nil {
		cb(path)
	}
}

//export goObservationStopCallback
func goObservationStopCallback(cElapsedSeconds C.int) {
	elapsed := int(cElapsedSeconds)
	log.Printf("[observation] stop recording: elapsed=%ds", elapsed)

	stopMu.Lock()
	cb := stopCallback
	stopMu.Unlock()
	if cb != nil {
		// Run in a goroutine so the Cocoa UI thread is not blocked during
		// recording finalization and whisper transcription.
		go cb(elapsed)
	} else {
		log.Printf("[observation] WARNING: no stop callback registered — recording not processed")
	}
}

//export goObservationStoreCallback
func goObservationStoreCallback(cTags, cNotes, cContentType, cImagePath *C.char) {
	tags := C.GoString(cTags)
	notes := C.GoString(cNotes)
	contentType := C.GoString(cContentType)
	imagePath := C.GoString(cImagePath)

	log.Printf("[observation] store requested: contentType=%s tags=%q", contentType, tags)

	storeMu.Lock()
	cb := storeCallback
	storeMu.Unlock()
	if cb != nil {
		// Run in a goroutine so the Cocoa UI thread is not blocked during upload.
		go cb(tags, notes, contentType, imagePath)
	} else {
		log.Printf("[store] WARNING: no store callback registered — upload skipped")
	}
}

// ObservationTab identifies which tab is active in the Observation Window.
type ObservationTab int

const (
	// TabRecord is the first tab — image preview, VU meter, recording controls.
	TabRecord ObservationTab = iota
	// TabReview is the second tab — transcript review after whisper processing.
	TabReview
	// TabTags is the third tab — tag editing before ER1 upload or draft save.
	TabTags
)

// ReviewMetadata holds recording/transcript metadata displayed in the
// Review tab's header section. All fields are optional â empty strings
// and zero values display as "\xe2\x80\x94" or "0" in the UI.
type ReviewMetadata struct {
	Source       string // e.g. "Screenshot", "YouTube", "Microphone"
	Language     string // e.g. "English"
	SnippetCount int    // number of transcript snippets
	CharCount    int    // total character count of transcript text
	Duration     string // e.g. "1m 23s", "0:45"
	FileSize     string // e.g. "42 KB", "1.2 MB"
	Date         string // e.g. "2026-03-10 14:23:05"
	FilePath     string // e.g. "/tmp/recording.wav"
}

// FormatDuration formats seconds into a human-readable duration string.
// Examples: 0 \xe2\x86\x92 "0s", 45 \xe2\x86\x92 "45s", 83 \xe2\x86\x92 "1m 23s", 3661 \xe2\x86\x92 "1h 1m 1s".
func FormatDuration(seconds int) string {
	if seconds < 0 {
		seconds = 0
	}
	if seconds == 0 {
		return "0s"
	}
	h := seconds / 3600
	m := (seconds % 3600) / 60
	s := seconds % 60
	switch {
	case h > 0:
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	case m > 0:
		return fmt.Sprintf("%dm %ds", m, s)
	default:
		return fmt.Sprintf("%ds", s)
	}
}

// FormatFileSize formats byte count into a human-readable size string.
// Examples: 512 \xe2\x86\x92 "512 B", 1536 \xe2\x86\x92 "1.5 KB", 1048576 \xe2\x86\x92 "1.0 MB".
func FormatFileSize(bytes int64) string {
	switch {
	case bytes < 1024:
		return fmt.Sprintf("%d B", bytes)
	case bytes < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	case bytes < 1024*1024*1024:
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	default:
		return fmt.Sprintf("%.1f GB", float64(bytes)/(1024*1024*1024))
	}
}

// ShowObservationWindow creates and displays a native macOS NSWindow with
// 3 tabs (Record, Review, Tags). If imagePath is non-empty, the Record tab
// displays the image scaled to fit within 50% of the screen width/height.
//
// The channelType parameter controls pre-filled tags and labels in the Tags tab:
//   - ChannelTypeProgress: "youtube" with type "YouTube-Video-Impression"
//   - ChannelTypeIdea:     "idea, screenshot" with type "Screenshot"
//   - ChannelTypeImpulse:  "impulse" with type "Impulse"
//   - ChannelTypeImport:   "import, audio-import" with type "Audio-Track"
//
// The window is created on the main thread via dispatch_async and shown
// immediately. This function returns promptly; the window lifecycle is
// managed by the Cocoa run loop.
//
// Returns true if the window was requested successfully.
// ChannelType identifies the observation channel for the Tags tab pre-fill.
type ChannelType int

const (
	// ChannelTypeProgress is Channel A — YouTube video impression.
	ChannelTypeProgress ChannelType = iota
	// ChannelTypeIdea is Channel B — Screenshot observation.
	ChannelTypeIdea
	// ChannelTypeImpulse is Channel C — Quick capture / impulse.
	ChannelTypeImpulse
	// ChannelTypeImport is Channel D — Batch audio import.
	ChannelTypeImport
)

func ShowObservationWindow(title, imagePath string, channelType ChannelType) bool {
	return ShowObservationWindowWithMeta(title, imagePath, channelType, nil)
}

// ShowObservationWindowWithMeta creates the Observation Window with metadata
// pre-populated in the Review tab header. If meta is nil, the Review tab
// displays placeholder values. The channelType controls Tags tab pre-fill.
func ShowObservationWindowWithMeta(title, imagePath string, channelType ChannelType, meta *ReviewMetadata) bool {
	var cTitle *C.char
	if title != "" {
		cTitle = C.CString(title)
		defer C.free(unsafe.Pointer(cTitle))
	}

	var cPath *C.char
	if imagePath != "" {
		cPath = C.CString(imagePath)
		defer C.free(unsafe.Pointer(cPath))
	}

	var cMeta C.ReviewMeta
	var cMetaPtr *C.ReviewMeta

	if meta != nil {
		var cStrs []*C.char
		allocStr := func(s string) *C.char {
			if s == "" {
				return nil
			}
			cs := C.CString(s)
			cStrs = append(cStrs, cs)
			return cs
		}

		cMeta.source = allocStr(meta.Source)
		cMeta.language = allocStr(meta.Language)
		cMeta.snippetCount = C.int(meta.SnippetCount)
		cMeta.charCount = C.int(meta.CharCount)
		cMeta.duration = allocStr(meta.Duration)
		cMeta.fileSize = allocStr(meta.FileSize)
		cMeta.date = allocStr(meta.Date)
		cMeta.filePath = allocStr(meta.FilePath)
		cMetaPtr = &cMeta

		defer func() {
			for _, cs := range cStrs {
				C.free(unsafe.Pointer(cs))
			}
		}()
	}

	return C.showObservationWindow(cTitle, cPath, cMetaPtr, C.int(channelType)) == 1
}

// ShowObservationWindowForScreenshot is a convenience wrapper for Channel B
// (Screenshot capture). It opens the Observation Window with the Record tab
// active, displaying the captured screenshot image.
func ShowObservationWindowForScreenshot(screenshotPath string) bool {
	return ShowObservationWindow("Observation — Screenshot", screenshotPath, ChannelTypeIdea)
}

// ShowObservationWindowForProgress is a convenience wrapper for Channel A
// (YouTube video). Tags are pre-filled with "youtube".
func ShowObservationWindowForProgress(imagePath string) bool {
	return ShowObservationWindow("Observation — YouTube", imagePath, ChannelTypeProgress)
}

// ShowObservationWindowForImpulse is a convenience wrapper for Channel C
// (Quick capture). Tags are pre-filled with "impulse". If imagePath is
// non-empty, the region screenshot is displayed in the Record tab.
func ShowObservationWindowForImpulse(imagePath string) bool {
	return ShowObservationWindow("Observation — Impulse", imagePath, ChannelTypeImpulse)
}

// ShowObservationWindowForImport is a convenience wrapper for Channel D
// (Batch audio import). Tags are pre-filled with "import, audio-import".
func ShowObservationWindowForImport() bool {
	return ShowObservationWindow("Observation — Import", "", ChannelTypeImport)
}

// UpdateReviewTranscript sets the transcript text displayed in the Review tab's
// scrollable NSTextView. The text view is read-only and selectable, allowing
// the user to review and copy transcript content.
//
// Thread-safe: dispatches to the main thread internally. After setting the text,
// the view scrolls to the top automatically.
//
// This is a no-op if the Observation Window has not been shown yet.
func UpdateReviewTranscript(text string) {
	cText := C.CString(text)
	defer C.free(unsafe.Pointer(cText))
	C.setReviewTranscript(cText, nil)
}

// StartRecordingTimer starts the elapsed timer in the Record tab.
// The timer resets to 00:00 and increments every second in MM:SS format.
// Must be called after ShowObservationWindow so the timer label exists.
func StartRecordingTimer() {
	C.startRecordingTimer()
}

// StopRecordingTimer stops the elapsed timer, leaving the final elapsed
// value displayed in the Record tab. Call this when recording ends.
func StopRecordingTimer() {
	C.stopRecordingTimer()
}

// ResetRecordingTimer stops the timer (if running) and resets the display
// to 00:00. Useful when preparing for a new recording session.
func ResetRecordingTimer() {
	C.resetRecordingTimer()
}

// ElapsedSeconds returns the current elapsed recording time in seconds.
// Returns 0 if no recording has started or after a reset.
func ElapsedSeconds() int {
	return int(C.getElapsedSeconds())
}

// UpdateVUMeterLevel sets the VU meter level in the Record tab.
// level is a linear amplitude value from 0.0 (silence) to 1.0 (full scale).
// The meter bar is color-coded: green (< 0.6), yellow (0.6–0.85), red (>= 0.85).
// A dB readout label is updated alongside the bar.
// Safe to call from any goroutine — dispatches to the main thread internally.
func UpdateVUMeterLevel(level float32) {
	C.updateVUMeterLevel(C.float(level))
}

// ResetVUMeter resets the VU meter fill to zero and the dB label to "-∞ dB".
// Useful when stopping a recording or preparing for a new session.
func ResetVUMeter() {
	C.resetVUMeter()
}

// SetRecordSourceLabel sets a label overlaid on the image in the Record tab,
// e.g. "from clipboard" or "snapshot at 08:15:30".
func SetRecordSourceLabel(text string) {
	if text == "" {
		return
	}
	cText := C.CString(text)
	defer C.free(unsafe.Pointer(cText))
	C.setRecordSourceLabel(cText)
}

// PrepareForInteractiveCapture hands app focus back to the previously active
// application before running interactive screencapture from the menu bar app.
func PrepareForInteractiveCapture() {
	C.prepareForInteractiveCapture()
}

// StartFrontmostAppTracker begins tracking frontmost non-M3C applications.
// Call once during menubar startup so screenshot handoff can restore focus.
func StartFrontmostAppTracker() {
	C.startFrontmostAppTracker()
}

// HasScreenCaptureAccess reports whether macOS Screen Recording access is granted.
func HasScreenCaptureAccess() bool {
	return C.hasScreenCaptureAccess() == 1
}

// RequestScreenCaptureAccess asks macOS for Screen Recording permission.
func RequestScreenCaptureAccess() bool {
	return C.requestScreenCaptureAccess() == 1
}

// ClipboardChangeCount returns NSPasteboard.generalPasteboard.changeCount.
func ClipboardChangeCount() int {
	return int(C.clipboardChangeCount())
}

// ShowCaptureHintWindow shows a small non-blocking panel instructing the user
// to take a screenshot via system shortcut in clipboard-first mode.
func ShowCaptureHintWindow(title, detail string) {
	var cTitle, cDetail *C.char
	if title != "" {
		cTitle = C.CString(title)
		defer C.free(unsafe.Pointer(cTitle))
	}
	if detail != "" {
		cDetail = C.CString(detail)
		defer C.free(unsafe.Pointer(cDetail))
	}
	C.showCaptureHintWindow(cTitle, cDetail)
}

// HideCaptureHintWindow hides the non-blocking screenshot instruction panel.
func HideCaptureHintWindow() {
	C.hideCaptureHintWindow()
}

// CaptureHintWasCancelled reports whether the hint window cancel button was clicked.
func CaptureHintWasCancelled() bool {
	return C.captureHintWasCancelled() == 1
}

// ResetCaptureHintCancelled clears the hint window cancel state.
func ResetCaptureHintCancelled() {
	C.resetCaptureHintCancelled()
}

// GetReviewMemoText returns the current (possibly user-edited) text from the
// Review tab's editable text view. Returns empty string if unavailable.
func GetReviewMemoText() string {
	cText := C.getReviewMemoText()
	if cText == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(cText))
	return C.GoString(cText)
}

// ShowWhisperProgress shows and starts animating the indeterminate progress
// bar in the Review tab. Call when whisper transcription begins.
func ShowWhisperProgress() {
	C.showWhisperProgress()
}

// HideWhisperProgress stops and hides the progress bar in the Review tab.
// Call when whisper transcription finishes (success or failure).
func HideWhisperProgress() {
	C.hideWhisperProgress()
}

// SwitchToTab switches the Observation Window to the specified tab.
// Safe to call from any goroutine — dispatches to the main thread internally.
// This is a no-op if the Observation Window has not been shown yet.
func SwitchToTab(tab ObservationTab) {
	C.switchToTab(C.int(tab))
}

// SwitchToReviewTab is a convenience function that switches the Observation
// Window to the Review tab (tab index 1). Typically called after stopping
// a recording to show the transcript processing status.
func SwitchToReviewTab() {
	SwitchToTab(TabReview)
}

// LargeTranscriptThreshold is the character count above which transcript text
// is loaded incrementally in chunks to avoid UI freeze. Exported for testing.
const LargeTranscriptThreshold = 28000

// SetReviewTranscript updates the Review tab's NSTextView with the given
// transcript text. For texts shorter than LargeTranscriptThreshold (28K chars),
// the text is set in one shot. For longer texts, it is loaded incrementally
// in 8 KB chunks with 5 ms delays between chunks so the Cocoa run loop can
// process scroll events and redraws - preventing UI freeze during insertion.
//
// statusText is displayed in the review status bar (e.g., "Transcript loaded -
// 1,234 chars"). If empty, the status bar is not updated.
//
// This function is safe to call from any goroutine; all Cocoa work is
// dispatched to the main thread internally.
func SetReviewTranscript(text, statusText string) {
	if text == "" {
		return
	}
	cText := C.CString(text)
	defer C.free(unsafe.Pointer(cText))

	var cStatus *C.char
	if statusText != "" {
		cStatus = C.CString(statusText)
		defer C.free(unsafe.Pointer(cStatus))
	}

	C.setReviewTranscript(cText, cStatus)
}

// SetObservationTags updates the tags field in the Tags tab of the
// Observation Window. This allows programmatic tag override after
// the window has been created (e.g., to include a YouTube video ID).
// Thread-safe: dispatches to the main thread internally.
// This is a no-op if the Observation Window has not been shown yet.
func SetObservationTags(tags string) {
	if tags == "" {
		return
	}
	cTags := C.CString(tags)
	defer C.free(unsafe.Pointer(cTags))
	C.setObservationTags(cTags)
}

// SetObservationTitle updates the title field in the Tags tab of the
// Observation Window. Thread-safe: dispatches to the main thread internally.
// This is a no-op if the Observation Window has not been shown yet.
func SetObservationTitle(title string) {
	if title == "" {
		return
	}
	cTitle := C.CString(title)
	defer C.free(unsafe.Pointer(cTitle))
	C.setObservationTitle(cTitle)
}

// ShowObservationWindowForYouTube opens the Observation Window for a YouTube
// transcript fetch. It displays the video thumbnail in the Record tab,
// populates Review metadata, sets the transcript in the Review tab, and
// pre-fills tags with "youtube, <videoID>" in the Tags tab.
//
// Parameters:
//   - thumbnailPath: path to the saved thumbnail image (displayed in Record tab)
//   - videoID: the YouTube video ID (added to tags and title)
//   - meta: review metadata (language, snippet count, char count, etc.)
//   - transcriptText: the formatted transcript text for the Review tab
func ShowObservationWindowForYouTube(thumbnailPath, videoID string, meta *ReviewMetadata, transcriptText string) bool {
	title := fmt.Sprintf("Observation — YouTube [%s]", videoID)
	ok := ShowObservationWindowWithMeta(title, thumbnailPath, ChannelTypeProgress, meta)
	if !ok {
		return false
	}

	// Pre-fill tags with video ID
	tags := fmt.Sprintf("youtube, %s", videoID)
	SetObservationTags(tags)

	// Set the video ID as the observation title
	SetObservationTitle(videoID)

	// Set transcript text in the Review tab
	if transcriptText != "" {
		statusText := fmt.Sprintf("Transcript loaded — %d chars", len(transcriptText))
		SetReviewTranscript(transcriptText, statusText)
		// Switch to the Review tab to show the transcript
		SwitchToReviewTab()
	}

	return true
}

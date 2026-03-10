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
#cgo LDFLAGS: -framework Cocoa

#import <Cocoa/Cocoa.h>
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
		case ObsChannelProgress: return @"progress, youtube";
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
		case ObsChannelIdea:     return @"Screenshot";
		case ObsChannelImpulse:  return @"Impulse";
		case ObsChannelImport:   return @"Audio-Track";
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

// Forward declaration of the Go callbacks (exported from Go via //export).
// Note: Go's cgo exports use char* (not const char*).
extern void goObservationCancelCallback(char *tags, char *notes,
                                         char *contentType, char *imagePath);
extern void goObservationStoreCallback(char *tags, char *notes,
                                        char *contentType, char *imagePath);

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
	g_obsTagsField = nil;
	g_obsExtraField = nil;
	g_obsTitleField = nil;
	g_obsSummaryText = nil;
	g_obsCtValue = nil;
	g_obsTabView = nil;
	g_reviewTextView = nil;
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

// Singleton handler instances for buttons (dynamically registered classes).
static id g_cancelHandler = nil;
static id g_storeHandler  = nil;

// ensureHandlerClasses registers the ObsCancelHandler and ObsStoreHandler
// classes with the ObjC runtime if they haven't been registered yet.
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

// ---------- Observation Window (Cocoa) ----------

// showObservationWindow creates and shows a native NSWindow with 3 tabs.
// imagePath may be NULL or empty to skip image display.
// meta may be NULL for default placeholder metadata in the Review tab.
// Returns 1 on success, 0 on failure.
static int showObservationWindow(const char *title, const char *imagePath, const ReviewMeta *meta, int channelType) {
	// Must run on main thread for Cocoa UI.
	dispatch_async(dispatch_get_main_queue(), ^{
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
		[imageView setImageScaling:NSImageScaleProportionallyUpOrDown];
		[imageView setImageAlignment:NSImageAlignCenter];
		[imageView setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
		[imageView setImageFrameStyle:NSImageFrameGrayBezel];

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

		// -- Stop Recording button (initially hidden, placeholder) --
		NSButton *stopBtn = [NSButton buttonWithTitle:@"🛑 Stop Recording"
											   target:nil
											   action:nil];
		[stopBtn setFrame:NSMakeRect(winW - 170, 10, 150, 30)];
		[stopBtn setAutoresizingMask:(NSViewMinXMargin | NSViewMaxYMargin)];
		[stopBtn setEnabled:NO]; // placeholder — enabled when recording starts
		[recordView addSubview:stopBtn];

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

		// Appearance.
		[textView setEditable:NO];
		[textView setSelectable:YES];
		[textView setRichText:NO];
		[textView setFont:[NSFont monospacedSystemFontOfSize:12 weight:NSFontWeightRegular]];
		[textView setString:@"Transcript will appear here after recording is processed..."];
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

		// Metadata label at top.
		NSTextField *metaLabel = [[NSTextField alloc]
			initWithFrame:NSMakeRect(10, winH - 90, winW - 20, 20)];
		[metaLabel setStringValue:@"Channel: — | Duration: — | Snippets: —"];
		[metaLabel setBezeled:NO];
		[metaLabel setDrawsBackground:NO];
		[metaLabel setEditable:NO];
		[metaLabel setSelectable:NO];
		[metaLabel setFont:[NSFont systemFontOfSize:11]];
		[metaLabel setTextColor:[NSColor secondaryLabelColor]];
		[metaLabel setAutoresizingMask:(NSViewWidthSizable | NSViewMinYMargin)];
		[reviewView addSubview:metaLabel];

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

var (
	cancelMu       sync.Mutex
	cancelCallback CancelCallback
	storeMu        sync.Mutex
	storeCallback  StoreCallback
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
//   - ChannelTypeProgress: "progress, youtube" with type "YouTube-Video-Impression"
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
// (YouTube video). Tags are pre-filled with "progress, youtube".
func ShowObservationWindowForProgress(imagePath string) bool {
	return ShowObservationWindow("Observation — YouTube", imagePath, ChannelTypeProgress)
}

// ShowObservationWindowForImpulse is a convenience wrapper for Channel C
// (Quick capture). Tags are pre-filled with "impulse".
func ShowObservationWindowForImpulse() bool {
	return ShowObservationWindow("Observation — Impulse", "", ChannelTypeImpulse)
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

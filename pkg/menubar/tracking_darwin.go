// tracking_darwin.go — Native macOS Tracking DB Window via Cocoa/cgo.
//
// Creates an NSWindow with an NSTabView containing 2 tabs:
//   - Tracked: table view of all DB records (uploaded/imported/failed)
//   - Source Files: table view of all files in IMPORT_AUDIO_SOURCE,
//     with folder path header, running number, creation date,
//     checkbox selection, sortable columns, and bulk action buttons
//
// This file must be built on macOS (darwin) with cgo enabled.
package menubar

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa

#import <Cocoa/Cocoa.h>
#include <stdlib.h>

// ---------- Global Tracking Window State ----------

static NSWindow     *g_trackWindow    = nil;
static NSTableView  *g_trackTable     = nil;  // Tab 1: tracked items
static NSTableView  *g_sourceTable    = nil;  // Tab 2: source files
static NSTextField  *g_srcFolderLabel = nil;  // Tab 2: folder path label
static NSTextField  *g_srcSelectLabel = nil;  // Tab 2: "N selected" label
static NSProgressIndicator *g_bulkProgressBar = nil;
static NSTextField  *g_bulkRunLabel    = nil;
static NSTextField  *g_bulkDetailLabel = nil;
static NSTextField  *g_bulkErrorLabel  = nil;
static NSButton     *g_btnReprocess    = nil;
static NSButton     *g_btnTxUpload     = nil;
static BOOL          g_bulkActive      = NO;
static int           g_bulkTotal       = 0;
static int           g_bulkDone        = 0;
static int           g_bulkSuccess     = 0;
static int           g_bulkFailed      = 0;

// ---------- Row Data Storage ----------

// Tab 1 (Tracked): columns = filename, status, transcript_len, doc_id, processed_at
#define TRACK_MAX_ROWS 500
#define TRACK_COLS     5

static char *g_trackData[TRACK_MAX_ROWS][TRACK_COLS];
static int   g_trackRowCount = 0;

// Tab 2 (Source): columns = num, filename, status, size, created
#define SRC_MAX_ROWS 500
#define SRC_COLS     5

static char      *g_srcData[SRC_MAX_ROWS][SRC_COLS];
static long long  g_srcSizeBytes[SRC_MAX_ROWS];   // raw bytes for numeric sort
static BOOL       g_srcSelected[SRC_MAX_ROWS];     // checkbox selection state
static int        g_srcRowCount = 0;
static int        g_srcSortOrder[SRC_MAX_ROWS];    // index mapping for sorted display

// Source folder path for header label.
static char *g_srcFolderPath = NULL;

// ---------- Helper: Store Row Data ----------

static void clearTrackData(void) {
	for (int r = 0; r < g_trackRowCount; r++) {
		for (int c = 0; c < TRACK_COLS; c++) {
			if (g_trackData[r][c]) { free(g_trackData[r][c]); g_trackData[r][c] = NULL; }
		}
	}
	g_trackRowCount = 0;
}

static void clearSrcData(void) {
	for (int r = 0; r < g_srcRowCount; r++) {
		for (int c = 0; c < SRC_COLS; c++) {
			if (g_srcData[r][c]) { free(g_srcData[r][c]); g_srcData[r][c] = NULL; }
		}
	}
	g_srcRowCount = 0;
	memset(g_srcSelected, 0, sizeof(g_srcSelected));
}

static void initSrcSortOrder(void) {
	for (int i = 0; i < g_srcRowCount; i++) {
		g_srcSortOrder[i] = i;
	}
}

static void updateSelectionLabel(void) {
	if (!g_srcSelectLabel) return;
	int count = 0;
	for (int i = 0; i < g_srcRowCount; i++) {
		if (g_srcSelected[i]) count++;
	}
	[g_srcSelectLabel setStringValue:
		[NSString stringWithFormat:@"%d selected", count]];
}

static void applyBulkControls(void) {
	BOOL active = g_bulkActive ? YES : NO;
	if (g_btnReprocess) [g_btnReprocess setEnabled:!active];
	if (g_btnTxUpload) [g_btnTxUpload setEnabled:!active];
	if (g_bulkProgressBar) {
		[g_bulkProgressBar setHidden:!active];
		if (active && g_bulkTotal > 0) {
			[g_bulkProgressBar setIndeterminate:NO];
			[g_bulkProgressBar setMinValue:0.0];
			[g_bulkProgressBar setMaxValue:(double)g_bulkTotal];
			[g_bulkProgressBar setDoubleValue:(double)g_bulkDone];
		}
	}
	if (g_bulkRunLabel) {
		if (active) {
			[g_bulkRunLabel setStringValue:
				[NSString stringWithFormat:@"Bulk run: %d/%d (ok=%d fail=%d)",
					g_bulkDone, g_bulkTotal, g_bulkSuccess, g_bulkFailed]];
		} else {
			[g_bulkRunLabel setStringValue:@"Bulk run: idle"];
		}
	}
}

static void addTrackRow(const char *filename, const char *status,
						const char *txLen, const char *docID, const char *processedAt) {
	if (g_trackRowCount >= TRACK_MAX_ROWS) return;
	int r = g_trackRowCount++;
	g_trackData[r][0] = strdup(filename    ? filename    : "");
	g_trackData[r][1] = strdup(status      ? status      : "");
	g_trackData[r][2] = strdup(txLen       ? txLen       : "");
	g_trackData[r][3] = strdup(docID       ? docID       : "");
	g_trackData[r][4] = strdup(processedAt ? processedAt : "");
}

static void addSrcRow(const char *num, const char *filename, const char *status,
					  const char *size, const char *created, long long sizeBytes) {
	if (g_srcRowCount >= SRC_MAX_ROWS) return;
	int r = g_srcRowCount++;
	g_srcData[r][0] = strdup(num      ? num      : "");
	g_srcData[r][1] = strdup(filename ? filename : "");
	g_srcData[r][2] = strdup(status   ? status   : "");
	g_srcData[r][3] = strdup(size     ? size     : "");
	g_srcData[r][4] = strdup(created  ? created  : "");
	g_srcSizeBytes[r] = sizeBytes;
	g_srcSortOrder[r] = r;
	g_srcSelected[r] = NO;
}

static void setSrcFolderPath(const char *path) {
	if (g_srcFolderPath) { free(g_srcFolderPath); g_srcFolderPath = NULL; }
	if (path) g_srcFolderPath = strdup(path);
}

static int isTrackingWindowOpen(void) {
	return (g_trackWindow != nil) ? 1 : 0;
}

// reloadTrackingTables tells the already-open window to refresh both table
// views with the current global data.  Safe to call from any thread.
static void reloadTrackingTables(void) {
	dispatch_async(dispatch_get_main_queue(), ^{
		if (g_trackWindow == nil) return;
		if (g_srcFolderLabel && g_srcFolderPath) {
			[g_srcFolderLabel setStringValue:
				[NSString stringWithFormat:@"Source: %s", g_srcFolderPath]];
		}
		initSrcSortOrder();
		if (g_sourceTable) {
			[g_sourceTable setSortDescriptors:@[]];
			[g_sourceTable reloadData];
		}
		if (g_trackTable) [g_trackTable reloadData];
		updateSelectionLabel();
		applyBulkControls();
	});
}

// ---------- Non-static accessors (called from tracking_bulk_darwin.go via extern) ----------

int trackingSrcRowCount(void) { return g_srcRowCount; }

int trackingIsSrcSelected(int row) {
	return (row >= 0 && row < g_srcRowCount && g_srcSelected[row]) ? 1 : 0;
}

const char* trackingSrcFilename(int row) {
	return (row >= 0 && row < g_srcRowCount && g_srcData[row][1])
		? g_srcData[row][1] : "";
}

const char* trackingSrcStatus(int row) {
	return (row >= 0 && row < g_srcRowCount && g_srcData[row][2])
		? g_srcData[row][2] : "";
}

static void setTrackingSrcStatusByFilename(const char *filename, const char *status) {
	if (!filename || !status) return;
	for (int i = 0; i < g_srcRowCount; i++) {
		if (!g_srcData[i][1]) continue;
		if (strcmp(g_srcData[i][1], filename) == 0) {
			free(g_srcData[i][2]);
			g_srcData[i][2] = strdup(status);
		}
	}
	dispatch_async(dispatch_get_main_queue(), ^{
		if (g_sourceTable) [g_sourceTable reloadData];
	});
}

static void setTrackingBulkState(int active,
								 const char *runText,
								 const char *detailText,
								 const char *errorText,
								 int total,
								 int done,
								 int success,
								 int failed) {
	g_bulkActive = active ? YES : NO;
	g_bulkTotal = total;
	g_bulkDone = done;
	g_bulkSuccess = success;
	g_bulkFailed = failed;
	dispatch_async(dispatch_get_main_queue(), ^{
		applyBulkControls();
		if (g_bulkDetailLabel) {
			NSString *detail = detailText ? [NSString stringWithUTF8String:detailText] : @"";
			[g_bulkDetailLabel setStringValue:detail];
		}
		if (g_bulkErrorLabel) {
			NSString *err = errorText ? [NSString stringWithUTF8String:errorText] : @"";
			[g_bulkErrorLabel setStringValue:err];
		}
		if (g_bulkRunLabel && runText) {
			[g_bulkRunLabel setStringValue:[NSString stringWithUTF8String:runText]];
		}
	});
}

// ---------- Forward declaration of Go bulk-action callback ----------

extern void goTrackingBulkAction(char* action);

// ---------- Table Data Source ----------

@interface TrackingTableDataSource : NSObject <NSTableViewDataSource, NSTableViewDelegate>
- (void)srcCheckboxClicked:(NSButton *)sender;
- (void)selectAllClicked:(id)sender;
- (void)deselectAllClicked:(id)sender;
- (void)transcribeUploadClicked:(id)sender;
- (void)reprocessClicked:(id)sender;
@end

@implementation TrackingTableDataSource

- (NSInteger)numberOfRowsInTableView:(NSTableView *)tableView {
	if (tableView == g_trackTable) return g_trackRowCount;
	if (tableView == g_sourceTable) return g_srcRowCount;
	return 0;
}

- (NSView *)tableView:(NSTableView *)tableView
   viewForTableColumn:(NSTableColumn *)tableColumn
                  row:(NSInteger)row {

	NSString *identifier = [tableColumn identifier];

	// ---------- Source table: checkbox column ----------
	if (tableView == g_sourceTable && [identifier isEqualToString:@"select"]) {
		int dataRow = g_srcSortOrder[row];
		NSButton *cb = [[NSButton alloc] initWithFrame:NSZeroRect];
		[cb setButtonType:NSButtonTypeSwitch];
		[cb setTitle:@""];
		[cb setState:g_srcSelected[dataRow] ? NSControlStateValueOn : NSControlStateValueOff];
		[cb setTarget:self];
		[cb setAction:@selector(srcCheckboxClicked:)];
		return cb;
	}

	// ---------- Default: text cell ----------
	NSTextField *cell = [[NSTextField alloc] initWithFrame:NSZeroRect];
	[cell setBezeled:NO];
	[cell setDrawsBackground:NO];
	[cell setEditable:NO];
	[cell setSelectable:YES];
	[cell setLineBreakMode:NSLineBreakByTruncatingTail];

	NSString *value = @"";

	if (tableView == g_trackTable && row < g_trackRowCount) {
		int col = -1;
		if ([identifier isEqualToString:@"filename"])    col = 0;
		else if ([identifier isEqualToString:@"status"]) col = 1;
		else if ([identifier isEqualToString:@"txlen"])   col = 2;
		else if ([identifier isEqualToString:@"docid"])   col = 3;
		else if ([identifier isEqualToString:@"date"])    col = 4;
		if (col >= 0 && g_trackData[row][col]) {
			value = [NSString stringWithUTF8String:g_trackData[row][col]];
		}

		// Color by status
		if (g_trackData[row][1]) {
			NSString *st = [NSString stringWithUTF8String:g_trackData[row][1]];
			if ([st isEqualToString:@"uploaded"]) {
				[cell setTextColor:[NSColor systemGreenColor]];
			} else if ([st isEqualToString:@"failed"]) {
				[cell setTextColor:[NSColor systemRedColor]];
			}
		}
	}
	else if (tableView == g_sourceTable && row < g_srcRowCount) {
		int dataRow = g_srcSortOrder[row];
		int col = -1;
		if ([identifier isEqualToString:@"num"])           col = 0;
		else if ([identifier isEqualToString:@"filename"]) col = 1;
		else if ([identifier isEqualToString:@"status"])   col = 2;
		else if ([identifier isEqualToString:@"size"])     col = 3;
		else if ([identifier isEqualToString:@"created"])  col = 4;
		if (col >= 0 && g_srcData[dataRow][col]) {
			value = [NSString stringWithUTF8String:g_srcData[dataRow][col]];
		}

		// Right-align # and Size columns.
		if (col == 0 || col == 3) {
			[cell setAlignment:NSTextAlignmentRight];
		}

		// Color: green=uploaded, blue=new
		if (g_srcData[dataRow][2]) {
			NSString *st = [NSString stringWithUTF8String:g_srcData[dataRow][2]];
			if ([st isEqualToString:@"uploaded"] || [st isEqualToString:@"done"]) {
				[cell setTextColor:[NSColor systemGreenColor]];
			} else if ([st isEqualToString:@"failed"]) {
				[cell setTextColor:[NSColor systemRedColor]];
			} else if ([st isEqualToString:@"queued"] ||
					   [st isEqualToString:@"importing"] ||
					   [st isEqualToString:@"transcribing"] ||
					   [st isEqualToString:@"uploading"] ||
					   [st isEqualToString:@"reprocessing"] ||
					   [st isEqualToString:@"processing"]) {
				[cell setTextColor:[NSColor systemOrangeColor]];
			} else {
				[cell setTextColor:[NSColor systemBlueColor]];
			}
		}
	}

	[cell setStringValue:value];
	[cell setFont:[NSFont systemFontOfSize:12]];
	return cell;
}

- (CGFloat)tableView:(NSTableView *)tableView heightOfRow:(NSInteger)row {
	return 22.0;
}

// ---------- Checkbox handling ----------

- (void)srcCheckboxClicked:(NSButton *)sender {
	NSInteger displayRow = [g_sourceTable rowForView:sender];
	if (displayRow >= 0 && displayRow < g_srcRowCount) {
		int dataRow = g_srcSortOrder[displayRow];
		g_srcSelected[dataRow] = (sender.state == NSControlStateValueOn);
		updateSelectionLabel();
	}
}

- (void)selectAllClicked:(id)sender {
	for (int i = 0; i < g_srcRowCount; i++) g_srcSelected[i] = YES;
	updateSelectionLabel();
	[g_sourceTable reloadData];
}

- (void)deselectAllClicked:(id)sender {
	memset(g_srcSelected, 0, sizeof(g_srcSelected));
	updateSelectionLabel();
	[g_sourceTable reloadData];
}

// ---------- Bulk action buttons ----------

- (void)transcribeUploadClicked:(id)sender {
	if (g_bulkActive) return;
	goTrackingBulkAction("transcribe_upload");
}

- (void)reprocessClicked:(id)sender {
	if (g_bulkActive) return;
	goTrackingBulkAction("retranscribe_reupload");
}

// ---------- Sorting for Source Files Table ----------

- (void)tableView:(NSTableView *)tableView sortDescriptorsDidChange:(NSArray<NSSortDescriptor *> *)oldDescriptors {
	if (tableView != g_sourceTable) return;

	NSSortDescriptor *sd = [[tableView sortDescriptors] firstObject];
	if (!sd || g_srcRowCount == 0) {
		initSrcSortOrder();
		[tableView reloadData];
		return;
	}

	NSString *key = [sd key];
	BOOL ascending = [sd ascending];

	int sortCol = -1;
	BOOL numericCol = NO;
	BOOL sizeCol = NO;

	if ([key isEqualToString:@"num"])           { sortCol = 0; numericCol = YES; }
	else if ([key isEqualToString:@"filename"]) { sortCol = 1; }
	else if ([key isEqualToString:@"status"])   { sortCol = 2; }
	else if ([key isEqualToString:@"size"])     { sizeCol = YES; }
	else if ([key isEqualToString:@"created"])  { sortCol = 4; }

	initSrcSortOrder();

	qsort_b(g_srcSortOrder, g_srcRowCount, sizeof(int), ^int(const void *a, const void *b) {
		int ia = *(const int *)a;
		int ib = *(const int *)b;
		int cmp = 0;

		if (sizeCol) {
			if (g_srcSizeBytes[ia] < g_srcSizeBytes[ib]) cmp = -1;
			else if (g_srcSizeBytes[ia] > g_srcSizeBytes[ib]) cmp = 1;
		} else if (numericCol) {
			int va = atoi(g_srcData[ia][sortCol] ? g_srcData[ia][sortCol] : "0");
			int vb = atoi(g_srcData[ib][sortCol] ? g_srcData[ib][sortCol] : "0");
			cmp = va - vb;
		} else if (sortCol >= 0) {
			const char *sa = g_srcData[ia][sortCol] ? g_srcData[ia][sortCol] : "";
			const char *sb = g_srcData[ib][sortCol] ? g_srcData[ib][sortCol] : "";
			cmp = strcmp(sa, sb);
		}

		return ascending ? cmp : -cmp;
	});

	[tableView reloadData];
}

@end

// Global data source instance (retained by tables).
static TrackingTableDataSource *g_trackDS = nil;

// ---------- Window Creation ----------

static void showTrackingWindow(void) {
	dispatch_sync(dispatch_get_main_queue(), ^{
		// If already open, just bring to front.
		if (g_trackWindow != nil) {
			[g_trackWindow makeKeyAndOrderFront:nil];
			[NSApp activateIgnoringOtherApps:YES];
			if (g_srcFolderLabel && g_srcFolderPath) {
				[g_srcFolderLabel setStringValue:
					[NSString stringWithFormat:@"Source: %s", g_srcFolderPath]];
			}
			initSrcSortOrder();
			if (g_sourceTable) {
				[g_sourceTable setSortDescriptors:@[]];
				[g_sourceTable reloadData];
			}
			if (g_trackTable) [g_trackTable reloadData];
			updateSelectionLabel();
			applyBulkControls();
			return;
		}

		// ---- Window ----
		NSScreen *screen = [NSScreen mainScreen];
		NSRect sf = [screen visibleFrame];
		CGFloat winW = sf.size.width * 0.55;
		CGFloat winH = sf.size.height * 0.6;
		if (winW < 800) winW = 800;
		if (winH < 450) winH = 450;

		NSRect winRect = NSMakeRect(
			sf.origin.x + (sf.size.width  - winW) / 2,
			sf.origin.y + (sf.size.height - winH) / 2,
			winW, winH);

		NSWindow *window = [[NSWindow alloc]
			initWithContentRect:winRect
			styleMask:(NSWindowStyleMaskTitled |
					   NSWindowStyleMaskClosable |
					   NSWindowStyleMaskResizable |
					   NSWindowStyleMaskMiniaturizable)
			backing:NSBackingStoreBuffered
			defer:NO];

		[window setTitle:@"Tracking DB"];
		[window setReleasedWhenClosed:NO];
		[window setHidesOnDeactivate:NO];
		g_trackWindow = window;

		[NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];

		if (g_trackDS == nil) {
			g_trackDS = [[TrackingTableDataSource alloc] init];
		}

		// ---- Tab View ----
		NSTabView *tabView = [[NSTabView alloc] initWithFrame:
			NSMakeRect(0, 0, winW, winH)];
		[tabView setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];

		// ======== Tab 1: Tracked ========
		NSTabViewItem *tab1 = [[NSTabViewItem alloc] initWithIdentifier:@"tracked"];
		[tab1 setLabel:@"Tracked"];

		NSView *tab1View = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, winW, winH - 60)];
		[tab1View setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];

		NSScrollView *scroll1 = [[NSScrollView alloc] initWithFrame:
			NSMakeRect(10, 10, winW - 20, winH - 80)];
		[scroll1 setHasVerticalScroller:YES];
		[scroll1 setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
		[scroll1 setBorderType:NSBezelBorder];

		NSTableView *table1 = [[NSTableView alloc] initWithFrame:NSZeroRect];
		[table1 setUsesAlternatingRowBackgroundColors:YES];
		[table1 setGridStyleMask:NSTableViewSolidVerticalGridLineMask];
		g_trackTable = table1;

		NSTableColumn *tc1a = [[NSTableColumn alloc] initWithIdentifier:@"filename"];
		[tc1a setTitle:@"File"]; [tc1a setWidth:280]; [tc1a setMinWidth:150];
		[table1 addTableColumn:tc1a];

		NSTableColumn *tc1b = [[NSTableColumn alloc] initWithIdentifier:@"status"];
		[tc1b setTitle:@"Status"]; [tc1b setWidth:80];
		[table1 addTableColumn:tc1b];

		NSTableColumn *tc1c = [[NSTableColumn alloc] initWithIdentifier:@"txlen"];
		[tc1c setTitle:@"Transcript"]; [tc1c setWidth:80];
		[table1 addTableColumn:tc1c];

		NSTableColumn *tc1d = [[NSTableColumn alloc] initWithIdentifier:@"docid"];
		[tc1d setTitle:@"Doc ID"]; [tc1d setWidth:160];
		[table1 addTableColumn:tc1d];

		NSTableColumn *tc1e = [[NSTableColumn alloc] initWithIdentifier:@"date"];
		[tc1e setTitle:@"Date"]; [tc1e setWidth:120];
		[table1 addTableColumn:tc1e];

		[table1 setDataSource:g_trackDS];
		[table1 setDelegate:g_trackDS];
		[scroll1 setDocumentView:table1];
		[tab1View addSubview:scroll1];
		[tab1 setView:tab1View];
		[tabView addTabViewItem:tab1];

		// ======== Tab 2: Source Files ========
		NSTabViewItem *tab2 = [[NSTabViewItem alloc] initWithIdentifier:@"source"];
		[tab2 setLabel:@"Source Files"];

		CGFloat tabContentH = winH - 60;
		NSView *tab2View = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, winW, tabContentH)];
		[tab2View setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];

		// -- Folder path label at top --
		NSTextField *folderLabel = [[NSTextField alloc] initWithFrame:
			NSMakeRect(10, tabContentH - 30, winW - 20, 20)];
		[folderLabel setBezeled:NO];
		[folderLabel setDrawsBackground:NO];
		[folderLabel setEditable:NO];
		[folderLabel setSelectable:YES];
		[folderLabel setFont:[NSFont systemFontOfSize:11]];
		[folderLabel setTextColor:[NSColor secondaryLabelColor]];
		[folderLabel setLineBreakMode:NSLineBreakByTruncatingMiddle];
		[folderLabel setAutoresizingMask:(NSViewWidthSizable | NSViewMinYMargin)];
		if (g_srcFolderPath) {
			[folderLabel setStringValue:
				[NSString stringWithFormat:@"Source: %s", g_srcFolderPath]];
		} else {
			[folderLabel setStringValue:@"Source: (not configured)"];
		}
		g_srcFolderLabel = folderLabel;
		[tab2View addSubview:folderLabel];

		// -- Bulk progress strip --
		NSProgressIndicator *bulkBar = [[NSProgressIndicator alloc] initWithFrame:
			NSMakeRect(10, tabContentH - 54, winW - 20, 12)];
		[bulkBar setStyle:NSProgressIndicatorStyleBar];
		[bulkBar setIndeterminate:NO];
		[bulkBar setMinValue:0.0];
		[bulkBar setMaxValue:100.0];
		[bulkBar setDoubleValue:0.0];
		[bulkBar setHidden:YES];
		[bulkBar setAutoresizingMask:(NSViewWidthSizable | NSViewMinYMargin)];
		g_bulkProgressBar = bulkBar;
		[tab2View addSubview:bulkBar];

		NSTextField *bulkRunLabel = [[NSTextField alloc] initWithFrame:
			NSMakeRect(10, tabContentH - 72, winW - 20, 16)];
		[bulkRunLabel setBezeled:NO];
		[bulkRunLabel setDrawsBackground:NO];
		[bulkRunLabel setEditable:NO];
		[bulkRunLabel setFont:[NSFont systemFontOfSize:11]];
		[bulkRunLabel setTextColor:[NSColor secondaryLabelColor]];
		[bulkRunLabel setStringValue:@"Bulk run: idle"];
		[bulkRunLabel setAutoresizingMask:(NSViewWidthSizable | NSViewMinYMargin)];
		g_bulkRunLabel = bulkRunLabel;
		[tab2View addSubview:bulkRunLabel];

		NSTextField *bulkDetailLabel = [[NSTextField alloc] initWithFrame:
			NSMakeRect(10, tabContentH - 90, winW - 20, 16)];
		[bulkDetailLabel setBezeled:NO];
		[bulkDetailLabel setDrawsBackground:NO];
		[bulkDetailLabel setEditable:NO];
		[bulkDetailLabel setFont:[NSFont systemFontOfSize:11]];
		[bulkDetailLabel setTextColor:[NSColor secondaryLabelColor]];
		[bulkDetailLabel setStringValue:@""];
		[bulkDetailLabel setAutoresizingMask:(NSViewWidthSizable | NSViewMinYMargin)];
		g_bulkDetailLabel = bulkDetailLabel;
		[tab2View addSubview:bulkDetailLabel];

		NSTextField *bulkErrorLabel = [[NSTextField alloc] initWithFrame:
			NSMakeRect(10, tabContentH - 108, winW - 20, 16)];
		[bulkErrorLabel setBezeled:NO];
		[bulkErrorLabel setDrawsBackground:NO];
		[bulkErrorLabel setEditable:NO];
		[bulkErrorLabel setFont:[NSFont systemFontOfSize:11]];
		[bulkErrorLabel setTextColor:[NSColor systemRedColor]];
		[bulkErrorLabel setStringValue:@""];
		[bulkErrorLabel setAutoresizingMask:(NSViewWidthSizable | NSViewMinYMargin)];
		g_bulkErrorLabel = bulkErrorLabel;
		[tab2View addSubview:bulkErrorLabel];

		// -- Button bar at bottom --
		CGFloat btnY = 10;
		CGFloat btnH = 28;

		NSButton *btnAll = [[NSButton alloc] initWithFrame:NSMakeRect(10, btnY, 40, btnH)];
		[btnAll setTitle:@"All"];
		[btnAll setBezelStyle:NSBezelStyleRounded];
		[btnAll setTarget:g_trackDS];
		[btnAll setAction:@selector(selectAllClicked:)];
		[btnAll setAutoresizingMask:NSViewMaxXMargin];
		[tab2View addSubview:btnAll];

		NSButton *btnNone = [[NSButton alloc] initWithFrame:NSMakeRect(55, btnY, 55, btnH)];
		[btnNone setTitle:@"None"];
		[btnNone setBezelStyle:NSBezelStyleRounded];
		[btnNone setTarget:g_trackDS];
		[btnNone setAction:@selector(deselectAllClicked:)];
		[btnNone setAutoresizingMask:NSViewMaxXMargin];
		[tab2View addSubview:btnNone];

		NSTextField *selLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(120, btnY + 4, 100, 20)];
		[selLabel setBezeled:NO];
		[selLabel setDrawsBackground:NO];
		[selLabel setEditable:NO];
		[selLabel setFont:[NSFont systemFontOfSize:11]];
		[selLabel setTextColor:[NSColor secondaryLabelColor]];
		[selLabel setStringValue:@"0 selected"];
		[selLabel setAutoresizingMask:NSViewMaxXMargin];
		g_srcSelectLabel = selLabel;
		[tab2View addSubview:selLabel];

		NSButton *btnReprocess = [[NSButton alloc] initWithFrame:
			NSMakeRect(winW - 185, btnY, 175, btnH)];
		[btnReprocess setTitle:@"Re-process Selected"];
		[btnReprocess setBezelStyle:NSBezelStyleRounded];
		[btnReprocess setTarget:g_trackDS];
		[btnReprocess setAction:@selector(reprocessClicked:)];
		[btnReprocess setAutoresizingMask:NSViewMinXMargin];
		g_btnReprocess = btnReprocess;
		[tab2View addSubview:btnReprocess];

		NSButton *btnTxUpload = [[NSButton alloc] initWithFrame:
			NSMakeRect(winW - 380, btnY, 185, btnH)];
		[btnTxUpload setTitle:@"Transcribe + Upload"];
		[btnTxUpload setBezelStyle:NSBezelStyleRounded];
		[btnTxUpload setTarget:g_trackDS];
		[btnTxUpload setAction:@selector(transcribeUploadClicked:)];
		[btnTxUpload setAutoresizingMask:NSViewMinXMargin];
		g_btnTxUpload = btnTxUpload;
		[tab2View addSubview:btnTxUpload];

		// -- Scroll view between label and buttons --
		NSScrollView *scroll2 = [[NSScrollView alloc] initWithFrame:
			NSMakeRect(10, btnY + btnH + 6, winW - 20, tabContentH - 112 - btnH - 20)];
		[scroll2 setHasVerticalScroller:YES];
		[scroll2 setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
		[scroll2 setBorderType:NSBezelBorder];

		NSTableView *table2 = [[NSTableView alloc] initWithFrame:NSZeroRect];
		[table2 setUsesAlternatingRowBackgroundColors:YES];
		[table2 setGridStyleMask:NSTableViewSolidVerticalGridLineMask];
		g_sourceTable = table2;

		// Columns: Select, #, File, Status, Size, Created
		NSTableColumn *tc2sel = [[NSTableColumn alloc] initWithIdentifier:@"select"];
		[tc2sel setTitle:@""];
		[tc2sel setWidth:28];
		[tc2sel setMinWidth:28];
		[tc2sel setMaxWidth:28];
		[table2 addTableColumn:tc2sel];

		NSTableColumn *tc2num = [[NSTableColumn alloc] initWithIdentifier:@"num"];
		[tc2num setTitle:@"#"];
		[tc2num setWidth:40];
		[tc2num setMinWidth:30];
		[tc2num setSortDescriptorPrototype:
			[[NSSortDescriptor alloc] initWithKey:@"num" ascending:YES]];
		[table2 addTableColumn:tc2num];

		NSTableColumn *tc2a = [[NSTableColumn alloc] initWithIdentifier:@"filename"];
		[tc2a setTitle:@"File"];
		[tc2a setWidth:260];
		[tc2a setMinWidth:150];
		[tc2a setSortDescriptorPrototype:
			[[NSSortDescriptor alloc] initWithKey:@"filename" ascending:YES]];
		[table2 addTableColumn:tc2a];

		NSTableColumn *tc2b = [[NSTableColumn alloc] initWithIdentifier:@"status"];
		[tc2b setTitle:@"Status"];
		[tc2b setWidth:80];
		[tc2b setSortDescriptorPrototype:
			[[NSSortDescriptor alloc] initWithKey:@"status" ascending:YES]];
		[table2 addTableColumn:tc2b];

		NSTableColumn *tc2c = [[NSTableColumn alloc] initWithIdentifier:@"size"];
		[tc2c setTitle:@"Size"];
		[tc2c setWidth:80];
		[tc2c setSortDescriptorPrototype:
			[[NSSortDescriptor alloc] initWithKey:@"size" ascending:YES]];
		[table2 addTableColumn:tc2c];

		NSTableColumn *tc2d = [[NSTableColumn alloc] initWithIdentifier:@"created"];
		[tc2d setTitle:@"Created"];
		[tc2d setWidth:140];
		[tc2d setSortDescriptorPrototype:
			[[NSSortDescriptor alloc] initWithKey:@"created" ascending:YES]];
		[table2 addTableColumn:tc2d];

		[table2 setDataSource:g_trackDS];
		[table2 setDelegate:g_trackDS];
		[scroll2 setDocumentView:table2];
		[tab2View addSubview:scroll2];
		[tab2 setView:tab2View];
		[tabView addTabViewItem:tab2];

		// ---- Finalize ----
		[[window contentView] addSubview:tabView];
		[table1 reloadData];
		[table2 reloadData];
		updateSelectionLabel();
		applyBulkControls();
		[window makeKeyAndOrderFront:nil];
		[NSApp activateIgnoringOtherApps:YES];
	});
}

static void closeTrackingWindow(void) {
	dispatch_async(dispatch_get_main_queue(), ^{
		if (g_trackWindow != nil) {
			[g_trackWindow close];
			g_trackWindow = nil;
		}
		g_trackTable = nil;
		g_sourceTable = nil;
		g_srcFolderLabel = nil;
		g_srcSelectLabel = nil;
		g_bulkProgressBar = nil;
		g_bulkRunLabel = nil;
		g_bulkDetailLabel = nil;
		g_bulkErrorLabel = nil;
		g_btnReprocess = nil;
		g_btnTxUpload = nil;
		clearTrackData();
		clearSrcData();
		if (g_srcFolderPath) { free(g_srcFolderPath); g_srcFolderPath = NULL; }
		[NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
	});
}

*/
import "C"
import (
	"fmt"
	"unsafe"
)

// ShowTrackingWindow opens (or brings to front) the Tracking DB window.
// trackedRows populates Tab 1, sourceRows populates Tab 2.
// folderPath is displayed as a header label above the source files table.
func ShowTrackingWindow(tracked []TrackingRecord, source []SourceFileRecord, folderPath string) {
	C.clearTrackData()
	C.clearSrcData()

	cPath := C.CString(folderPath)
	C.setSrcFolderPath(cPath)
	C.free(unsafe.Pointer(cPath))

	for _, r := range tracked {
		cFile := C.CString(r.FileName)
		cStatus := C.CString(r.Status)
		cTxLen := C.CString(fmt.Sprintf("%d chars", r.TranscriptLen))
		cDocID := C.CString(r.UploadDocID)
		cDate := C.CString(r.ProcessedAt)
		C.addTrackRow(cFile, cStatus, cTxLen, cDocID, cDate)
		C.free(unsafe.Pointer(cFile))
		C.free(unsafe.Pointer(cStatus))
		C.free(unsafe.Pointer(cTxLen))
		C.free(unsafe.Pointer(cDocID))
		C.free(unsafe.Pointer(cDate))
	}

	for i, r := range source {
		cNum := C.CString(fmt.Sprintf("%d", i+1))
		cFile := C.CString(r.FileName)
		cStatus := C.CString(r.Status)
		cSize := C.CString(r.Size)
		cCreated := C.CString(r.CreatedAt)
		C.addSrcRow(cNum, cFile, cStatus, cSize, cCreated, C.longlong(r.SizeBytes))
		C.free(unsafe.Pointer(cNum))
		C.free(unsafe.Pointer(cFile))
		C.free(unsafe.Pointer(cStatus))
		C.free(unsafe.Pointer(cSize))
		C.free(unsafe.Pointer(cCreated))
	}

	if C.isTrackingWindowOpen() != 0 {
		// Window exists — just reload tables with the new data.
		C.reloadTrackingTables()
	} else {
		// First open — create the window (includes initial reloadData).
		C.showTrackingWindow()
	}
}

// SourceFileRecord represents a file in the source folder for Tab 2 display.
type SourceFileRecord struct {
	FileName  string
	Status    string // "uploaded", "imported", "new"
	Size      string // human-readable size
	SizeBytes int64  // raw bytes for numeric sorting
	CreatedAt string // "YYYY-MM-DD HH:MM" file creation date
}

// SetTrackingSourceStatus updates the Source Files tab row status by filename.
func SetTrackingSourceStatus(fileName, status string) {
	cFile := C.CString(fileName)
	cStatus := C.CString(status)
	C.setTrackingSrcStatusByFilename(cFile, cStatus)
	C.free(unsafe.Pointer(cFile))
	C.free(unsafe.Pointer(cStatus))
}

// SetTrackingBulkProgress updates the bulk progress strip and button enabled-state.
func SetTrackingBulkProgress(state BulkRunState) {
	active := 0
	if state.Active {
		active = 1
	}
	runText := "Bulk run: idle"
	detail := ""
	errText := ""
	if state.Active {
		runText = fmt.Sprintf("Bulk run: %d/%d (ok=%d fail=%d)", state.Done, state.Total, state.Success, state.Failed)
		if state.CurrentFile != "" {
			detail = fmt.Sprintf("%s [%s]", state.CurrentFile, state.Phase)
		} else if state.Phase != "" {
			detail = fmt.Sprintf("phase: %s", state.Phase)
		}
	}
	if state.LastError != "" {
		errText = "Last error: " + state.LastError
	}

	cRun := C.CString(runText)
	cDetail := C.CString(detail)
	cErr := C.CString(errText)
	C.setTrackingBulkState(C.int(active), cRun, cDetail, cErr,
		C.int(state.Total), C.int(state.Done), C.int(state.Success), C.int(state.Failed))
	C.free(unsafe.Pointer(cRun))
	C.free(unsafe.Pointer(cDetail))
	C.free(unsafe.Pointer(cErr))
}

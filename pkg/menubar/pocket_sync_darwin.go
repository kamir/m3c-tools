// pocket_sync_darwin.go — Native macOS Pocket Sync Window via Cocoa/cgo (SPEC-0119).
//
// Creates an NSWindow with an NSTableView showing Pocket recordings with
// checkboxes, "Group Selected", "Sync Selected" buttons, and a tags field.
// Follows the plaud_sync_darwin.go pattern exactly.
package menubar

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa

#import <Cocoa/Cocoa.h>
#include <stdlib.h>

// ---------- Global Pocket Sync Window State ----------

static NSWindow     *g_pocketWindow    = nil;
static NSTableView  *g_pocketTable     = nil;
static NSTextField  *g_pocketStatusLabel = nil;
static NSTextField  *g_pocketSelectLabel = nil;
static NSProgressIndicator *g_pocketProgressBar = nil;
static NSTextField  *g_pocketDeviceLabel = nil;
static NSButton     *g_btnPocketSync   = nil;
static NSButton     *g_btnPocketGroup  = nil;
static NSTextField  *g_pocketTagsField = nil;
static BOOL          g_pocketBulkActive = NO;

// ---------- Row Data Storage ----------

#define POCKET_MAX_ROWS 500
#define POCKET_COLS     7

// Columns: num, date, time, duration, size, status, filepath
static char *g_pocketData[POCKET_MAX_ROWS][POCKET_COLS];
static BOOL  g_pocketSelected[POCKET_MAX_ROWS];
static BOOL  g_pocketIsGroup[POCKET_MAX_ROWS];    // true = group header row
static BOOL  g_pocketIsChild[POCKET_MAX_ROWS];    // true = child of a group
static BOOL  g_pocketVisible[POCKET_MAX_ROWS];    // false = hidden (collapsed child)
static int   g_pocketGroupParent[POCKET_MAX_ROWS]; // index of parent group row (-1 = none)
static int   g_pocketRowCount = 0;
static int   g_pocketVisibleCount = 0;             // cached count of visible rows

// Map visible index → actual data index
static int g_pocketVisibleMap[POCKET_MAX_ROWS];

static char *g_pocketFilePaths[POCKET_MAX_ROWS];

// ---------- Helpers ----------

static void rebuildVisibleMap(void) {
	g_pocketVisibleCount = 0;
	for (int i = 0; i < g_pocketRowCount; i++) {
		if (g_pocketVisible[i]) {
			g_pocketVisibleMap[g_pocketVisibleCount++] = i;
		}
	}
}

static void clearPocketData(void) {
	for (int r = 0; r < g_pocketRowCount; r++) {
		for (int c = 0; c < POCKET_COLS; c++) {
			if (g_pocketData[r][c]) { free(g_pocketData[r][c]); g_pocketData[r][c] = NULL; }
		}
		if (g_pocketFilePaths[r]) { free(g_pocketFilePaths[r]); g_pocketFilePaths[r] = NULL; }
	}
	g_pocketRowCount = 0;
	g_pocketVisibleCount = 0;
	memset(g_pocketSelected, 0, sizeof(g_pocketSelected));
	memset(g_pocketIsGroup, 0, sizeof(g_pocketIsGroup));
	memset(g_pocketIsChild, 0, sizeof(g_pocketIsChild));
	memset(g_pocketVisible, 0, sizeof(g_pocketVisible));
	memset(g_pocketGroupParent, -1, sizeof(g_pocketGroupParent));
}

static void addPocketRow(const char *num, const char *date, const char *time_str,
                         const char *duration, const char *size,
                         const char *status, const char *filePath) {
	if (g_pocketRowCount >= POCKET_MAX_ROWS) return;
	int r = g_pocketRowCount++;
	g_pocketData[r][0] = strdup(num      ? num      : "");
	g_pocketData[r][1] = strdup(date     ? date     : "");
	g_pocketData[r][2] = strdup(time_str ? time_str : "");
	g_pocketData[r][3] = strdup(duration ? duration : "");
	g_pocketData[r][4] = strdup(size     ? size     : "");
	g_pocketData[r][5] = strdup(status   ? status   : "");
	g_pocketFilePaths[r] = strdup(filePath ? filePath : "");
	g_pocketSelected[r] = NO;
	g_pocketIsGroup[r] = NO;
	g_pocketIsChild[r] = NO;
	g_pocketVisible[r] = YES;
	g_pocketGroupParent[r] = -1;
}

// addPocketGroupRow inserts a group header row. Children are hidden by default.
static void addPocketGroupRow(const char *title, const char *duration,
                              const char *size, const char *status, const char *docID, int childCount) {
	if (g_pocketRowCount >= POCKET_MAX_ROWS) return;
	int r = g_pocketRowCount++;
	char segLabel[32];
	snprintf(segLabel, sizeof(segLabel), "[%d segments]", childCount);
	g_pocketData[r][0] = strdup("GROUP");
	g_pocketData[r][1] = strdup(title    ? title    : "");
	g_pocketData[r][2] = strdup("");
	g_pocketData[r][3] = strdup(duration ? duration : "");
	g_pocketData[r][4] = strdup(size     ? size     : "");
	g_pocketData[r][5] = strdup(status   ? status   : "");
	g_pocketFilePaths[r] = strdup(docID ? docID : "");
	g_pocketSelected[r] = NO;
	g_pocketIsGroup[r] = YES;
	g_pocketIsChild[r] = NO;
	g_pocketVisible[r] = YES;
	g_pocketGroupParent[r] = -1;
}

// markChildRow marks a row as a child of the given group row (hidden by default).
static void markChildRow(int childRow, int groupRow) {
	if (childRow < 0 || childRow >= g_pocketRowCount) return;
	g_pocketIsChild[childRow] = YES;
	g_pocketVisible[childRow] = NO;
	g_pocketGroupParent[childRow] = groupRow;
}

// toggleGroupExpand shows/hides children of a group row.
static void toggleGroupExpand(int groupRow) {
	if (groupRow < 0 || groupRow >= g_pocketRowCount || !g_pocketIsGroup[groupRow]) return;
	// Check if currently expanded (any child visible)
	BOOL expanded = NO;
	for (int i = 0; i < g_pocketRowCount; i++) {
		if (g_pocketGroupParent[i] == groupRow && g_pocketVisible[i]) {
			expanded = YES;
			break;
		}
	}
	// Toggle
	for (int i = 0; i < g_pocketRowCount; i++) {
		if (g_pocketGroupParent[i] == groupRow) {
			g_pocketVisible[i] = expanded ? NO : YES;
		}
	}
	rebuildVisibleMap();
}

static void updatePocketSelectionLabel(void) {
	if (!g_pocketSelectLabel) return;
	int count = 0;
	for (int i = 0; i < g_pocketRowCount; i++) {
		if (g_pocketSelected[i]) count++;
	}
	[g_pocketSelectLabel setStringValue:
		[NSString stringWithFormat:@"%d selected", count]];
	// Enable/disable group button (need 2+ selected)
	if (g_btnPocketGroup) [g_btnPocketGroup setEnabled:(count >= 2 && !g_pocketBulkActive)];
}

static void setPocketBulkControls(void) {
	BOOL active = g_pocketBulkActive;
	if (g_btnPocketSync) [g_btnPocketSync setEnabled:!active];
	if (g_btnPocketGroup) [g_btnPocketGroup setEnabled:!active];
	if (g_pocketProgressBar) {
		[g_pocketProgressBar setHidden:!active];
	}
}

static int isPocketSyncWindowOpen(void) {
	return (g_pocketWindow != nil) ? 1 : 0;
}

static void reloadPocketTable(void) {
	rebuildVisibleMap();
	dispatch_async(dispatch_get_main_queue(), ^{
		if (g_pocketWindow == nil) return;
		if (g_pocketTable) [g_pocketTable reloadData];
		updatePocketSelectionLabel();
		setPocketBulkControls();
	});
}

static char *g_pocketLastStatusURL = NULL;

static void setPocketStatusText(const char *text) {
	char *textCopy = (text && text[0]) ? strdup(text) : NULL;
	// Track if the status contains a URL (for copy button)
	if (textCopy && strstr(textCopy, "http")) {
		if (g_pocketLastStatusURL) free(g_pocketLastStatusURL);
		// Extract URL: find "http" and take until end or space
		const char *urlStart = strstr(textCopy, "http");
		if (urlStart) {
			g_pocketLastStatusURL = strdup(urlStart);
			// Trim trailing spaces
			char *end = g_pocketLastStatusURL + strlen(g_pocketLastStatusURL) - 1;
			while (end > g_pocketLastStatusURL && (*end == ' ' || *end == '\n')) { *end = '\0'; end--; }
		}
	}
	dispatch_async(dispatch_get_main_queue(), ^{
		if (g_pocketStatusLabel && textCopy) {
			NSString *str = [NSString stringWithUTF8String:textCopy];
			if (str) [g_pocketStatusLabel setStringValue:str];
			free(textCopy);
		}
	});
}

static void copyPocketStatusURL(void) {
	if (!g_pocketLastStatusURL) return;
	dispatch_async(dispatch_get_main_queue(), ^{
		NSString *url = [NSString stringWithUTF8String:g_pocketLastStatusURL];
		if (url) {
			NSPasteboard *pb = [NSPasteboard generalPasteboard];
			[pb clearContents];
			[pb setString:url forType:NSPasteboardTypeString];
			if (g_pocketStatusLabel) {
				[g_pocketStatusLabel setStringValue:@"URL copied to clipboard!"];
				dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2*NSEC_PER_SEC), dispatch_get_main_queue(), ^{
					if (g_pocketStatusLabel && g_pocketLastStatusURL) {
						NSString *orig = [NSString stringWithUTF8String:g_pocketLastStatusURL];
						if (orig) [g_pocketStatusLabel setStringValue:[NSString stringWithFormat:@"Done! View: %@", orig]];
					}
				});
			}
		}
	});
}

static void setPocketRowStatus(const char *filePath, const char *status) {
	if (!filePath || !status) return;
	for (int i = 0; i < g_pocketRowCount; i++) {
		if (!g_pocketFilePaths[i]) continue;
		if (strcmp(g_pocketFilePaths[i], filePath) == 0) {
			free(g_pocketData[i][5]);
			g_pocketData[i][5] = strdup(status);
			break;
		}
	}
	reloadPocketTable();
}

static void setPocketProgressState(int active, int total, int done, int success, int failed) {
	g_pocketBulkActive = active ? YES : NO;
	dispatch_async(dispatch_get_main_queue(), ^{
		setPocketBulkControls();
		if (g_pocketProgressBar && active && total > 0) {
			[g_pocketProgressBar setIndeterminate:NO];
			[g_pocketProgressBar setMinValue:0.0];
			[g_pocketProgressBar setMaxValue:(double)total];
			[g_pocketProgressBar setDoubleValue:(double)done];
		}
		if (g_pocketStatusLabel) {
			NSString *text;
			if (active) {
				text = [NSString stringWithFormat:@"Syncing %d/%d (ok=%d fail=%d)",
						done, total, success, failed];
			} else if (done > 0) {
				text = [NSString stringWithFormat:@"Done: %d synced, %d failed",
						success, failed];
			} else {
				text = @"Ready";
			}
			[g_pocketStatusLabel setStringValue:text];
		}
	});
}

// ---------- Non-static accessors (for callback file) ----------

int pocketSyncRowCount(void) { return g_pocketRowCount; }

int pocketSyncIsSelected(int row) {
	return (row >= 0 && row < g_pocketRowCount && g_pocketSelected[row]) ? 1 : 0;
}

const char* pocketSyncFilePath(int row) {
	return (row >= 0 && row < g_pocketRowCount && g_pocketFilePaths[row])
		? g_pocketFilePaths[row] : "";
}

static void setPocketDefaultTags(const char *tags) {
	char *tagsCopy = tags ? strdup(tags) : NULL;
	dispatch_async(dispatch_get_main_queue(), ^{
		if (g_pocketTagsField && tagsCopy) {
			NSString *str = [NSString stringWithUTF8String:tagsCopy];
			if (str) [g_pocketTagsField setStringValue:str];
			free(tagsCopy);
		}
	});
}

const char* getPocketCustomTags(void) {
	if (!g_pocketTagsField) return "";
	NSString *val = [g_pocketTagsField stringValue];
	return val ? [val UTF8String] : "";
}

// ---------- Forward declaration of Go callbacks ----------

extern void goPocketSyncAction(char* action);

// ---------- Table Data Source ----------

@interface PocketSyncTableDataSource : NSObject <NSTableViewDataSource, NSTableViewDelegate>
- (void)pocketCheckboxClicked:(NSButton *)sender;
- (void)selectAllClicked:(id)sender;
- (void)deselectAllClicked:(id)sender;
- (void)syncSelectedClicked:(id)sender;
- (void)groupSelectedClicked:(id)sender;
- (void)copyURLClicked:(id)sender;
- (void)groupDisclosureClicked:(NSButton *)sender;
@end

@implementation PocketSyncTableDataSource

- (NSInteger)numberOfRowsInTableView:(NSTableView *)tableView {
	return g_pocketVisibleCount > 0 ? g_pocketVisibleCount : g_pocketRowCount;
}

- (NSView *)tableView:(NSTableView *)tableView
   viewForTableColumn:(NSTableColumn *)tableColumn
                  row:(NSInteger)visibleRow {

	int row = visibleRow; // direct mapping (Go handles grouping now)

	NSString *identifier = [tableColumn identifier];

	// Check if this row is a group header (# column shows "+" or "-")
	BOOL isGroupRow = (row < g_pocketRowCount && g_pocketData[row][0] &&
		(g_pocketData[row][0][0] == '+' || g_pocketData[row][0][0] == '-'));

	// Checkbox column: empty for group rows, checkbox for regular rows
	if ([identifier isEqualToString:@"select"]) {
		if (isGroupRow) {
			// Empty cell — no checkbox for group headers
			NSTextField *empty = [[NSTextField alloc] initWithFrame:NSZeroRect];
			[empty setBezeled:NO]; [empty setDrawsBackground:NO]; [empty setEditable:NO];
			[empty setStringValue:@""];
			return empty;
		}
		NSButton *cb = [[NSButton alloc] initWithFrame:NSZeroRect];
		[cb setButtonType:NSButtonTypeSwitch];
		[cb setTitle:@""];
		[cb setState:g_pocketSelected[row] ? NSControlStateValueOn : NSControlStateValueOff];
		[cb setTarget:self];
		[cb setAction:@selector(pocketCheckboxClicked:)];
		return cb;
	}

	// Group row: # column → clickable +/- button
	if (isGroupRow && [identifier isEqualToString:@"num"]) {
		NSButton *btn = [[NSButton alloc] initWithFrame:NSZeroRect];
		[btn setButtonType:NSButtonTypeMomentaryPushIn];
		[btn setBezelStyle:NSBezelStyleSmallSquare];
		char ch = g_pocketData[row][0][0];
		[btn setTitle:(ch == '+') ? @"▶" : @"▼"];
		[btn setFont:[NSFont systemFontOfSize:11]];
		[btn setTarget:self];
		[btn setAction:@selector(groupToggleClicked:)];
		[btn setTag:row];
		return btn;
	}

	NSTextField *cell = [[NSTextField alloc] initWithFrame:NSZeroRect];
	[cell setBezeled:NO];
	[cell setDrawsBackground:NO];
	[cell setEditable:NO];
	[cell setSelectable:YES];
	[cell setLineBreakMode:NSLineBreakByTruncatingTail];

	NSString *value = @"";

	if (row < g_pocketRowCount) {
		int col = -1;
		if ([identifier isEqualToString:@"num"])           col = 0;
		else if ([identifier isEqualToString:@"date"])     col = 1;
		else if ([identifier isEqualToString:@"time"])     col = 2;
		else if ([identifier isEqualToString:@"duration"]) col = 3;
		else if ([identifier isEqualToString:@"size"])     col = 4;
		else if ([identifier isEqualToString:@"status"])   col = 5;
		if (col >= 0 && g_pocketData[row][col]) {
			NSString *parsed = [NSString stringWithUTF8String:g_pocketData[row][col]];
			if (parsed) value = parsed;
		}

		if (col == 0 || col == 3 || col == 4) {
			[cell setAlignment:NSTextAlignmentRight];
		}

		// Color-coded status
		if (g_pocketData[row][5]) {
			NSString *st = [NSString stringWithUTF8String:g_pocketData[row][5]];
			if ([st isEqualToString:@"Synced"]) {
				[cell setTextColor:[NSColor systemGreenColor]];
			} else if ([st isEqualToString:@"new"]) {
				[cell setTextColor:[NSColor systemBlueColor]];
			} else if ([st isEqualToString:@"staged"]) {
				[cell setTextColor:[NSColor systemTealColor]];
			} else if ([st containsString:@"..."]) {
				[cell setTextColor:[NSColor systemOrangeColor]];
			} else if ([st isEqualToString:@"Failed"]) {
				[cell setTextColor:[NSColor systemRedColor]];
			} else if ([st isEqualToString:@"Grouped"]) {
				[cell setTextColor:[NSColor systemPurpleColor]];
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

- (void)pocketCheckboxClicked:(NSButton *)sender {
	NSInteger visibleRow = [g_pocketTable rowForView:sender];
	int row = visibleRow;
	if (g_pocketVisibleCount > 0 && visibleRow < g_pocketVisibleCount) {
		row = g_pocketVisibleMap[visibleRow];
	}
	if (row >= 0 && row < g_pocketRowCount) {
		g_pocketSelected[row] = (sender.state == NSControlStateValueOn);
		updatePocketSelectionLabel();
	}
}

- (void)groupDisclosureClicked:(NSButton *)sender {
	// Legacy — kept for compatibility
}

- (void)groupToggleClicked:(NSButton *)sender {
	int row = (int)[sender tag];
	if (row >= 0 && row < g_pocketRowCount && g_pocketFilePaths[row]) {
		// Pass the group's filePath (e.g., "group:uuid") as the action data
		char actionBuf[512];
		snprintf(actionBuf, sizeof(actionBuf), "toggle_group:%s", g_pocketFilePaths[row]);
		goPocketSyncAction(actionBuf);
	}
}

- (void)selectAllClicked:(id)sender {
	for (int i = 0; i < g_pocketRowCount; i++) g_pocketSelected[i] = YES;
	updatePocketSelectionLabel();
	[g_pocketTable reloadData];
}

- (void)deselectAllClicked:(id)sender {
	memset(g_pocketSelected, 0, sizeof(g_pocketSelected));
	updatePocketSelectionLabel();
	[g_pocketTable reloadData];
}

- (void)syncSelectedClicked:(id)sender {
	if (g_pocketBulkActive) return;
	goPocketSyncAction("sync");
}

- (void)groupSelectedClicked:(id)sender {
	if (g_pocketBulkActive) return;
	goPocketSyncAction("group");
}

- (void)copyURLClicked:(id)sender {
	copyPocketStatusURL();
}

@end

static PocketSyncTableDataSource *g_pocketDS = nil;

// ---------- Window Creation ----------

static void showPocketSyncWindow(const char *deviceInfo) {
	char *deviceCopy = deviceInfo ? strdup(deviceInfo) : NULL;
	dispatch_async(dispatch_get_main_queue(), ^{
		if (g_pocketWindow != nil) {
			// Window exists — just reload the table with new data
			if (g_pocketTable) [g_pocketTable reloadData];
			updatePocketSelectionLabel();
			[g_pocketWindow makeKeyAndOrderFront:nil];
			[NSApp activateIgnoringOtherApps:YES];
			if (deviceCopy) free(deviceCopy);
			return;
		}

		NSRect frame = NSMakeRect(200, 200, 780, 540);
		g_pocketWindow = [[NSWindow alloc]
			initWithContentRect:frame
			styleMask:(NSWindowStyleMaskTitled |
					   NSWindowStyleMaskClosable |
					   NSWindowStyleMaskResizable |
					   NSWindowStyleMaskMiniaturizable)
			backing:NSBackingStoreBuffered
			defer:NO];
		[g_pocketWindow setTitle:@"Pocket Sync — Audio Recordings"];
		[g_pocketWindow setMinSize:NSMakeSize(640, 420)];

		NSView *content = [g_pocketWindow contentView];

		// Device info label
		g_pocketDeviceLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(10, frame.size.height - 30, 760, 18)];
		[g_pocketDeviceLabel setBezeled:NO];
		[g_pocketDeviceLabel setDrawsBackground:NO];
		[g_pocketDeviceLabel setEditable:NO];
		[g_pocketDeviceLabel setFont:[NSFont systemFontOfSize:11]];
		[g_pocketDeviceLabel setTextColor:[NSColor secondaryLabelColor]];
		if (deviceCopy) {
			NSString *devStr = [NSString stringWithUTF8String:deviceCopy];
			[g_pocketDeviceLabel setStringValue:devStr ? devStr : @""];
			free(deviceCopy);
		}
		[g_pocketDeviceLabel setAutoresizingMask:NSViewWidthSizable | NSViewMinYMargin];
		[content addSubview:g_pocketDeviceLabel];

		// Buttons row
		CGFloat btnY = frame.size.height - 60;

		NSButton *btnSelectAll = [[NSButton alloc] initWithFrame:NSMakeRect(10, btnY, 90, 24)];
		[btnSelectAll setTitle:@"All"];
		[btnSelectAll setBezelStyle:NSBezelStyleRounded];
		[btnSelectAll setAutoresizingMask:NSViewMaxXMargin | NSViewMinYMargin];
		[content addSubview:btnSelectAll];

		NSButton *btnDeselectAll = [[NSButton alloc] initWithFrame:NSMakeRect(105, btnY, 90, 24)];
		[btnDeselectAll setTitle:@"None"];
		[btnDeselectAll setBezelStyle:NSBezelStyleRounded];
		[btnDeselectAll setAutoresizingMask:NSViewMaxXMargin | NSViewMinYMargin];
		[content addSubview:btnDeselectAll];

		g_pocketSelectLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(205, btnY + 2, 80, 18)];
		[g_pocketSelectLabel setBezeled:NO];
		[g_pocketSelectLabel setDrawsBackground:NO];
		[g_pocketSelectLabel setEditable:NO];
		[g_pocketSelectLabel setFont:[NSFont systemFontOfSize:11]];
		[g_pocketSelectLabel setStringValue:@"0 selected"];
		[g_pocketSelectLabel setAutoresizingMask:NSViewMaxXMargin | NSViewMinYMargin];
		[content addSubview:g_pocketSelectLabel];

		// Group Selected button
		g_btnPocketGroup = [[NSButton alloc] initWithFrame:NSMakeRect(295, btnY, 130, 24)];
		[g_btnPocketGroup setTitle:@"Group Selected"];
		[g_btnPocketGroup setBezelStyle:NSBezelStyleRounded];
		[g_btnPocketGroup setEnabled:NO];
		[g_btnPocketGroup setAutoresizingMask:NSViewMaxXMargin | NSViewMinYMargin];
		[content addSubview:g_btnPocketGroup];

		// Tags label + editable field
		NSTextField *tagsLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(435, btnY + 2, 40, 18)];
		[tagsLabel setBezeled:NO];
		[tagsLabel setDrawsBackground:NO];
		[tagsLabel setEditable:NO];
		[tagsLabel setFont:[NSFont systemFontOfSize:11]];
		[tagsLabel setStringValue:@"Tags:"];
		[tagsLabel setAutoresizingMask:NSViewMaxXMargin | NSViewMinYMargin];
		[content addSubview:tagsLabel];

		g_pocketTagsField = [[NSTextField alloc] initWithFrame:NSMakeRect(475, btnY, frame.size.width - 625, 24)];
		[g_pocketTagsField setFont:[NSFont systemFontOfSize:11]];
		[g_pocketTagsField setPlaceholderString:@"pocket,fieldnote"];
		[g_pocketTagsField setAutoresizingMask:NSViewWidthSizable | NSViewMinYMargin];
		[content addSubview:g_pocketTagsField];

		g_btnPocketSync = [[NSButton alloc] initWithFrame:NSMakeRect(frame.size.width - 140, btnY, 130, 24)];
		[g_btnPocketSync setTitle:@"Sync Selected"];
		[g_btnPocketSync setBezelStyle:NSBezelStyleRounded];
		[g_btnPocketSync setAutoresizingMask:NSViewMinXMargin | NSViewMinYMargin];
		[content addSubview:g_btnPocketSync];

		// Progress bar
		g_pocketProgressBar = [[NSProgressIndicator alloc]
			initWithFrame:NSMakeRect(10, btnY - 20, frame.size.width - 20, 8)];
		[g_pocketProgressBar setStyle:NSProgressIndicatorStyleBar];
		[g_pocketProgressBar setIndeterminate:YES];
		[g_pocketProgressBar setHidden:YES];
		[g_pocketProgressBar setAutoresizingMask:NSViewWidthSizable | NSViewMinYMargin];
		[content addSubview:g_pocketProgressBar];

		// Status label + Copy URL button
		g_pocketStatusLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(10, btnY - 38, frame.size.width - 90, 18)];
		[g_pocketStatusLabel setBezeled:NO];
		[g_pocketStatusLabel setDrawsBackground:NO];
		[g_pocketStatusLabel setEditable:NO];
		[g_pocketStatusLabel setSelectable:YES];
		[g_pocketStatusLabel setFont:[NSFont systemFontOfSize:11]];
		[g_pocketStatusLabel setStringValue:@"Ready"];
		[g_pocketStatusLabel setAutoresizingMask:NSViewWidthSizable | NSViewMinYMargin];
		[content addSubview:g_pocketStatusLabel];

		NSButton *btnCopyURL = [[NSButton alloc] initWithFrame:NSMakeRect(frame.size.width - 80, btnY - 40, 70, 22)];
		[btnCopyURL setTitle:@"Copy URL"];
		[btnCopyURL setBezelStyle:NSBezelStyleRounded];
		[btnCopyURL setFont:[NSFont systemFontOfSize:10]];
		[btnCopyURL setAutoresizingMask:NSViewMinXMargin | NSViewMinYMargin];
		[btnCopyURL setTarget:g_pocketDS];
		[btnCopyURL setAction:@selector(copyURLClicked:)];
		[content addSubview:btnCopyURL];

		// Table view
		CGFloat tableTop = btnY - 50;
		NSScrollView *scrollView = [[NSScrollView alloc]
			initWithFrame:NSMakeRect(10, 10, frame.size.width - 20, tableTop - 10)];
		[scrollView setHasVerticalScroller:YES];
		[scrollView setHasHorizontalScroller:NO];
		[scrollView setBorderType:NSBezelBorder];
		[scrollView setAutoresizingMask:NSViewWidthSizable | NSViewHeightSizable];

		g_pocketTable = [[NSTableView alloc] initWithFrame:NSZeroRect];
		[g_pocketTable setUsesAlternatingRowBackgroundColors:YES];
		[g_pocketTable setGridStyleMask:NSTableViewSolidVerticalGridLineMask];

		// Columns
		NSTableColumn *colSelect = [[NSTableColumn alloc] initWithIdentifier:@"select"];
		[colSelect setWidth:28]; [colSelect setMinWidth:28]; [colSelect setMaxWidth:28];
		[[colSelect headerCell] setStringValue:@""];
		[g_pocketTable addTableColumn:colSelect];

		NSTableColumn *colNum = [[NSTableColumn alloc] initWithIdentifier:@"num"];
		[colNum setWidth:35]; [colNum setMinWidth:28];
		[[colNum headerCell] setStringValue:@"#"];
		[g_pocketTable addTableColumn:colNum];

		NSTableColumn *colDate = [[NSTableColumn alloc] initWithIdentifier:@"date"];
		[colDate setWidth:180]; [colDate setMinWidth:120];
		[[colDate headerCell] setStringValue:@"Date / Time"];
		[g_pocketTable addTableColumn:colDate];

		NSTableColumn *colDuration = [[NSTableColumn alloc] initWithIdentifier:@"duration"];
		[colDuration setWidth:70]; [colDuration setMinWidth:40];
		[[colDuration headerCell] setStringValue:@"Duration"];
		[g_pocketTable addTableColumn:colDuration];

		NSTableColumn *colSize = [[NSTableColumn alloc] initWithIdentifier:@"size"];
		[colSize setWidth:70]; [colSize setMinWidth:40];
		[[colSize headerCell] setStringValue:@"Size"];
		[g_pocketTable addTableColumn:colSize];

		NSTableColumn *colStatus = [[NSTableColumn alloc] initWithIdentifier:@"status"];
		[colStatus setWidth:260]; [colStatus setMinWidth:100];
		[[colStatus headerCell] setStringValue:@"Status"];
		[g_pocketTable addTableColumn:colStatus];

		// Data source + delegate
		g_pocketDS = [[PocketSyncTableDataSource alloc] init];
		[g_pocketTable setDataSource:g_pocketDS];
		[g_pocketTable setDelegate:g_pocketDS];

		// Wire buttons
		[btnSelectAll setTarget:g_pocketDS];
		[btnSelectAll setAction:@selector(selectAllClicked:)];
		[btnDeselectAll setTarget:g_pocketDS];
		[btnDeselectAll setAction:@selector(deselectAllClicked:)];
		[g_btnPocketSync setTarget:g_pocketDS];
		[g_btnPocketSync setAction:@selector(syncSelectedClicked:)];
		[g_btnPocketGroup setTarget:g_pocketDS];
		[g_btnPocketGroup setAction:@selector(groupSelectedClicked:)];

		[scrollView setDocumentView:g_pocketTable];
		[content addSubview:scrollView];

		[g_pocketWindow setReleasedWhenClosed:NO];
		[g_pocketWindow makeKeyAndOrderFront:nil];
		[NSApp activateIgnoringOtherApps:YES];
	});
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// ShowPocketSyncWindow populates and displays the Pocket Sync window.
func ShowPocketSyncWindow(records []PocketSyncRecord, deviceInfo string, defaultTags ...string) {
	C.clearPocketData()

	for _, rec := range records {
		cNum := C.CString(rec.Num)
		cDate := C.CString(rec.Date)
		cTime := C.CString(rec.Time)
		cDur := C.CString(rec.Duration)
		cSize := C.CString(rec.Size)
		cStatus := C.CString(rec.Status)
		cPath := C.CString(rec.FilePath)
		C.addPocketRow(cNum, cDate, cTime, cDur, cSize, cStatus, cPath)
		C.free(unsafe.Pointer(cNum))
		C.free(unsafe.Pointer(cDate))
		C.free(unsafe.Pointer(cTime))
		C.free(unsafe.Pointer(cDur))
		C.free(unsafe.Pointer(cSize))
		C.free(unsafe.Pointer(cStatus))
		C.free(unsafe.Pointer(cPath))
	}

	C.rebuildVisibleMap()

	var cDevice *C.char
	if deviceInfo != "" {
		cDevice = C.CString(deviceInfo)
		defer C.free(unsafe.Pointer(cDevice))
	}
	C.showPocketSyncWindow(cDevice)

	if len(defaultTags) > 0 && defaultTags[0] != "" {
		cTags := C.CString(defaultTags[0])
		C.setPocketDefaultTags(cTags)
		C.free(unsafe.Pointer(cTags))
	}
}

// GetPocketCustomTags returns the current value of the custom tags field.
func GetPocketCustomTags() string {
	return C.GoString(C.getPocketCustomTags())
}

// SetPocketSyncStatus updates the status text of a specific recording by file path.
func SetPocketSyncStatus(filePath, status string) {
	cPath := C.CString(filePath)
	cStatus := C.CString(status)
	C.setPocketRowStatus(cPath, cStatus)
	C.free(unsafe.Pointer(cPath))
	C.free(unsafe.Pointer(cStatus))
}

// SetPocketSyncProgress updates the progress bar and status label.
func SetPocketSyncProgress(state BulkRunState) {
	active := 0
	if state.Active {
		active = 1
	}
	C.setPocketProgressState(C.int(active), C.int(state.Total), C.int(state.Done),
		C.int(state.Success), C.int(state.Failed))
}

// IsPocketSyncWindowOpen returns true if the Pocket Sync window is visible.
func IsPocketSyncWindowOpen() bool {
	return C.isPocketSyncWindowOpen() != 0
}

// ReloadPocketSyncTable reloads the table data in the open window.
func ReloadPocketSyncTable() {
	C.reloadPocketTable()
}

// SetPocketStatusText updates the status label text directly.
func SetPocketStatusText(text string) {
	cText := C.CString(text)
	C.setPocketStatusText(cText)
	C.free(unsafe.Pointer(cText))
}

// SelectedPocketFilePaths returns the file paths of all selected recordings.
func SelectedPocketFilePaths() []string {
	n := int(C.pocketSyncRowCount())
	var paths []string
	for i := 0; i < n; i++ {
		if C.pocketSyncIsSelected(C.int(i)) != 0 {
			p := C.GoString(C.pocketSyncFilePath(C.int(i)))
			if p != "" {
				paths = append(paths, p)
			}
		}
	}
	return paths
}

// SetPocketRowStatusByIndex updates the status column for a row by index.
func SetPocketRowStatusByIndex(index int, status string) {
	if index < 0 || index >= int(C.pocketSyncRowCount()) {
		return
	}
	fp := C.GoString(C.pocketSyncFilePath(C.int(index)))
	if fp != "" {
		SetPocketSyncStatus(fp, status)
	}
}

// PocketSyncRowCountGo returns the current row count (for testing).
func PocketSyncRowCountGo() int {
	return int(C.pocketSyncRowCount())
}

// CollapseGroupInTable replaces individual row statuses with a single group header
// and marks member rows as hidden children. Call after a group upload succeeds.
func CollapseGroupInTable(memberFilePaths []string, groupTitle, duration, size, status, docID string) {
	// Find the indices of member rows
	var memberIndices []int
	for i := 0; i < int(C.pocketSyncRowCount()); i++ {
		fp := C.GoString(C.pocketSyncFilePath(C.int(i)))
		for _, mfp := range memberFilePaths {
			if fp == mfp {
				memberIndices = append(memberIndices, i)
				break
			}
		}
	}
	if len(memberIndices) == 0 {
		return
	}

	// Add group header row
	cTitle := C.CString(groupTitle)
	cDur := C.CString(duration)
	cSize := C.CString(size)
	cStatus := C.CString(status)
	cDocID := C.CString(docID)
	C.addPocketGroupRow(cTitle, cDur, cSize, cStatus, cDocID, C.int(len(memberIndices)))
	C.free(unsafe.Pointer(cTitle))
	C.free(unsafe.Pointer(cDur))
	C.free(unsafe.Pointer(cSize))
	C.free(unsafe.Pointer(cStatus))
	C.free(unsafe.Pointer(cDocID))

	groupRowIdx := int(C.pocketSyncRowCount()) - 1

	// Mark member rows as children of the group
	for _, idx := range memberIndices {
		C.markChildRow(C.int(idx), C.int(groupRowIdx))
	}

	C.rebuildVisibleMap()
	ReloadPocketSyncTable()
}

// FormatDuration is in pocket_handler.go as FormatPocketDuration.
// FormatSize is in pocket_handler.go as FormatPocketSize.
// These aliases avoid name collisions with observation_darwin.go.
func init() {
	// Ensure the type and function registrations.
	_ = fmt.Sprintf
}

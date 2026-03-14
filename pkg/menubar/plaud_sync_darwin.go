// plaud_sync_darwin.go — Native macOS Plaud Sync Window via Cocoa/cgo.
//
// Creates an NSWindow with an NSTableView showing Plaud recordings
// with checkboxes for selection and a "Sync Selected" button.
// Follows the tracking_darwin.go pattern exactly.
//
// This file must be built on macOS (darwin) with cgo enabled.
package menubar

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa

#import <Cocoa/Cocoa.h>
#include <stdlib.h>

// ---------- Global Plaud Sync Window State ----------

static NSWindow     *g_plaudWindow    = nil;
static NSTableView  *g_plaudTable     = nil;
static NSTextField  *g_plaudStatusLabel = nil;
static NSTextField  *g_plaudSelectLabel = nil;
static NSProgressIndicator *g_plaudProgressBar = nil;
static NSTextField  *g_plaudAccountLabel = nil;
static NSButton     *g_btnPlaudSync   = nil;
static BOOL          g_plaudBulkActive = NO;

// ---------- Row Data Storage ----------

#define PLAUD_MAX_ROWS 200
#define PLAUD_COLS     6

// Columns: select(checkbox), num, title, duration, date, status
static char *g_plaudData[PLAUD_MAX_ROWS][PLAUD_COLS];
static BOOL  g_plaudSelected[PLAUD_MAX_ROWS];
static int   g_plaudRowCount = 0;

// Recording IDs (parallel to rows).
static char *g_plaudRecordingIDs[PLAUD_MAX_ROWS];

// ---------- Helpers ----------

static void clearPlaudData(void) {
	for (int r = 0; r < g_plaudRowCount; r++) {
		for (int c = 0; c < PLAUD_COLS; c++) {
			if (g_plaudData[r][c]) { free(g_plaudData[r][c]); g_plaudData[r][c] = NULL; }
		}
		if (g_plaudRecordingIDs[r]) { free(g_plaudRecordingIDs[r]); g_plaudRecordingIDs[r] = NULL; }
	}
	g_plaudRowCount = 0;
	memset(g_plaudSelected, 0, sizeof(g_plaudSelected));
}

static void addPlaudRow(const char *num, const char *title, const char *duration,
						const char *date, const char *status, const char *recordingID) {
	if (g_plaudRowCount >= PLAUD_MAX_ROWS) return;
	int r = g_plaudRowCount++;
	g_plaudData[r][0] = strdup(num       ? num       : "");
	g_plaudData[r][1] = strdup(title     ? title     : "");
	g_plaudData[r][2] = strdup(duration  ? duration  : "");
	g_plaudData[r][3] = strdup(date      ? date      : "");
	g_plaudData[r][4] = strdup(status    ? status    : "");
	g_plaudRecordingIDs[r] = strdup(recordingID ? recordingID : "");
	g_plaudSelected[r] = NO;
}

static void updatePlaudSelectionLabel(void) {
	if (!g_plaudSelectLabel) return;
	int count = 0;
	for (int i = 0; i < g_plaudRowCount; i++) {
		if (g_plaudSelected[i]) count++;
	}
	[g_plaudSelectLabel setStringValue:
		[NSString stringWithFormat:@"%d selected", count]];
}

static void setPlaudBulkControls(void) {
	BOOL active = g_plaudBulkActive;
	if (g_btnPlaudSync) [g_btnPlaudSync setEnabled:!active];
	if (g_plaudProgressBar) {
		[g_plaudProgressBar setHidden:!active];
	}
}

static int isPlaudSyncWindowOpen(void) {
	return (g_plaudWindow != nil) ? 1 : 0;
}

static void reloadPlaudTable(void) {
	dispatch_async(dispatch_get_main_queue(), ^{
		if (g_plaudWindow == nil) return;
		if (g_plaudTable) [g_plaudTable reloadData];
		updatePlaudSelectionLabel();
		setPlaudBulkControls();
	});
}

static void setPlaudStatusText(const char *text) {
	dispatch_async(dispatch_get_main_queue(), ^{
		if (g_plaudStatusLabel && text) {
			[g_plaudStatusLabel setStringValue:[NSString stringWithUTF8String:text]];
		}
	});
}

static void setPlaudRowStatus(const char *recordingID, const char *status) {
	if (!recordingID || !status) return;
	for (int i = 0; i < g_plaudRowCount; i++) {
		if (!g_plaudRecordingIDs[i]) continue;
		if (strcmp(g_plaudRecordingIDs[i], recordingID) == 0) {
			free(g_plaudData[i][4]);
			g_plaudData[i][4] = strdup(status);
			break;
		}
	}
	reloadPlaudTable();
}

static void setPlaudProgressState(int active, int total, int done, int success, int failed) {
	g_plaudBulkActive = active ? YES : NO;
	dispatch_async(dispatch_get_main_queue(), ^{
		setPlaudBulkControls();
		if (g_plaudProgressBar && active && total > 0) {
			[g_plaudProgressBar setIndeterminate:NO];
			[g_plaudProgressBar setMinValue:0.0];
			[g_plaudProgressBar setMaxValue:(double)total];
			[g_plaudProgressBar setDoubleValue:(double)done];
		}
		if (g_plaudStatusLabel) {
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
			[g_plaudStatusLabel setStringValue:text];
		}
	});
}

// ---------- Non-static accessors (for callback file) ----------

int plaudSyncRowCount(void) { return g_plaudRowCount; }

int plaudSyncIsSelected(int row) {
	return (row >= 0 && row < g_plaudRowCount && g_plaudSelected[row]) ? 1 : 0;
}

const char* plaudSyncRecordingID(int row) {
	return (row >= 0 && row < g_plaudRowCount && g_plaudRecordingIDs[row])
		? g_plaudRecordingIDs[row] : "";
}

// ---------- Forward declaration of Go callback ----------

extern void goPlaudSyncAction(char* action);

// ---------- Table Data Source ----------

@interface PlaudSyncTableDataSource : NSObject <NSTableViewDataSource, NSTableViewDelegate>
- (void)plaudCheckboxClicked:(NSButton *)sender;
- (void)selectAllClicked:(id)sender;
- (void)deselectAllClicked:(id)sender;
- (void)syncSelectedClicked:(id)sender;
@end

@implementation PlaudSyncTableDataSource

- (NSInteger)numberOfRowsInTableView:(NSTableView *)tableView {
	return g_plaudRowCount;
}

- (NSView *)tableView:(NSTableView *)tableView
   viewForTableColumn:(NSTableColumn *)tableColumn
                  row:(NSInteger)row {

	NSString *identifier = [tableColumn identifier];

	// Checkbox column
	if ([identifier isEqualToString:@"select"]) {
		NSButton *cb = [[NSButton alloc] initWithFrame:NSZeroRect];
		[cb setButtonType:NSButtonTypeSwitch];
		[cb setTitle:@""];
		[cb setState:g_plaudSelected[row] ? NSControlStateValueOn : NSControlStateValueOff];
		[cb setTarget:self];
		[cb setAction:@selector(plaudCheckboxClicked:)];
		return cb;
	}

	// Default: text cell
	NSTextField *cell = [[NSTextField alloc] initWithFrame:NSZeroRect];
	[cell setBezeled:NO];
	[cell setDrawsBackground:NO];
	[cell setEditable:NO];
	[cell setSelectable:YES];
	[cell setLineBreakMode:NSLineBreakByTruncatingTail];

	NSString *value = @"";

	if (row < g_plaudRowCount) {
		int col = -1;
		if ([identifier isEqualToString:@"num"])           col = 0;
		else if ([identifier isEqualToString:@"title"])    col = 1;
		else if ([identifier isEqualToString:@"duration"]) col = 2;
		else if ([identifier isEqualToString:@"date"])     col = 3;
		else if ([identifier isEqualToString:@"status"])   col = 4;
		if (col >= 0 && g_plaudData[row][col]) {
			value = [NSString stringWithUTF8String:g_plaudData[row][col]];
		}

		// Right-align # and duration columns.
		if (col == 0 || col == 2) {
			[cell setAlignment:NSTextAlignmentRight];
		}

		// Color-coded status
		if (g_plaudData[row][4]) {
			NSString *st = [NSString stringWithUTF8String:g_plaudData[row][4]];
			if ([st isEqualToString:@"synced"]) {
				[cell setTextColor:[NSColor systemGreenColor]];
			} else if ([st isEqualToString:@"new"]) {
				[cell setTextColor:[NSColor systemBlueColor]];
			} else if ([st isEqualToString:@"syncing"]) {
				[cell setTextColor:[NSColor systemOrangeColor]];
			} else if ([st isEqualToString:@"failed"]) {
				[cell setTextColor:[NSColor systemRedColor]];
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

- (void)plaudCheckboxClicked:(NSButton *)sender {
	NSInteger row = [g_plaudTable rowForView:sender];
	if (row >= 0 && row < g_plaudRowCount) {
		g_plaudSelected[row] = (sender.state == NSControlStateValueOn);
		updatePlaudSelectionLabel();
	}
}

- (void)selectAllClicked:(id)sender {
	for (int i = 0; i < g_plaudRowCount; i++) g_plaudSelected[i] = YES;
	updatePlaudSelectionLabel();
	[g_plaudTable reloadData];
}

- (void)deselectAllClicked:(id)sender {
	memset(g_plaudSelected, 0, sizeof(g_plaudSelected));
	updatePlaudSelectionLabel();
	[g_plaudTable reloadData];
}

// ---------- Sync action ----------

- (void)syncSelectedClicked:(id)sender {
	if (g_plaudBulkActive) return;
	goPlaudSyncAction("sync");
}

@end

// ---------- Global data source (must live for the window's lifetime) ----------

static PlaudSyncTableDataSource *g_plaudDS = nil;

// ---------- Window Creation ----------

static void showPlaudSyncWindow(const char *accountInfo) {
	dispatch_async(dispatch_get_main_queue(), ^{
		if (g_plaudWindow != nil) {
			[g_plaudWindow makeKeyAndOrderFront:nil];
			[NSApp activateIgnoringOtherApps:YES];
			return;
		}

		NSRect frame = NSMakeRect(200, 200, 720, 520);
		g_plaudWindow = [[NSWindow alloc]
			initWithContentRect:frame
			styleMask:(NSWindowStyleMaskTitled |
					   NSWindowStyleMaskClosable |
					   NSWindowStyleMaskResizable |
					   NSWindowStyleMaskMiniaturizable)
			backing:NSBackingStoreBuffered
			defer:NO];
		[g_plaudWindow setTitle:@"Plaud Sync — Fieldnote Recordings"];
		[g_plaudWindow setMinSize:NSMakeSize(600, 400)];

		NSView *content = [g_plaudWindow contentView];

		// Account info label
		g_plaudAccountLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(10, frame.size.height - 30, 700, 18)];
		[g_plaudAccountLabel setBezeled:NO];
		[g_plaudAccountLabel setDrawsBackground:NO];
		[g_plaudAccountLabel setEditable:NO];
		[g_plaudAccountLabel setFont:[NSFont systemFontOfSize:11]];
		[g_plaudAccountLabel setTextColor:[NSColor secondaryLabelColor]];
		if (accountInfo) {
			[g_plaudAccountLabel setStringValue:[NSString stringWithUTF8String:accountInfo]];
		}
		[g_plaudAccountLabel setAutoresizingMask:NSViewWidthSizable | NSViewMinYMargin];
		[content addSubview:g_plaudAccountLabel];

		// Buttons row
		CGFloat btnY = frame.size.height - 60;

		NSButton *btnSelectAll = [[NSButton alloc] initWithFrame:NSMakeRect(10, btnY, 80, 24)];
		[btnSelectAll setTitle:@"Select All"];
		[btnSelectAll setBezelStyle:NSBezelStyleRounded];
		[btnSelectAll setAutoresizingMask:NSViewMaxXMargin | NSViewMinYMargin];
		[content addSubview:btnSelectAll];

		NSButton *btnDeselectAll = [[NSButton alloc] initWithFrame:NSMakeRect(95, btnY, 80, 24)];
		[btnDeselectAll setTitle:@"Select None"];
		[btnDeselectAll setBezelStyle:NSBezelStyleRounded];
		[btnDeselectAll setAutoresizingMask:NSViewMaxXMargin | NSViewMinYMargin];
		[content addSubview:btnDeselectAll];

		g_plaudSelectLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(185, btnY + 2, 100, 18)];
		[g_plaudSelectLabel setBezeled:NO];
		[g_plaudSelectLabel setDrawsBackground:NO];
		[g_plaudSelectLabel setEditable:NO];
		[g_plaudSelectLabel setFont:[NSFont systemFontOfSize:11]];
		[g_plaudSelectLabel setStringValue:@"0 selected"];
		[g_plaudSelectLabel setAutoresizingMask:NSViewMaxXMargin | NSViewMinYMargin];
		[content addSubview:g_plaudSelectLabel];

		g_btnPlaudSync = [[NSButton alloc] initWithFrame:NSMakeRect(frame.size.width - 140, btnY, 130, 24)];
		[g_btnPlaudSync setTitle:@"Sync Selected"];
		[g_btnPlaudSync setBezelStyle:NSBezelStyleRounded];
		[g_btnPlaudSync setAutoresizingMask:NSViewMinXMargin | NSViewMinYMargin];
		[content addSubview:g_btnPlaudSync];

		// Progress bar
		g_plaudProgressBar = [[NSProgressIndicator alloc]
			initWithFrame:NSMakeRect(10, btnY - 20, frame.size.width - 20, 8)];
		[g_plaudProgressBar setStyle:NSProgressIndicatorStyleBar];
		[g_plaudProgressBar setIndeterminate:YES];
		[g_plaudProgressBar setHidden:YES];
		[g_plaudProgressBar setAutoresizingMask:NSViewWidthSizable | NSViewMinYMargin];
		[content addSubview:g_plaudProgressBar];

		// Status label
		g_plaudStatusLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(10, btnY - 38, frame.size.width - 20, 18)];
		[g_plaudStatusLabel setBezeled:NO];
		[g_plaudStatusLabel setDrawsBackground:NO];
		[g_plaudStatusLabel setEditable:NO];
		[g_plaudStatusLabel setFont:[NSFont systemFontOfSize:11]];
		[g_plaudStatusLabel setStringValue:@"Ready"];
		[g_plaudStatusLabel setAutoresizingMask:NSViewWidthSizable | NSViewMinYMargin];
		[content addSubview:g_plaudStatusLabel];

		// Table view in scroll view
		CGFloat tableTop = btnY - 50;
		NSScrollView *scrollView = [[NSScrollView alloc]
			initWithFrame:NSMakeRect(10, 10, frame.size.width - 20, tableTop - 10)];
		[scrollView setHasVerticalScroller:YES];
		[scrollView setHasHorizontalScroller:NO];
		[scrollView setBorderType:NSBezelBorder];
		[scrollView setAutoresizingMask:NSViewWidthSizable | NSViewHeightSizable];

		g_plaudTable = [[NSTableView alloc] initWithFrame:NSZeroRect];
		[g_plaudTable setUsesAlternatingRowBackgroundColors:YES];
		[g_plaudTable setGridStyleMask:NSTableViewSolidVerticalGridLineMask];

		// Columns
		NSTableColumn *colSelect = [[NSTableColumn alloc] initWithIdentifier:@"select"];
		[colSelect setWidth:28]; [colSelect setMinWidth:28]; [colSelect setMaxWidth:28];
		[[colSelect headerCell] setStringValue:@""];
		[g_plaudTable addTableColumn:colSelect];

		NSTableColumn *colNum = [[NSTableColumn alloc] initWithIdentifier:@"num"];
		[colNum setWidth:40]; [colNum setMinWidth:30];
		[[colNum headerCell] setStringValue:@"#"];
		[g_plaudTable addTableColumn:colNum];

		NSTableColumn *colTitle = [[NSTableColumn alloc] initWithIdentifier:@"title"];
		[colTitle setWidth:260]; [colTitle setMinWidth:100];
		[[colTitle headerCell] setStringValue:@"Title"];
		[g_plaudTable addTableColumn:colTitle];

		NSTableColumn *colDuration = [[NSTableColumn alloc] initWithIdentifier:@"duration"];
		[colDuration setWidth:80]; [colDuration setMinWidth:50];
		[[colDuration headerCell] setStringValue:@"Duration"];
		[g_plaudTable addTableColumn:colDuration];

		NSTableColumn *colDate = [[NSTableColumn alloc] initWithIdentifier:@"date"];
		[colDate setWidth:140]; [colDate setMinWidth:80];
		[[colDate headerCell] setStringValue:@"Date"];
		[g_plaudTable addTableColumn:colDate];

		NSTableColumn *colStatus = [[NSTableColumn alloc] initWithIdentifier:@"status"];
		[colStatus setWidth:80]; [colStatus setMinWidth:50];
		[[colStatus headerCell] setStringValue:@"Status"];
		[g_plaudTable addTableColumn:colStatus];

		// Data source
		g_plaudDS = [[PlaudSyncTableDataSource alloc] init];
		[g_plaudTable setDataSource:g_plaudDS];
		[g_plaudTable setDelegate:g_plaudDS];

		// Wire buttons
		[btnSelectAll setTarget:g_plaudDS];
		[btnSelectAll setAction:@selector(selectAllClicked:)];
		[btnDeselectAll setTarget:g_plaudDS];
		[btnDeselectAll setAction:@selector(deselectAllClicked:)];
		[g_btnPlaudSync setTarget:g_plaudDS];
		[g_btnPlaudSync setAction:@selector(syncSelectedClicked:)];

		[scrollView setDocumentView:g_plaudTable];
		[content addSubview:scrollView];

		// Close delegate to nil out window reference
		[g_plaudWindow setReleasedWhenClosed:NO];

		[g_plaudWindow makeKeyAndOrderFront:nil];
		[NSApp activateIgnoringOtherApps:YES];
	});
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// PlaudSyncRecord holds one recording row for the Plaud Sync window.
type PlaudSyncRecord struct {
	Title       string
	Duration    string
	Date        string
	Status      string
	RecordingID string
}

// ShowPlaudSyncWindow populates and displays the Plaud Sync window.
func ShowPlaudSyncWindow(records []PlaudSyncRecord, accountInfo string) {
	C.clearPlaudData()

	for i, rec := range records {
		cNum := C.CString(fmt.Sprintf("%d", i+1))
		cTitle := C.CString(rec.Title)
		cDur := C.CString(rec.Duration)
		cDate := C.CString(rec.Date)
		cStatus := C.CString(rec.Status)
		cID := C.CString(rec.RecordingID)
		C.addPlaudRow(cNum, cTitle, cDur, cDate, cStatus, cID)
		C.free(unsafe.Pointer(cNum))
		C.free(unsafe.Pointer(cTitle))
		C.free(unsafe.Pointer(cDur))
		C.free(unsafe.Pointer(cDate))
		C.free(unsafe.Pointer(cStatus))
		C.free(unsafe.Pointer(cID))
	}

	var cAccount *C.char
	if accountInfo != "" {
		cAccount = C.CString(accountInfo)
		defer C.free(unsafe.Pointer(cAccount))
	}
	C.showPlaudSyncWindow(cAccount)
}

// SetPlaudSyncStatus updates the status text of a specific recording by ID.
func SetPlaudSyncStatus(recordingID, status string) {
	cID := C.CString(recordingID)
	cStatus := C.CString(status)
	C.setPlaudRowStatus(cID, cStatus)
	C.free(unsafe.Pointer(cID))
	C.free(unsafe.Pointer(cStatus))
}

// SetPlaudSyncProgress updates the progress bar and status label.
func SetPlaudSyncProgress(state BulkRunState) {
	active := 0
	if state.Active {
		active = 1
	}
	C.setPlaudProgressState(C.int(active), C.int(state.Total), C.int(state.Done),
		C.int(state.Success), C.int(state.Failed))
}

// IsPlaudSyncWindowOpen returns true if the Plaud Sync window is visible.
func IsPlaudSyncWindowOpen() bool {
	return C.isPlaudSyncWindowOpen() != 0
}

// ReloadPlaudSyncTable reloads the table data in the open window.
func ReloadPlaudSyncTable() {
	C.reloadPlaudTable()
}

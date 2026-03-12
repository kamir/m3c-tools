// gantt_darwin.go — Native macOS Gantt chart Time Tracker window via Cocoa/cgo.
//
// Creates an NSWindow with a custom GanttView that renders project time
// tracking sessions as horizontal bars on a time grid. Supports week and
// month views with navigation controls.
//
// This file must be built on macOS (darwin) with cgo enabled.
package menubar

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa

#import <Cocoa/Cocoa.h>
#include <stdlib.h>

// ---------- Forward declaration of Go navigation callback ----------

extern void goGanttNavigate(int viewMode, int offset);

// ---------- Global Gantt Window State ----------

static NSWindow         *g_ganttWindow    = nil;
static NSView           *g_ganttChartView = nil;
static NSScrollView     *g_ganttScrollView = nil;
static NSTextField      *g_ganttPeriodLabel = nil;
static NSSegmentedControl *g_ganttSegCtrl = nil;

// Navigation state (managed by C, passed to Go callback).
static int g_ganttViewMode = 0; // 0=week, 1=month
static int g_ganttOffset   = 0; // 0=current, negative=past, positive=future

// ---------- Data Storage ----------

#define GANTT_MAX_PROJECTS 20
#define GANTT_MAX_SESSIONS 500
#define GANTT_MAX_DAYS     31

// Per-project data.
static char  *g_ganttProjName[GANTT_MAX_PROJECTS];
static char  *g_ganttProjTotal[GANTT_MAX_PROJECTS]; // formatted duration
static float  g_ganttProjR[GANTT_MAX_PROJECTS];
static float  g_ganttProjG[GANTT_MAX_PROJECTS];
static float  g_ganttProjB[GANTT_MAX_PROJECTS];
static int    g_ganttProjCount = 0;

// Per-session data.
static int    g_ganttSessProjIdx[GANTT_MAX_SESSIONS];
static double g_ganttSessStart[GANTT_MAX_SESSIONS]; // epoch seconds
static double g_ganttSessEnd[GANTT_MAX_SESSIONS];   // epoch seconds
static int    g_ganttSessActive[GANTT_MAX_SESSIONS]; // 1=still active
static int    g_ganttSessInferred[GANTT_MAX_SESSIONS]; // 1=observation-inferred block
static int    g_ganttSessCount = 0;

// Period info.
static double g_ganttPeriodStart = 0; // epoch seconds
static double g_ganttPeriodEnd   = 0; // epoch seconds
static char  *g_ganttDayLabels[GANTT_MAX_DAYS];
static int    g_ganttDayCount = 0;
static char  *g_ganttPeriodText = NULL; // e.g. "Mar 10 – 16, 2026"

// ---------- Data Functions ----------

static void clearGanttData(void) {
	for (int i = 0; i < g_ganttProjCount; i++) {
		if (g_ganttProjName[i])  { free(g_ganttProjName[i]);  g_ganttProjName[i] = NULL; }
		if (g_ganttProjTotal[i]) { free(g_ganttProjTotal[i]); g_ganttProjTotal[i] = NULL; }
	}
	g_ganttProjCount = 0;
	g_ganttSessCount = 0;
	for (int i = 0; i < g_ganttDayCount; i++) {
		if (g_ganttDayLabels[i]) { free(g_ganttDayLabels[i]); g_ganttDayLabels[i] = NULL; }
	}
	g_ganttDayCount = 0;
	if (g_ganttPeriodText) { free(g_ganttPeriodText); g_ganttPeriodText = NULL; }
}

static void addGanttProject(const char *name, const char *total,
                            float r, float g, float b) {
	if (g_ganttProjCount >= GANTT_MAX_PROJECTS) return;
	int i = g_ganttProjCount++;
	g_ganttProjName[i]  = strdup(name  ? name  : "");
	g_ganttProjTotal[i] = strdup(total ? total : "");
	g_ganttProjR[i] = r;
	g_ganttProjG[i] = g;
	g_ganttProjB[i] = b;
}

static void addGanttSession(int projIdx, double start, double end, int active, int inferred) {
	if (g_ganttSessCount >= GANTT_MAX_SESSIONS) return;
	int i = g_ganttSessCount++;
	g_ganttSessProjIdx[i]    = projIdx;
	g_ganttSessStart[i]      = start;
	g_ganttSessEnd[i]        = end;
	g_ganttSessActive[i]     = active;
	g_ganttSessInferred[i]   = inferred;
}

static void setGanttPeriod(double start, double end, const char *label, int viewMode) {
	g_ganttPeriodStart = start;
	g_ganttPeriodEnd   = end;
	g_ganttViewMode    = viewMode;
	if (g_ganttPeriodText) { free(g_ganttPeriodText); g_ganttPeriodText = NULL; }
	if (label) g_ganttPeriodText = strdup(label);
}

static void addGanttDayLabel(const char *label) {
	if (g_ganttDayCount >= GANTT_MAX_DAYS) return;
	g_ganttDayLabels[g_ganttDayCount++] = strdup(label ? label : "");
}

static int isGanttWindowOpen(void) {
	return (g_ganttWindow != nil) ? 1 : 0;
}

// ---------- GanttView (custom drawing) ----------

@interface GanttView : NSView
@end

@implementation GanttView

- (BOOL)isFlipped { return YES; }

- (void)drawRect:(NSRect)dirtyRect {
	[super drawRect:dirtyRect];
	NSRect bounds = [self bounds];

	CGFloat leftMargin  = 140.0;
	CGFloat rightMargin = 80.0;
	CGFloat headerH     = 28.0;
	CGFloat rowH        = 36.0;
	CGFloat chartWidth  = bounds.size.width - leftMargin - rightMargin;

	// --- Empty state ---
	if (g_ganttProjCount == 0) {
		NSString *msg = @"No time tracking sessions in this period";
		NSDictionary *attrs = @{
			NSFontAttributeName: [NSFont systemFontOfSize:14],
			NSForegroundColorAttributeName: [NSColor secondaryLabelColor]
		};
		NSSize sz = [msg sizeWithAttributes:attrs];
		CGFloat x = (bounds.size.width - sz.width) / 2;
		CGFloat y = bounds.size.height / 2 - sz.height / 2;
		[msg drawAtPoint:NSMakePoint(x, y) withAttributes:attrs];
		return;
	}

	if (chartWidth < 50) return;

	double periodDur = g_ganttPeriodEnd - g_ganttPeriodStart;
	if (periodDur <= 0) return;

	// --- Day grid lines and labels ---
	for (int d = 0; d < g_ganttDayCount; d++) {
		CGFloat x = leftMargin + ((double)d / g_ganttDayCount) * chartWidth;
		CGFloat dayWidth = chartWidth / g_ganttDayCount;

		// Vertical grid line (dashed).
		if (d > 0) {
			[[NSColor separatorColor] setStroke];
			NSBezierPath *gridLine = [NSBezierPath bezierPath];
			[gridLine setLineWidth:0.5];
			CGFloat dash[] = {3, 3};
			[gridLine setLineDash:dash count:2 phase:0];
			[gridLine moveToPoint:NSMakePoint(x, headerH)];
			[gridLine lineToPoint:NSMakePoint(x, bounds.size.height)];
			[gridLine stroke];
		}

		// Day label.
		if (g_ganttDayLabels[d]) {
			NSString *label = [NSString stringWithUTF8String:g_ganttDayLabels[d]];
			NSDictionary *attrs = @{
				NSFontAttributeName: [NSFont systemFontOfSize:10 weight:NSFontWeightMedium],
				NSForegroundColorAttributeName: [NSColor secondaryLabelColor]
			};
			NSRect labelRect = NSMakeRect(x + 4, 7, dayWidth - 8, 16);
			[label drawInRect:labelRect withAttributes:attrs];
		}
	}

	// Right edge line.
	[[NSColor separatorColor] setStroke];
	NSBezierPath *rightEdge = [NSBezierPath bezierPath];
	[rightEdge setLineWidth:0.5];
	[rightEdge moveToPoint:NSMakePoint(leftMargin + chartWidth, headerH)];
	[rightEdge lineToPoint:NSMakePoint(leftMargin + chartWidth, bounds.size.height)];
	[rightEdge stroke];

	// Left edge line.
	NSBezierPath *leftEdge = [NSBezierPath bezierPath];
	[leftEdge setLineWidth:0.5];
	[leftEdge moveToPoint:NSMakePoint(leftMargin, headerH)];
	[leftEdge lineToPoint:NSMakePoint(leftMargin, bounds.size.height)];
	[leftEdge stroke];

	// Header bottom line.
	[NSBezierPath strokeLineFromPoint:NSMakePoint(0, headerH)
	                          toPoint:NSMakePoint(bounds.size.width, headerH)];

	// --- Project rows ---
	for (int p = 0; p < g_ganttProjCount; p++) {
		CGFloat y = headerH + p * rowH;

		// Alternating row background.
		if (p % 2 == 0) {
			[[NSColor colorWithWhite:0.5 alpha:0.05] setFill];
			NSRectFill(NSMakeRect(0, y, bounds.size.width, rowH));
		}

		// Row separator.
		[[NSColor separatorColor] setStroke];
		NSBezierPath *rowLine = [NSBezierPath bezierPath];
		[rowLine setLineWidth:0.25];
		[rowLine moveToPoint:NSMakePoint(0, y + rowH)];
		[rowLine lineToPoint:NSMakePoint(bounds.size.width, y + rowH)];
		[rowLine stroke];

		// Project name (left margin).
		if (g_ganttProjName[p]) {
			NSString *name = [NSString stringWithUTF8String:g_ganttProjName[p]];
			NSDictionary *attrs = @{
				NSFontAttributeName: [NSFont systemFontOfSize:11],
				NSForegroundColorAttributeName: [NSColor labelColor]
			};
			NSRect nameRect = NSMakeRect(8, y + 10, leftMargin - 16, 16);
			[name drawInRect:nameRect withAttributes:attrs];
		}

		// Duration total (right margin).
		if (g_ganttProjTotal[p]) {
			NSString *total = [NSString stringWithUTF8String:g_ganttProjTotal[p]];
			NSDictionary *attrs = @{
				NSFontAttributeName: [NSFont monospacedDigitSystemFontOfSize:10 weight:NSFontWeightRegular],
				NSForegroundColorAttributeName: [NSColor secondaryLabelColor]
			};
			CGFloat tx = leftMargin + chartWidth + 8;
			[total drawAtPoint:NSMakePoint(tx, y + 11) withAttributes:attrs];
		}
	}

	// --- Session bars ---
	for (int i = 0; i < g_ganttSessCount; i++) {
		int pidx = g_ganttSessProjIdx[i];
		if (pidx < 0 || pidx >= g_ganttProjCount) continue;

		double start = g_ganttSessStart[i];
		double end   = g_ganttSessEnd[i];

		// Clamp to visible period.
		if (start < g_ganttPeriodStart) start = g_ganttPeriodStart;
		if (end   > g_ganttPeriodEnd)   end   = g_ganttPeriodEnd;
		if (end <= start) continue;

		CGFloat x1 = leftMargin + (start - g_ganttPeriodStart) / periodDur * chartWidth;
		CGFloat x2 = leftMargin + (end   - g_ganttPeriodStart) / periodDur * chartWidth;
		CGFloat barW = x2 - x1;
		if (barW < 2) barW = 2; // minimum visible width

		CGFloat y    = headerH + pidx * rowH + 5;
		CGFloat barH = rowH - 10;

		NSRect barRect = NSMakeRect(x1, y, barW, barH);
		NSBezierPath *bar = [NSBezierPath bezierPathWithRoundedRect:barRect
		                                                   xRadius:3
		                                                   yRadius:3];

		if (g_ganttSessInferred[i]) {
			// Inferred block: semi-transparent fill + dashed border.
			NSColor *fillColor = [NSColor colorWithCalibratedRed:g_ganttProjR[pidx]
			                                              green:g_ganttProjG[pidx]
			                                               blue:g_ganttProjB[pidx]
			                                              alpha:0.35];
			[fillColor setFill];
			[bar fill];

			NSColor *strokeColor = [NSColor colorWithCalibratedRed:g_ganttProjR[pidx]
			                                                green:g_ganttProjG[pidx]
			                                                 blue:g_ganttProjB[pidx]
			                                                alpha:0.70];
			[strokeColor setStroke];
			[bar setLineWidth:1.5];
			CGFloat dash[] = {4, 3};
			[bar setLineDash:dash count:2 phase:0];
			[bar stroke];
		} else {
			// Explicit block: solid fill.
			NSColor *color = [NSColor colorWithCalibratedRed:g_ganttProjR[pidx]
			                                           green:g_ganttProjG[pidx]
			                                            blue:g_ganttProjB[pidx]
			                                           alpha:0.85];
			[color setFill];
			[bar fill];
		}

		// Active session: draw a brighter extension indicator at the right edge.
		if (g_ganttSessActive[i]) {
			NSColor *glow = [NSColor colorWithCalibratedRed:g_ganttProjR[pidx]
			                                          green:g_ganttProjG[pidx]
			                                           blue:g_ganttProjB[pidx]
			                                          alpha:0.40];
			[glow setFill];
			NSRect glowRect = NSMakeRect(x1 + barW - 2, y - 2, 8, barH + 4);
			NSBezierPath *glowPath = [NSBezierPath bezierPathWithRoundedRect:glowRect
			                                                         xRadius:4
			                                                         yRadius:4];
			[glowPath fill];
		}
	}

	// --- "Now" indicator (vertical red line) ---
	double now = [[NSDate date] timeIntervalSince1970];
	if (now >= g_ganttPeriodStart && now <= g_ganttPeriodEnd) {
		CGFloat nowX = leftMargin + (now - g_ganttPeriodStart) / periodDur * chartWidth;

		[[NSColor systemRedColor] setStroke];
		NSBezierPath *nowLine = [NSBezierPath bezierPath];
		[nowLine setLineWidth:1.5];
		[nowLine moveToPoint:NSMakePoint(nowX, 0)];
		[nowLine lineToPoint:NSMakePoint(nowX, bounds.size.height)];
		[nowLine stroke];

		// Small triangle at the top.
		[[NSColor systemRedColor] setFill];
		NSBezierPath *tri = [NSBezierPath bezierPath];
		[tri moveToPoint:NSMakePoint(nowX - 5, 0)];
		[tri lineToPoint:NSMakePoint(nowX + 5, 0)];
		[tri lineToPoint:NSMakePoint(nowX, 8)];
		[tri closePath];
		[tri fill];
	}
}

@end

// ---------- Navigation Delegate ----------

@interface GanttNavHandler : NSObject
- (void)prevClicked:(id)sender;
- (void)nextClicked:(id)sender;
- (void)todayClicked:(id)sender;
- (void)viewModeChanged:(NSSegmentedControl *)sender;
@end

static GanttNavHandler *g_ganttNavDelegate = nil;

@implementation GanttNavHandler

- (void)prevClicked:(id)sender {
	g_ganttOffset--;
	goGanttNavigate(g_ganttViewMode, g_ganttOffset);
}

- (void)nextClicked:(id)sender {
	g_ganttOffset++;
	goGanttNavigate(g_ganttViewMode, g_ganttOffset);
}

- (void)todayClicked:(id)sender {
	g_ganttOffset = 0;
	goGanttNavigate(g_ganttViewMode, g_ganttOffset);
}

- (void)viewModeChanged:(NSSegmentedControl *)sender {
	g_ganttViewMode = (int)[sender selectedSegment];
	g_ganttOffset = 0;
	goGanttNavigate(g_ganttViewMode, g_ganttOffset);
}

@end

// ---------- Window Delegate (resets state on close) ----------

@interface GanttWindowDelegate : NSObject <NSWindowDelegate>
@end

static GanttWindowDelegate *g_ganttWindowDelegate = nil;

@implementation GanttWindowDelegate

- (void)windowWillClose:(NSNotification *)notification {
	g_ganttWindow     = nil;
	g_ganttChartView  = nil;
	g_ganttScrollView = nil;
	g_ganttPeriodLabel = nil;
	g_ganttSegCtrl    = nil;
}

@end

// ---------- UI Reload (must be called on main thread) ----------

static void reloadGanttChartUI(void) {
	if (g_ganttChartView == nil) return;

	// Update period label.
	if (g_ganttPeriodLabel && g_ganttPeriodText) {
		[g_ganttPeriodLabel setStringValue:
			[NSString stringWithUTF8String:g_ganttPeriodText]];
	}

	// Update segmented control.
	if (g_ganttSegCtrl) {
		[g_ganttSegCtrl setSelectedSegment:g_ganttViewMode];
	}

	// Resize chart view to fit content.
	CGFloat headerH = 28.0;
	CGFloat rowH    = 36.0;
	CGFloat neededH = headerH + g_ganttProjCount * rowH;
	if (neededH < 200) neededH = 200;

	if (g_ganttScrollView) {
		NSSize contentSize = [g_ganttScrollView contentSize];
		CGFloat chartH = contentSize.height;
		if (neededH > chartH) chartH = neededH;
		[g_ganttChartView setFrameSize:NSMakeSize(contentSize.width, chartH)];
	}

	[g_ganttChartView setNeedsDisplay:YES];
}

// reloadGanttChart is thread-safe — dispatches to main thread.
static void reloadGanttChart(void) {
	dispatch_async(dispatch_get_main_queue(), ^{
		reloadGanttChartUI();
	});
}

// ---------- Window Creation ----------

static void showGanttWindow(void) {
	dispatch_sync(dispatch_get_main_queue(), ^{
		// If already open, bring to front and reload.
		if (g_ganttWindow != nil) {
			[g_ganttWindow makeKeyAndOrderFront:nil];
			[NSApp activateIgnoringOtherApps:YES];
			reloadGanttChartUI();
			return;
		}

		// ---- Window ----
		NSScreen *screen = [NSScreen mainScreen];
		NSRect sf = [screen visibleFrame];
		CGFloat winW = sf.size.width * 0.55;
		CGFloat winH = sf.size.height * 0.6;
		if (winW < 800) winW = 800;
		if (winH < 400) winH = 400;

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

		[window setTitle:@"Time Tracker"];
		[window setReleasedWhenClosed:NO];
		[window setHidesOnDeactivate:NO];
		[window setMinSize:NSMakeSize(800, 400)];

		// ---- Window delegate (resets global pointers on close) ----
		if (g_ganttWindowDelegate == nil) {
			g_ganttWindowDelegate = [[GanttWindowDelegate alloc] init];
		}
		[window setDelegate:g_ganttWindowDelegate];

		g_ganttWindow = window;

		[NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];

		// ---- Navigation delegate ----
		if (g_ganttNavDelegate == nil) {
			g_ganttNavDelegate = [[GanttNavHandler alloc] init];
		}

		NSView *contentView = [window contentView];
		CGFloat toolbarH = 44;

		// Previous button.
		NSButton *btnPrev = [[NSButton alloc] initWithFrame:
			NSMakeRect(10, winH - toolbarH + 8, 30, 28)];
		[btnPrev setTitle:@"◀"];
		[btnPrev setBezelStyle:NSBezelStyleRounded];
		[btnPrev setTarget:g_ganttNavDelegate];
		[btnPrev setAction:@selector(prevClicked:)];
		[btnPrev setAutoresizingMask:(NSViewMaxXMargin | NSViewMinYMargin)];
		[contentView addSubview:btnPrev];

		// Next button.
		NSButton *btnNext = [[NSButton alloc] initWithFrame:
			NSMakeRect(42, winH - toolbarH + 8, 30, 28)];
		[btnNext setTitle:@"▶"];
		[btnNext setBezelStyle:NSBezelStyleRounded];
		[btnNext setTarget:g_ganttNavDelegate];
		[btnNext setAction:@selector(nextClicked:)];
		[btnNext setAutoresizingMask:(NSViewMaxXMargin | NSViewMinYMargin)];
		[contentView addSubview:btnNext];

		// Today button.
		NSButton *btnToday = [[NSButton alloc] initWithFrame:
			NSMakeRect(78, winH - toolbarH + 8, 80, 28)];
		[btnToday setTitle:@"Today"];
		[btnToday setBezelStyle:NSBezelStyleRounded];
		[btnToday setTarget:g_ganttNavDelegate];
		[btnToday setAction:@selector(todayClicked:)];
		[btnToday setAutoresizingMask:(NSViewMaxXMargin | NSViewMinYMargin)];
		[contentView addSubview:btnToday];

		// Period label (centered).
		NSTextField *periodLabel = [[NSTextField alloc] initWithFrame:
			NSMakeRect(170, winH - toolbarH + 12, winW - 340, 20)];
		[periodLabel setBezeled:NO];
		[periodLabel setDrawsBackground:NO];
		[periodLabel setEditable:NO];
		[periodLabel setSelectable:NO];
		[periodLabel setAlignment:NSTextAlignmentCenter];
		[periodLabel setFont:[NSFont systemFontOfSize:14 weight:NSFontWeightMedium]];
		[periodLabel setAutoresizingMask:(NSViewWidthSizable | NSViewMinYMargin)];
		if (g_ganttPeriodText) {
			[periodLabel setStringValue:
				[NSString stringWithUTF8String:g_ganttPeriodText]];
		} else {
			[periodLabel setStringValue:@""];
		}
		g_ganttPeriodLabel = periodLabel;
		[contentView addSubview:periodLabel];

		// Segmented control (right side): Week | Month.
		NSSegmentedControl *segCtrl = [NSSegmentedControl
			segmentedControlWithLabels:@[@"Week", @"Month"]
			trackingMode:NSSegmentSwitchTrackingSelectOne
			target:g_ganttNavDelegate
			action:@selector(viewModeChanged:)];
		[segCtrl setFrame:NSMakeRect(winW - 160, winH - toolbarH + 10, 150, 24)];
		[segCtrl setSelectedSegment:g_ganttViewMode];
		[segCtrl setAutoresizingMask:(NSViewMinXMargin | NSViewMinYMargin)];
		g_ganttSegCtrl = segCtrl;
		[contentView addSubview:segCtrl];

		// ---- Separator ----
		NSBox *separator = [[NSBox alloc] initWithFrame:
			NSMakeRect(0, winH - toolbarH, winW, 1)];
		[separator setBoxType:NSBoxSeparator];
		[separator setAutoresizingMask:(NSViewWidthSizable | NSViewMinYMargin)];
		[contentView addSubview:separator];

		// ---- Scroll view + Chart view ----
		CGFloat chartAreaH = winH - toolbarH;
		NSScrollView *scrollView = [[NSScrollView alloc] initWithFrame:
			NSMakeRect(0, 0, winW, chartAreaH)];
		[scrollView setHasVerticalScroller:YES];
		[scrollView setHasHorizontalScroller:NO];
		[scrollView setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
		[scrollView setBorderType:NSNoBorder];
		g_ganttScrollView = scrollView;

		GanttView *chartView = [[GanttView alloc] initWithFrame:
			NSMakeRect(0, 0, winW, chartAreaH)];
		[chartView setAutoresizingMask:NSViewWidthSizable];
		g_ganttChartView = chartView;

		[scrollView setDocumentView:chartView];
		[contentView addSubview:scrollView];

		// Size chart to content.
		reloadGanttChartUI();

		[window makeKeyAndOrderFront:nil];
		[NSApp activateIgnoringOtherApps:YES];
	});
}

*/
import "C"
import (
	"unsafe"
)

// GanttProject holds per-project data for the Gantt chart.
type GanttProject struct {
	Name   string
	Total  string // formatted duration, e.g. "2h 15m"
	ColorR float32
	ColorG float32
	ColorB float32
}

// GanttSession holds one session bar for the Gantt chart.
type GanttSession struct {
	ProjectIndex int
	Start        float64 // Unix epoch seconds
	End          float64 // Unix epoch seconds
	IsActive     bool
	IsInferred   bool // true for observation-inferred reverse time blocks
}

// GanttData holds all data needed to render the Gantt chart.
type GanttData struct {
	Projects    []GanttProject
	Sessions    []GanttSession
	PeriodStart float64 // Unix epoch seconds
	PeriodEnd   float64 // Unix epoch seconds
	DayLabels   []string
	PeriodLabel string
	ViewMode    int // 0=week, 1=month
}

// ShowTimeTrackerWindow opens (or brings to front) the Gantt chart Time Tracker
// window, populated with the given data.
func ShowTimeTrackerWindow(data GanttData) {
	C.clearGanttData()

	for _, p := range data.Projects {
		cName := C.CString(p.Name)
		cTotal := C.CString(p.Total)
		C.addGanttProject(cName, cTotal, C.float(p.ColorR), C.float(p.ColorG), C.float(p.ColorB))
		C.free(unsafe.Pointer(cName))
		C.free(unsafe.Pointer(cTotal))
	}

	for _, s := range data.Sessions {
		active := 0
		if s.IsActive {
			active = 1
		}
		inferred := 0
		if s.IsInferred {
			inferred = 1
		}
		C.addGanttSession(C.int(s.ProjectIndex), C.double(s.Start), C.double(s.End), C.int(active), C.int(inferred))
	}

	cLabel := C.CString(data.PeriodLabel)
	C.setGanttPeriod(C.double(data.PeriodStart), C.double(data.PeriodEnd), cLabel, C.int(data.ViewMode))
	C.free(unsafe.Pointer(cLabel))

	for _, dl := range data.DayLabels {
		cDL := C.CString(dl)
		C.addGanttDayLabel(cDL)
		C.free(unsafe.Pointer(cDL))
	}

	if C.isGanttWindowOpen() != 0 {
		C.reloadGanttChart()
	} else {
		C.showGanttWindow()
	}
}

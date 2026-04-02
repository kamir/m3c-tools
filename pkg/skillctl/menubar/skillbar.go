//go:build darwin

// Package menubar provides a macOS menu bar application for monitoring
// the Claude Code skill inventory. It runs periodic scans, computes
// deltas against the latest sealed inventory, and offers a review UI.
package menubar

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/caseymrm/menuet"
	"github.com/kamir/m3c-tools/pkg/skillctl/delta"
	"github.com/kamir/m3c-tools/pkg/skillctl/model"
	"github.com/kamir/m3c-tools/pkg/skillctl/report"
	"github.com/kamir/m3c-tools/pkg/skillctl/scanner"
)

// SkillBarStatus represents the current operational state.
type SkillBarStatus string

const (
	SkillBarIdle     SkillBarStatus = "idle"
	SkillBarScanning SkillBarStatus = "scanning"
	SkillBarChanges  SkillBarStatus = "changes"
	SkillBarError    SkillBarStatus = "error"
)

// SealRecord is a lightweight summary of a sealed inventory for menu display.
type SealRecord struct {
	Date       string
	SkillCount int
}

// SkillBar is the menu bar app for skill inventory monitoring.
type SkillBar struct {
	mu           sync.Mutex
	status       SkillBarStatus
	lastScan     *model.Inventory
	lastScanTime time.Time
	pendingDelta *delta.DeltaReport
	scanPaths    []string
	scanInterval time.Duration
	includeHome  bool
	scanError    string
	reviewAddr   string

	// Seal history for display.
	sealHistory []SealRecord

	// Web UI server reference (started on demand).
	reviewServer *http.Server
}

// New creates a SkillBar with the given configuration.
func New(paths []string, interval time.Duration, includeHome bool) *SkillBar {
	return &SkillBar{
		status:       SkillBarIdle,
		scanPaths:    paths,
		scanInterval: interval,
		includeHome:  includeHome,
	}
}

// Run configures the menuet application and starts the macOS run loop.
// This function blocks forever and must be called from the main goroutine.
func (sb *SkillBar) Run() {
	// Start the background scan scheduler.
	go sb.startScheduler()

	mApp := menuet.App()
	mApp.Name = "SkillMonitor"
	mApp.Label = "com.m3c-tools.skill-monitor"
	mApp.Children = sb.menuItems

	state := &menuet.MenuState{Title: sb.menuTitle()}
	mApp.SetMenuState(state)

	mApp.RunApplication()
}

// --- Thread-safe state accessors ---

func (sb *SkillBar) setStatus(s SkillBarStatus) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.status = s
	sb.updateMenuTitle()
}

func (sb *SkillBar) getStatus() SkillBarStatus {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.status
}

func (sb *SkillBar) setLastScan(inv *model.Inventory) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.lastScan = inv
	sb.lastScanTime = time.Now()
}

func (sb *SkillBar) getLastScan() (*model.Inventory, time.Time) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.lastScan, sb.lastScanTime
}

func (sb *SkillBar) setPendingDelta(d *delta.DeltaReport) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.pendingDelta = d
}

func (sb *SkillBar) getPendingDelta() *delta.DeltaReport {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.pendingDelta
}

func (sb *SkillBar) setScanError(err string) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.scanError = err
}

func (sb *SkillBar) getScanError() string {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.scanError
}

func (sb *SkillBar) setSealHistory(records []SealRecord) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.sealHistory = make([]SealRecord, len(records))
	copy(sb.sealHistory, records)
}

func (sb *SkillBar) getSealHistory() []SealRecord {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	out := make([]SealRecord, len(sb.sealHistory))
	copy(out, sb.sealHistory)
	return out
}

// --- Menu title ---

func (sb *SkillBar) menuTitle() string {
	// Must be called with lock held or during init.
	switch sb.status {
	case SkillBarScanning:
		return "\u27F3" // ⟳
	case SkillBarChanges:
		count := 0
		if sb.pendingDelta != nil {
			count = sb.pendingDelta.Summary.Total
		}
		if count > 0 {
			return fmt.Sprintf("\u26A1%d", count)
		}
		return "\u26A1" // ⚡
	case SkillBarError:
		return "\u26A0" // ⚠
	default:
		return "\u26A1" // ⚡
	}
}

func (sb *SkillBar) updateMenuTitle() {
	// Called with lock held — compute title and schedule update.
	title := sb.menuTitle()
	go func() {
		menuet.App().SetMenuState(&menuet.MenuState{Title: title})
	}()
}

// --- Menu construction ---

func (sb *SkillBar) menuItems() []menuet.MenuItem {
	status := sb.getStatus()
	inv, scanTime := sb.getLastScan()
	scanErr := sb.getScanError()
	pendingDelta := sb.getPendingDelta()

	var items []menuet.MenuItem

	// Title
	items = append(items, menuet.MenuItem{
		Text: "\u25C9 Skill Monitor",
	})
	items = append(items, menuet.MenuItem{Type: menuet.Separator})

	// Status line
	statusText := "Status: Idle"
	switch status {
	case SkillBarScanning:
		statusText = "Status: Scanning..."
	case SkillBarChanges:
		if pendingDelta != nil {
			statusText = fmt.Sprintf("Status: %d Changes Detected", pendingDelta.Summary.Total)
		} else {
			statusText = "Status: Changes Detected"
		}
	case SkillBarError:
		statusText = "Status: Error"
	}
	items = append(items, menuet.MenuItem{Text: statusText})

	// Last scan line
	if !scanTime.IsZero() && inv != nil {
		ago := time.Since(scanTime).Round(time.Second)
		agoStr := formatDuration(ago)
		items = append(items, menuet.MenuItem{
			Text: fmt.Sprintf("Last scan: %s ago (%d skills)", agoStr, inv.TotalCount),
		})
	} else {
		items = append(items, menuet.MenuItem{Text: "Last scan: (none)"})
	}

	// Error detail
	if scanErr != "" {
		items = append(items, menuet.MenuItem{Text: fmt.Sprintf("\u26A0 %s", scanErr)})
	}

	items = append(items, menuet.MenuItem{Type: menuet.Separator})

	// Actions
	items = append(items, menuet.MenuItem{
		Text: "\u27F3 Rescan Now",
		Clicked: func() {
			go sb.runScan()
		},
	})
	items = append(items, menuet.MenuItem{
		Text: "\U0001F4CB View Report",
		Clicked: func() {
			go sb.openReport()
		},
	})

	// Review Changes — only if changes detected
	if status == SkillBarChanges && pendingDelta != nil {
		items = append(items, menuet.MenuItem{
			Text: "\U0001F50D Review Changes...",
			Clicked: func() {
				go sb.openReviewUI()
			},
		})
	}

	items = append(items, menuet.MenuItem{Type: menuet.Separator})

	// Seal History submenu
	items = append(items, sb.buildSealHistoryMenu())

	items = append(items, menuet.MenuItem{Type: menuet.Separator})

	// Settings submenu
	items = append(items, sb.buildSettingsMenu())

	items = append(items, menuet.MenuItem{Type: menuet.Separator})

	// Quit
	items = append(items, menuet.MenuItem{
		Text: "Quit",
		Clicked: func() {
			sb.shutdown()
			os.Exit(0)
		},
	})

	return items
}

func (sb *SkillBar) buildSealHistoryMenu() menuet.MenuItem {
	return menuet.MenuItem{
		Text: "Seal History",
		Children: func() []menuet.MenuItem {
			history := sb.getSealHistory()
			if len(history) == 0 {
				return []menuet.MenuItem{{Text: "(no seals yet)"}}
			}
			var items []menuet.MenuItem
			for i, rec := range history {
				label := "Previous"
				if i == 0 {
					label = "Latest"
				}
				items = append(items, menuet.MenuItem{
					Text: fmt.Sprintf("%s: %s (%d skills)", label, rec.Date, rec.SkillCount),
				})
			}
			return items
		},
	}
}

func (sb *SkillBar) buildSettingsMenu() menuet.MenuItem {
	return menuet.MenuItem{
		Text: "Settings",
		Children: func() []menuet.MenuItem {
			sb.mu.Lock()
			interval := sb.scanInterval
			paths := make([]string, len(sb.scanPaths))
			copy(paths, sb.scanPaths)
			home := sb.includeHome
			sb.mu.Unlock()

			items := []menuet.MenuItem{
				{Text: fmt.Sprintf("Scan interval: %s", interval)},
			}
			for _, p := range paths {
				items = append(items, menuet.MenuItem{Text: fmt.Sprintf("Watch: %s", p)})
			}
			if home {
				items = append(items, menuet.MenuItem{Text: "Watch: ~/.claude/ (home)"})
			}
			return items
		},
	}
}

// --- Background scheduler ---

func (sb *SkillBar) startScheduler() {
	// Run initial scan immediately.
	sb.runScan()

	ticker := time.NewTicker(sb.scanInterval)
	defer ticker.Stop()

	for range ticker.C {
		sb.runScan()
	}
}

// --- Scan execution ---

func (sb *SkillBar) runScan() {
	sb.setStatus(SkillBarScanning)
	sb.setScanError("")

	sc := &scanner.Scanner{
		Paths:       sb.scanPaths,
		Recursive:   true,
		IncludeHome: sb.includeHome,
	}

	inv, err := sc.Scan()
	if err != nil {
		log.Printf("[skillbar] scan error: %v", err)
		sb.setScanError(err.Error())
		sb.setStatus(SkillBarError)
		return
	}

	sb.setLastScan(inv)

	// Try to compute delta against latest seal.
	// delta package may provide LoadLatestSeal or similar.
	// For now, we attempt to load and compare.
	dr, deltaErr := sb.computeDelta(inv)
	if deltaErr != nil {
		// No seal to compare against — treat as clean.
		log.Printf("[skillbar] delta: %v (treating as no changes)", deltaErr)
		sb.setPendingDelta(nil)
		sb.setStatus(SkillBarIdle)
		return
	}

	if dr != nil && dr.Summary.Total > 0 {
		sb.setPendingDelta(dr)
		sb.setStatus(SkillBarChanges)
		log.Printf("[skillbar] %d changes detected", dr.Summary.Total)
	} else {
		sb.setPendingDelta(nil)
		sb.setStatus(SkillBarIdle)
		log.Printf("[skillbar] scan complete: %d skills, no changes", inv.TotalCount)
	}
}

// computeDelta attempts to load the latest seal and compute a delta report.
// Returns nil, error if no seal is available.
func (sb *SkillBar) computeDelta(current *model.Inventory) (*delta.DeltaReport, error) {
	store, err := delta.NewSealStore()
	if err != nil {
		return nil, fmt.Errorf("open seal store: %w", err)
	}

	_, baseline, err := store.LatestSeal()
	if err != nil {
		return nil, fmt.Errorf("load latest seal: %w", err)
	}
	if baseline == nil {
		return nil, fmt.Errorf("no seals found")
	}

	dr := delta.ComputeDelta(baseline, current)

	// Update seal history for menu display.
	seals, _ := store.ListSeals()
	var records []SealRecord
	for _, s := range seals {
		records = append(records, SealRecord{
			Date:       s.SealedAt,
			SkillCount: s.SkillCount,
		})
	}
	sb.setSealHistory(records)

	return dr, nil
}

// --- Report generation ---

func (sb *SkillBar) openReport() {
	inv, _ := sb.getLastScan()
	if inv == nil {
		sb.showNotification("Skill Monitor", "No scan data available. Run a scan first.")
		return
	}

	// Generate HTML report to a temp file.
	tmpFile, err := os.CreateTemp("", "skillctl-report-*.html")
	if err != nil {
		log.Printf("[skillbar] create temp file: %v", err)
		sb.showNotification("Skill Monitor", fmt.Sprintf("Error creating report: %v", err))
		return
	}

	if err := report.GenerateHTML(tmpFile, inv); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		log.Printf("[skillbar] generate HTML: %v", err)
		sb.showNotification("Skill Monitor", fmt.Sprintf("Error generating report: %v", err))
		return
	}
	tmpFile.Close()

	// Open in default browser.
	if err := exec.Command("open", tmpFile.Name()).Start(); err != nil {
		log.Printf("[skillbar] open browser: %v", err)
		sb.showNotification("Skill Monitor", fmt.Sprintf("Error opening report: %v", err))
	}
}

// --- Review UI ---

func (sb *SkillBar) openReviewUI() {
	sb.mu.Lock()
	srv := sb.reviewServer
	addr := sb.reviewAddr
	sb.mu.Unlock()

	if srv == nil {
		// Start a new review server on a random port.
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			log.Printf("[skillbar] listen: %v", err)
			sb.showNotification("Skill Monitor", fmt.Sprintf("Error starting review server: %v", err))
			return
		}
		addr = listener.Addr().String()

		mux := http.NewServeMux()
		mux.HandleFunc("/", sb.handleReviewPage)

		srv = &http.Server{Handler: mux}

		sb.mu.Lock()
		sb.reviewServer = srv
		sb.reviewAddr = addr
		sb.mu.Unlock()

		go func() {
			if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
				log.Printf("[skillbar] review server: %v", err)
			}
		}()

		log.Printf("[skillbar] review UI started at http://%s", addr)
	}

	// Open in default browser.
	url := fmt.Sprintf("http://%s", addr)
	if err := exec.Command("open", url).Start(); err != nil {
		log.Printf("[skillbar] open browser: %v", err)
	}
}

func (sb *SkillBar) handleReviewPage(w http.ResponseWriter, r *http.Request) {
	pendingDelta := sb.getPendingDelta()
	inv, scanTime := sb.getLastScan()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	var buf bytes.Buffer
	buf.WriteString("<!DOCTYPE html>\n<html><head><title>Skill Monitor - Review Changes</title>\n")
	buf.WriteString("<style>")
	buf.WriteString("body{font-family:system-ui,-apple-system,sans-serif;max-width:900px;margin:40px auto;padding:0 20px;background:#1a1a2e;color:#e0e0e0;}")
	buf.WriteString("h1{color:#a78bfa;}h2{color:#c4b5fd;border-bottom:1px solid #333;padding-bottom:8px;}")
	buf.WriteString("table{width:100%;border-collapse:collapse;margin:16px 0;}th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #333;}")
	buf.WriteString("th{background:#2a2a4a;color:#a78bfa;}.added{color:#4ade80;}.removed{color:#f87171;}.changed{color:#fbbf24;}")
	buf.WriteString(".badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.85em;}")
	buf.WriteString(".badge-add{background:#166534;color:#4ade80;}.badge-remove{background:#7f1d1d;color:#f87171;}.badge-change{background:#78350f;color:#fbbf24;}")
	buf.WriteString(".meta{color:#888;font-size:0.9em;margin-bottom:24px;}")
	buf.WriteString("</style></head><body>\n")
	buf.WriteString("<h1>\u26A1 Skill Monitor - Review Changes</h1>\n")

	if inv != nil {
		buf.WriteString(fmt.Sprintf("<p class=\"meta\">Last scan: %s | Total skills: %d</p>\n",
			scanTime.Format("2006-01-02 15:04:05"), inv.TotalCount))
	}

	if pendingDelta == nil {
		buf.WriteString("<p>No changes detected.</p>\n")
	} else {
		buf.WriteString(fmt.Sprintf("<h2>Summary: %d changes</h2>\n", pendingDelta.Summary.Total))

		// Group entries by delta type for display.
		var added, removed, modified []delta.DeltaEntry
		for _, e := range pendingDelta.Entries {
			switch e.DeltaType {
			case delta.DeltaAdded:
				added = append(added, e)
			case delta.DeltaRemoved:
				removed = append(removed, e)
			case delta.DeltaModified, delta.DeltaMoved:
				modified = append(modified, e)
			}
		}

		if len(added) > 0 {
			buf.WriteString("<h2 class=\"added\">Added Skills</h2>\n<table><tr><th>ID</th><th>Name</th><th>Path</th></tr>\n")
			for _, e := range added {
				buf.WriteString(fmt.Sprintf("<tr><td><span class=\"badge badge-add\">%s</span></td><td>%s</td><td>%s</td></tr>\n",
					e.SkillID, e.SkillName, e.CurrentPath))
			}
			buf.WriteString("</table>\n")
		}

		if len(removed) > 0 {
			buf.WriteString("<h2 class=\"removed\">Removed Skills</h2>\n<table><tr><th>ID</th><th>Name</th><th>Path</th></tr>\n")
			for _, e := range removed {
				buf.WriteString(fmt.Sprintf("<tr><td><span class=\"badge badge-remove\">%s</span></td><td>%s</td><td>%s</td></tr>\n",
					e.SkillID, e.SkillName, e.BaselinePath))
			}
			buf.WriteString("</table>\n")
		}

		if len(modified) > 0 {
			buf.WriteString("<h2 class=\"changed\">Changed Skills</h2>\n<table><tr><th>ID</th><th>Name</th><th>Change</th></tr>\n")
			for _, e := range modified {
				changeDesc := string(e.DeltaType)
				if e.ContentDiff != "" {
					changeDesc = e.ContentDiff
				}
				buf.WriteString(fmt.Sprintf("<tr><td><span class=\"badge badge-change\">%s</span></td><td>%s</td><td>%s</td></tr>\n",
					e.SkillID, e.SkillName, changeDesc))
			}
			buf.WriteString("</table>\n")
		}
	}

	buf.WriteString("</body></html>")
	w.Write(buf.Bytes())
}

// --- Utilities ---

func (sb *SkillBar) showNotification(title, message string) {
	menuet.App().Notification(menuet.Notification{
		Title:   title,
		Message: message,
	})
}

func (sb *SkillBar) shutdown() {
	sb.mu.Lock()
	srv := sb.reviewServer
	sb.mu.Unlock()

	if srv != nil {
		srv.Close()
	}
}

// formatDuration returns a human-readable duration string.
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
}

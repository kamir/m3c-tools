package menubar

import (
	"fmt"
	"log"
	"time"

	"github.com/caseymrm/menuet"
)

// TimeTrackingProject represents a project available for time tracking.
type TimeTrackingProject struct {
	ID        string
	Name      string
	Client    string
	UpdatedAt time.Time
}

// TimeTrackingEngine is the interface the menubar uses to interact with
// the time tracking system. Implemented by timetracking.Engine.
type TimeTrackingEngine interface {
	Toggle(projectID, projectName string) error
	IsActive(projectID string) bool
	ActiveProjects() []string
}

// TimeTrackingState holds the current time tracking state for menu rendering.
type TimeTrackingState struct {
	Projects    []TimeTrackingProject
	TodaySummary map[string]time.Duration // project_id -> total today
	Error       string
	LastRefresh time.Time
}

// SetTimeEngine sets the time tracking engine for the app.
func (a *App) SetTimeEngine(engine TimeTrackingEngine) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.timeEngine = engine
}

// GetTimeEngine returns the current time tracking engine, or nil.
func (a *App) GetTimeEngine() TimeTrackingEngine {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.timeEngine
}

// timeTrackingProjects holds the cached project list for the menu.
// Updated by the project list refresher goroutine.
var (
	ttProjects    []TimeTrackingProject
	ttSummary     map[string]time.Duration
	ttLastRefresh time.Time
)

// SetTimeTrackingProjects updates the cached project list for menu rendering.
func SetTimeTrackingProjects(projects []TimeTrackingProject) {
	ttProjects = projects
	ttLastRefresh = time.Now()
}

// SetTimeTrackingSummary updates the cached today summary for menu rendering.
func SetTimeTrackingSummary(summary map[string]time.Duration) {
	ttSummary = summary
}

// buildProjectsMenu constructs the "Projects" submenu for time tracking.
func (a *App) buildProjectsMenu() menuet.MenuItem {
	engine := a.GetTimeEngine()

	title := "📂 Projects"
	activeCount := 0
	if engine != nil {
		activeCount = len(engine.ActiveProjects())
	}
	if activeCount > 0 {
		title = fmt.Sprintf("📂 Projects (%d active)", activeCount)
	}

	return menuet.MenuItem{
		Text: title,
		Children: func() []menuet.MenuItem {
			if engine == nil {
				return []menuet.MenuItem{
					{Text: "Time tracking not available"},
				}
			}

			var items []menuet.MenuItem

			if len(ttProjects) == 0 {
				items = append(items, menuet.MenuItem{Text: "No projects loaded"})
				if ttLastRefresh.IsZero() {
					items = append(items, menuet.MenuItem{Text: "Waiting for project list..."})
				}
				return items
			}

			// Project toggles.
			for _, p := range ttProjects {
				proj := p // capture
				isActive := engine.IsActive(proj.ID)
				indicator := "○"
				if isActive {
					indicator = "●"
				}
				label := fmt.Sprintf("%s %s", indicator, proj.Name)
				if proj.Client != "" {
					label = fmt.Sprintf("%s %s (%s)", indicator, proj.Name, proj.Client)
				}

				items = append(items, menuet.MenuItem{
					Text: label,
					Clicked: func() {
						if err := engine.Toggle(proj.ID, proj.Name); err != nil {
							log.Printf("[timetracking] toggle failed project=%s: %v", proj.ID, err)
						}
					},
				})
			}

			// Separator + today summary.
			items = append(items, menuet.MenuItem{Type: menuet.Separator})

			if len(ttSummary) > 0 {
				for _, p := range ttProjects {
					if dur, ok := ttSummary[p.ID]; ok && dur > 0 {
						items = append(items, menuet.MenuItem{
							Text: fmt.Sprintf("Today: %s %s", p.Name, formatDuration(dur)),
						})
					}
				}
			} else {
				items = append(items, menuet.MenuItem{Text: "No activity today"})
			}

			// Show Time Tracker entry (opens Gantt chart window).
			items = append(items, menuet.MenuItem{Type: menuet.Separator})
			items = append(items, menuet.MenuItem{
				Text: "Show Time Tracker...",
				Clicked: func() {
					if fn := a.getShowTimeTracker(); fn != nil {
						go fn()
					} else {
						log.Printf("[timetracking] Gantt chart view not yet wired")
					}
				},
			})

			return items
		},
	}
}

func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}

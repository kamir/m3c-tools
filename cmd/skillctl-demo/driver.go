package main

// driver.go — the event model, the fan-out bus (CLI renderer + SSE browsers),
// and the Driver that walks the scenarios one step at a time.
//
// There is exactly ONE driver running the real skillctl. The web page is a
// passive MIRROR: it subscribes to the same event stream the terminal renders.

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// Event is the single message type on the bus. It is JSON-marshalled verbatim
// onto the SSE channel and rendered to the terminal by the CLI.
type Event struct {
	Kind string `json:"kind"` // ready|scenario|step|prep|cmd|line|exit|verdict|note|reset|done

	// scenario-header fields
	ID      string `json:"id,omitempty"`
	Title   string `json:"title,omitempty"`
	Tier    string `json:"tier,omitempty"` // LIVE | PARTIAL | ROADMAP
	SVG     string `json:"svg,omitempty"`
	Story   string `json:"story,omitempty"`
	Without string `json:"without,omitempty"`
	Roadmap string `json:"roadmap,omitempty"`
	ExitDoc string `json:"exit_doc,omitempty"` // human "expected exit" summary

	// step / line / exit fields
	Text     string `json:"text,omitempty"`
	Stream   string `json:"stream,omitempty"` // stdout | stderr
	Cmd      string `json:"cmd,omitempty"`
	Code     int    `json:"code"`
	Expected int    `json:"expected,omitempty"`
	Verdict  string `json:"verdict,omitempty"` // blocked | allowed | refused
	OK       bool   `json:"ok,omitempty"`      // did the observed exit match expectation?

	// kata-board fields (Kind "beat"): the local mastery state after a rep.
	State    string `json:"state,omitempty"`    // rot | gelb | gruen
	Reps     int    `json:"reps,omitempty"`     // distinct clean reps so far
	Required int    `json:"required,omitempty"` // reps needed for grün (sitzt)
	Rusting  bool   `json:"rusting,omitempty"`  // banked but freshness lapsed
	Added    bool   `json:"added,omitempty"`    // did this rep advance the distinct count?
}

// Emitter receives events. The Bus fans out to every registered emitter.
type Emitter interface{ Emit(Event) }

// Bus fans out to a terminal renderer plus any number of SSE subscribers, and
// keeps a replay history so a browser that connects mid-run sees prior events.
type Bus struct {
	mu       sync.Mutex
	subs     map[chan Event]struct{}
	history  []Event
	renderer *CLIRenderer
	taps     []func(Event)
}

// AddTap registers a synchronous observer of every event (used by --selftest to
// tally exit-code assertions). Called under the bus lock, so taps must not emit.
func (b *Bus) AddTap(fn func(Event)) {
	b.mu.Lock()
	b.taps = append(b.taps, fn)
	b.mu.Unlock()
}

func NewBus(r *CLIRenderer) *Bus {
	return &Bus{subs: make(map[chan Event]struct{}), renderer: r}
}

func (b *Bus) Emit(e Event) {
	b.mu.Lock()
	b.history = append(b.history, e)
	if b.renderer != nil {
		b.renderer.Render(e)
	}
	for ch := range b.subs {
		select {
		case ch <- e:
		default: // slow subscriber: drop rather than block the driver
		}
	}
	for _, t := range b.taps {
		t(e)
	}
	b.mu.Unlock()
}

// Subscribe returns a buffered channel plus a snapshot of history for replay.
func (b *Bus) Subscribe() (chan Event, []Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan Event, 256)
	b.subs[ch] = struct{}{}
	hist := make([]Event, len(b.history))
	copy(hist, b.history)
	return ch, hist
}

func (b *Bus) Unsubscribe(ch chan Event) {
	b.mu.Lock()
	delete(b.subs, ch)
	b.mu.Unlock()
}

// Driver walks the scenarios against the real skillctl.
type Driver struct {
	sb   *Sandbox
	run  *Runner
	bus  *Bus
	wait func() // pause between steps (Enter in guided, sleep in kiosk)
	last RunResult
}

func (d *Driver) scenario(s *Scenario) {
	d.bus.Emit(Event{
		Kind: "scenario", ID: s.ID, Title: s.Title, Tier: s.Tier,
		SVG: s.SVG, Story: s.Story, Without: s.Without, Roadmap: s.Roadmap, ExitDoc: s.ExitDoc,
	})
}

func (d *Driver) step(text string) {
	d.bus.Emit(Event{Kind: "step", Text: text})
}

func (d *Driver) note(text string) {
	d.bus.Emit(Event{Kind: "note", Text: text})
}

// prep runs a sandbox mutation (install / tamper / drift) and narrates it. A
// failure is surfaced as a note and returned so the caller can abort the step.
func (d *Driver) prep(text string, fn func() error) error {
	d.bus.Emit(Event{Kind: "prep", Text: text})
	if err := fn(); err != nil {
		d.note("sandbox error: " + err.Error())
		return err
	}
	return nil
}

// exec runs skillctl, streams its output, and emits the exit + verdict badge.
// expected is the exit code the scenario asserts; verdict is the human label
// (blocked/allowed/refused). Returns the full result for callers that parse it.
func (d *Driver) exec(expected int, verdict, stdin string, args ...string) RunResult {
	d.bus.Emit(Event{Kind: "cmd", Cmd: "skillctl " + strings.Join(args, " ")})
	res := d.run.Run(func(stream, line string) {
		d.bus.Emit(Event{Kind: "line", Stream: stream, Text: line})
	}, stdin, args...)
	if res.Err != nil {
		d.note("exec error: " + res.Err.Error())
	}
	ok := res.ExitCode == expected
	d.bus.Emit(Event{
		Kind: "exit", Code: res.ExitCode, Expected: expected, Verdict: verdict, OK: ok,
	})
	d.last = res
	return res
}

// jsonField pulls a top-level string field out of a skillctl --json stdout blob.
func jsonField(stdout, field string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(stdout), &m); err != nil {
		return ""
	}
	if v, ok := m[field].(string); ok {
		return v
	}
	return ""
}

// sweepVerdict extracts the per-skill trust verdict for one skill from a
// `verify --all --json` report: its state and numeric exit code. The sweep's own
// PROCESS exit is 0 by design; the enforcing verdict lives in the entry.
func sweepVerdict(stdout, skill string) (state string, code int, found bool) {
	var rep struct {
		Entries []struct {
			Skill string `json:"skill"`
			State string `json:"state"`
			Exit  int    `json:"exit"`
		} `json:"entries"`
	}
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		return "", 0, false
	}
	for _, e := range rep.Entries {
		if e.Skill == skill {
			return e.State, e.Exit, true
		}
	}
	return "", 0, false
}

func hookEvent(skill string) string {
	return fmt.Sprintf(`{"tool_name":"Skill","tool_input":{"skill":%q},"session_id":"demo"}`, skill)
}

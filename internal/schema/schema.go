// Package schema defines the Raijin Schema, the JSON shape every Raijin tool returns.
package schema

// Result is the top-level object a Raijin tool writes to stdout.
type Result struct {
	Tool     string         `json:"tool"`
	Version  string         `json:"version"`
	Target   string         `json:"target"`
	Summary  string         `json:"summary"`
	Findings []Finding      `json:"findings"`
	Groups   []Group        `json:"groups"`
	Omitted  map[string]int `json:"omitted"`
	Errors   []Error        `json:"errors"`
	Next     []string       `json:"next"`
	Budget   Budget         `json:"budget"`
}

// Finding is one deduplicated issue, collapsed across every host where it matched.
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	Hosts       []string `json:"hosts"`
	HostsCount  int      `json:"hosts_count"`
	Evidence    string   `json:"evidence"`
	EngineRef   string   `json:"engine_ref"`
	Fingerprint string   `json:"fingerprint"`
	New         bool     `json:"new,omitempty"`
}

// Group is something that repeats and is not worth a finding of its own (for example tech detection).
type Group struct {
	ID       string   `json:"id"`
	Count    int      `json:"count"`
	Examples []string `json:"examples"`
}

// Error is a problem during the run, with a hint about what to try next.
type Error struct {
	Kind string `json:"kind"`
	Hint string `json:"hint"`
}

// Budget reports the output limits that were applied.
type Budget struct {
	MaxItems  int  `json:"max_items"`
	MaxBytes  int  `json:"max_bytes"`
	Truncated bool `json:"truncated"`
}

// SeverityRank orders severities from most to least important.
var SeverityRank = map[string]int{
	"critical": 5,
	"high":     4,
	"medium":   3,
	"low":      2,
	"info":     1,
	"unknown":  0,
}

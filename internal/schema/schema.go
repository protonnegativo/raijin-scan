// Package schema defines the Raijin Schema, the JSON shape every Raijin tool returns.
//
// Anything an agent can rebuild is left out of the JSON to save tokens: empty lists, the budget when
// nothing was cut, a hosts_count equal to the hosts listed, and fields at their documented default.
package schema

import "encoding/json"

// Result is the top-level object a Raijin tool writes to stdout.
type Result struct {
	Tool     string         `json:"tool"`
	Version  string         `json:"version"`
	Target   string         `json:"target"`
	Summary  string         `json:"summary"`
	Findings []Finding      `json:"findings"`
	Groups   []Group        `json:"groups"`
	Omitted  map[string]int `json:"omitted,omitempty"`
	Errors   []Error        `json:"errors,omitempty"`
	Next     []string       `json:"next,omitempty"`
	Budget   Budget         `json:"budget"`
}

// MarshalJSON writes the budget only when something was cut.
func (r Result) MarshalJSON() ([]byte, error) {
	type plain Result
	out := struct {
		plain
		Budget *Budget `json:"budget,omitempty"`
	}{plain: plain(r)}
	if r.Budget.Truncated {
		out.Budget = &r.Budget
	}
	return json.Marshal(out)
}

// Finding is one deduplicated issue, collapsed across every host where it matched.
// The same tool and ID in two runs is the same finding.
type Finding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	// Confidence is "verified" or "heuristic"; empty means "matched".
	Confidence string   `json:"confidence,omitempty"`
	Hosts      []string `json:"hosts"`
	// HostsCount is written only when it is larger than len(Hosts).
	HostsCount int    `json:"hosts_count,omitempty"`
	Evidence   string `json:"evidence"`
	// EngineRef is written only when the engine rule is not the ID's prefix before ':'.
	EngineRef string `json:"engine_ref,omitempty"`
	// Fingerprint is the internal key for --state; it is derived from the ID and not written.
	Fingerprint string `json:"-"`
	New         bool   `json:"new,omitempty"`
}

// MarshalJSON leaves out hosts_count when every host is listed.
func (f Finding) MarshalJSON() ([]byte, error) {
	type plain Finding
	p := plain(f)
	if p.HostsCount <= len(p.Hosts) {
		p.HostsCount = 0
	}
	return json.Marshal(p)
}

// Group is something that repeats and is not worth a finding of its own (for example tech detection).
type Group struct {
	ID       string   `json:"id"`
	Count    int      `json:"count"`
	Examples []string `json:"examples,omitempty"`
	Variants []string `json:"variants,omitempty"`
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

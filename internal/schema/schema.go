// Package schema defines the Raijin Schema, the JSON shape every Raijin tool returns.
//
// Nothing the engine found is dropped silently: every finding and every location where it matched is
// listed, and anything a budget cuts is counted in Omitted. What an agent can rebuild is left out of the
// JSON to save tokens: empty lists, the budget when nothing was cut, a count equal to the locations
// listed, and fields at their documented default.
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
	// Raw is the file with the engine's full output, for details the result leaves out.
	Raw    string `json:"raw,omitempty"`
	Budget Budget `json:"budget"`
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

// Finding is one deduplicated issue with every location where it matched.
// The same tool and ID in two runs is the same finding.
type Finding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	// Confidence is "verified" or "heuristic"; empty means "matched".
	Confidence string   `json:"confidence,omitempty"`
	CVE        []string `json:"cve,omitempty"`
	CVSS       float64  `json:"cvss,omitempty"`
	// Locations are the exact places it matched, each with the values extracted there.
	Locations []string `json:"locations"`
	// Count is the number of locations; it is written only when the budget cut Locations.
	Count int `json:"count,omitempty"`
	// EngineRef is written only when the engine rule is not the ID's prefix before ':'.
	EngineRef string `json:"engine_ref,omitempty"`
	// Fingerprint is the internal key for --state; it is derived from the ID and not written.
	Fingerprint string `json:"-"`
	New         bool   `json:"new,omitempty"`
}

// MarshalJSON leaves out count when every location is listed.
func (f Finding) MarshalJSON() ([]byte, error) {
	type plain Finding
	p := plain(f)
	if p.Count <= len(p.Locations) {
		p.Count = 0
	}
	return json.Marshal(p)
}

// Group is info-level output collapsed per template: every variant listed matched every location listed.
// A template whose variants matched different locations becomes one group per set of locations.
type Group struct {
	ID        string   `json:"id"`
	Variants  []string `json:"variants,omitempty"`
	Locations []string `json:"locations,omitempty"`
	// Count is the number of locations; it is written only when the budget cut Locations.
	Count int `json:"count,omitempty"`
}

// MarshalJSON leaves out count when every location is listed.
func (g Group) MarshalJSON() ([]byte, error) {
	type plain Group
	p := plain(g)
	if p.Count <= len(p.Locations) {
		p.Count = 0
	}
	return json.Marshal(p)
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

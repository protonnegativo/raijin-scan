// Package schema defines the Raijin Schema, the JSON shape every Raijin tool returns.
//
// The envelope (Result, Error, Budget, Marshal and the rank tables) lives in raijin-core; this package
// keeps what is specific to raijin-scan: Finding and Group.
//
// Nothing the engine found is dropped silently: every finding and every location where it matched is
// listed, and anything a budget cuts is counted in Omitted. What an agent can rebuild is left out of the
// JSON to save tokens: empty lists, the budget when nothing was cut, a count equal to the locations
// listed, and fields at their documented default.
package schema

import core "github.com/protonnegativo/raijin-core/schema"

type (
	// Result is the top-level object a Raijin tool writes to stdout.
	Result = core.Result[Finding, Group]
	Error  = core.Error
	Budget = core.Budget
)

var (
	Marshal        = core.Marshal
	Write          = core.Write
	SeverityRank   = core.SeverityRank
	ConfidenceRank = core.ConfidenceRank
)

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
	p.Count = core.OmitCount(p.Count, len(p.Locations))
	return core.Marshal(p)
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
	p.Count = core.OmitCount(p.Count, len(p.Locations))
	return core.Marshal(p)
}

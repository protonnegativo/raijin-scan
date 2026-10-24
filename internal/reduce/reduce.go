// Package reduce turns raw nuclei events into a small, ranked Raijin result.
//
// It is lossless for what an agent acts on: every finding and every location where it matched is
// kept. Only exact duplicates collapse. A byte budget can cut, but every cut is counted in omitted.
package reduce

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/protonnegativo/raijin-scan/internal/nuclei"
	"github.com/protonnegativo/raijin-scan/internal/schema"
)

// Options control what the reducer keeps.
type Options struct {
	MaxItems    int // 0 keeps every finding
	MaxBytes    int
	MaxLocation int // longest location string, extracted values included
	IncludeInfo bool
	InScope     func(host string) bool
}

// Defaults keep every finding and cap the JSON at a size that fits comfortably in an agent's context.
func Defaults() Options {
	return Options{MaxBytes: 16000, MaxLocation: 300}
}

type bucket struct {
	finding  schema.Finding
	template string
	locs     map[string]bool
	cves     map[string]bool
}

// Reduce collapses events into findings (one per template and matcher) and info groups.
// It also returns every location per finding fingerprint, before any budget, for --state.
func Reduce(events []nuclei.Event, opt Options) ([]schema.Finding, []schema.Group, map[string]int, map[string][]string) {
	omitted := map[string]int{}
	buckets := map[string]*bucket{}
	var keys []string

	for _, ev := range events {
		host := ev.Host
		if host == "" {
			host = ev.MatchedAt
		}
		if opt.InScope != nil && !opt.InScope(host) {
			omitted["out_of_scope"]++
			continue
		}
		sev := strings.ToLower(ev.Info.Severity)
		if _, ok := schema.SeverityRank[sev]; !ok {
			sev = "unknown"
		}
		key := ev.TemplateID
		if ev.MatcherName != "" {
			key += ":" + ev.MatcherName
		}
		b, ok := buckets[key]
		if !ok {
			b = &bucket{
				finding: schema.Finding{
					ID:          key,
					Title:       ev.Info.Name,
					Severity:    sev,
					CVSS:        ev.CVSS(),
					Fingerprint: fingerprint(key),
				},
				template: ev.TemplateID,
				locs:     map[string]bool{},
				cves:     map[string]bool{},
			}
			buckets[key] = b
			keys = append(keys, key)
		}
		for _, c := range ev.Info.Classification.CVEID {
			b.cves[strings.ToUpper(c)] = true
		}
		loc := Location(ev, opt.MaxLocation)
		if b.locs[loc] {
			omitted["duplicates"]++
			continue
		}
		b.locs[loc] = true
	}

	findings := []schema.Finding{}
	allLocations := map[string][]string{}
	// info: template -> variant (matcher name) -> locations
	infos := map[string]map[string][]string{}
	var infoOrder []string
	for _, key := range keys {
		b := buckets[key]
		locs := sorted(b.locs)
		if b.finding.Severity == "info" && !opt.IncludeInfo {
			v, ok := infos[b.template]
			if !ok {
				v = map[string][]string{}
				infos[b.template] = v
				infoOrder = append(infoOrder, b.template)
			}
			v[strings.TrimPrefix(strings.TrimPrefix(key, b.template), ":")] = locs
			continue
		}
		f := b.finding
		f.CVE = sorted(b.cves)
		if len(f.CVE) == 0 || (len(f.CVE) == 1 && f.CVE[0] == strings.ToUpper(b.template)) {
			f.CVE = nil // none, or the ID already says it
		}
		f.Locations = locs
		f.Count = len(locs)
		allLocations[f.Fingerprint] = locs
		findings = append(findings, f)
	}

	groups := []schema.Group{}
	for _, tmpl := range infoOrder {
		groups = append(groups, infoGroups(tmpl, infos[tmpl])...)
	}

	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if schema.SeverityRank[a.Severity] != schema.SeverityRank[b.Severity] {
			return schema.SeverityRank[a.Severity] > schema.SeverityRank[b.Severity]
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.ID < b.ID
	})
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].Count != groups[j].Count {
			return groups[i].Count > groups[j].Count
		}
		return groups[i].ID < groups[j].ID
	})

	if opt.MaxItems > 0 && len(findings) > opt.MaxItems {
		omitted["findings"] += len(findings) - opt.MaxItems
		findings = findings[:opt.MaxItems]
	}
	return findings, groups, omitted, allLocations
}

// infoGroups collapses one template's info matches. Variants that matched exactly the same locations
// share a group, so a location is not repeated per variant and no variant/location pair is lost.
func infoGroups(tmpl string, variants map[string][]string) []schema.Group {
	bySet := map[string]*schema.Group{}
	var order []string
	names := make([]string, 0, len(variants))
	for v := range variants {
		names = append(names, v)
	}
	sort.Strings(names)
	for _, v := range names {
		locs := variants[v]
		k := strings.Join(locs, "\n")
		g, ok := bySet[k]
		if !ok {
			g = &schema.Group{ID: tmpl, Locations: locs, Count: len(locs)}
			bySet[k] = g
			order = append(order, k)
		}
		if v != "" {
			g.Variants = append(g.Variants, v)
		}
	}
	out := make([]schema.Group, 0, len(order))
	for _, k := range order {
		out = append(out, *bySet[k])
	}
	return out
}

// Location is where an event matched, with the values extracted there: "url [a, b]".
func Location(ev nuclei.Event, max int) string {
	s := ev.MatchedAt
	if s == "" {
		s = ev.Host
	}
	if len(ev.ExtractedResults) > 0 {
		s += " [" + strings.Join(ev.ExtractedResults, ", ") + "]"
	}
	return trim(s, max)
}

// Fit shrinks the result until its JSON is at most maxBytes. It cuts the least important data first:
// info group locations, then info groups, then the locations of the lowest-ranked findings (each keeps
// one, and its count), then the lowest-ranked findings. Every cut is counted in Omitted.
func Fit(res *schema.Result, maxBytes int) {
	if maxBytes <= 0 || size(res) <= maxBytes {
		return
	}
	res.Budget.Truncated = true
	if res.Omitted == nil {
		res.Omitted = map[string]int{}
	}
	total := size(res) // now includes the budget object
	for i := len(res.Groups) - 1; i >= 0 && total > maxBytes; i-- {
		g := &res.Groups[i]
		before := size(g)
		res.Omitted["locations"] += len(g.Locations)
		g.Locations = nil
		total += size(g) - before
	}
	for total > maxBytes && len(res.Groups) > 0 {
		last := len(res.Groups) - 1
		total -= size(res.Groups[last]) + 1
		res.Groups = res.Groups[:last]
		res.Omitted["groups"]++
	}
	for i := len(res.Findings) - 1; i >= 0 && total > maxBytes; i-- {
		f := &res.Findings[i]
		if len(f.Locations) <= 1 {
			continue
		}
		before := size(f)
		res.Omitted["locations"] += len(f.Locations) - 1
		f.Locations = f.Locations[:1]
		total += size(f) - before
	}
	for total > maxBytes && len(res.Findings) > 1 {
		last := len(res.Findings) - 1
		total -= size(res.Findings[last]) + 1
		res.Findings = res.Findings[:last]
		res.Omitted["findings"]++
	}
	// the estimate above ignores the omitted counters it adds; settle on the real size
	for size(res) > maxBytes && len(res.Findings) > 1 {
		res.Findings = res.Findings[:len(res.Findings)-1]
		res.Omitted["findings"]++
	}
}

func size(v any) int {
	b, _ := json.Marshal(v)
	return len(b)
}

func sorted(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func fingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}

func trim(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

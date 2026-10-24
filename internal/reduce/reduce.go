// Package reduce turns raw nuclei events into a small, ranked Raijin result.
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

// Options control how much output the reducer keeps.
type Options struct {
	MaxItems         int
	MaxBytes         int
	MaxHostExamples  int
	MaxGroups        int
	MaxGroupExamples int
	MaxEvidence      int
	IncludeInfo      bool
	InScope          func(host string) bool
}

// Defaults are sized for an agent's context: a few KB of JSON.
func Defaults() Options {
	return Options{
		MaxItems:         20,
		MaxBytes:         8000,
		MaxHostExamples:  5,
		MaxGroups:        10,
		MaxGroupExamples: 3,
		MaxEvidence:      300,
	}
}

type bucket struct {
	finding  schema.Finding
	hosts    map[string]bool
	order    []string
	evidence string
	template string
}

// Reduce collapses events into findings (one per template and matcher) and groups (info-level noise).
// It also returns every host per finding fingerprint, before any truncation, for diffing.
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
				hosts: map[string]bool{},
				finding: schema.Finding{
					ID:          key,
					Title:       ev.Info.Name,
					Severity:    sev,
					Fingerprint: fingerprint(key),
				},
				evidence: Evidence(ev, opt.MaxEvidence),
				template: ev.TemplateID,
			}
			buckets[key] = b
			keys = append(keys, key)
		}
		if b.hosts[host] {
			omitted["duplicates"]++
			continue
		}
		b.hosts[host] = true
		b.order = append(b.order, host)
	}

	findings := []schema.Finding{}
	groups := []schema.Group{}
	allHosts := map[string][]string{}
	// info matches are grouped per template: all matchers of one template become one group
	type infoGroup struct {
		hosts    map[string]bool
		variants []string
	}
	infos := map[string]*infoGroup{}
	var infoOrder []string
	for _, key := range keys {
		b := buckets[key]
		hosts := append([]string(nil), b.order...)
		sort.Strings(hosts)
		if b.finding.Severity == "info" && !opt.IncludeInfo {
			tmpl := b.template
			g, ok := infos[tmpl]
			if !ok {
				g = &infoGroup{hosts: map[string]bool{}}
				infos[tmpl] = g
				infoOrder = append(infoOrder, tmpl)
			}
			for _, h := range hosts {
				g.hosts[h] = true
			}
			if v := strings.TrimPrefix(key, tmpl+":"); v != key {
				g.variants = append(g.variants, v)
			}
			continue
		}
		f := b.finding
		allHosts[f.Fingerprint] = hosts
		f.HostsCount = len(hosts)
		f.Hosts = firstN(hosts, opt.MaxHostExamples)
		f.Evidence = b.evidence
		findings = append(findings, f)
	}

	for _, tmpl := range infoOrder {
		g := infos[tmpl]
		hosts := make([]string, 0, len(g.hosts))
		for h := range g.hosts {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		sort.Strings(g.variants)
		groups = append(groups, schema.Group{ID: tmpl, Count: len(hosts), Examples: firstN(hosts, opt.MaxGroupExamples), Variants: g.variants})
	}

	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if schema.SeverityRank[a.Severity] != schema.SeverityRank[b.Severity] {
			return schema.SeverityRank[a.Severity] > schema.SeverityRank[b.Severity]
		}
		if a.HostsCount != b.HostsCount {
			return a.HostsCount > b.HostsCount
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
		omitted["budget"] += len(findings) - opt.MaxItems
		findings = findings[:opt.MaxItems]
	}
	if opt.MaxGroups > 0 && len(groups) > opt.MaxGroups {
		omitted["groups"] += len(groups) - opt.MaxGroups
		groups = groups[:opt.MaxGroups]
	}
	return findings, groups, omitted, allHosts
}

// Evidence builds the minimal proof for an event: where it matched and what was extracted.
func Evidence(ev nuclei.Event, max int) string {
	parts := []string{ev.MatchedAt}
	if ev.MatcherName != "" {
		parts = append(parts, "matcher="+ev.MatcherName)
	}
	if len(ev.ExtractedResults) > 0 {
		parts = append(parts, "extracted="+strings.Join(firstN(ev.ExtractedResults, 3), ", "))
	}
	return trim(strings.Join(parts, " "), max)
}

// Fit shrinks the result until its JSON is at most MaxBytes: first host and group examples, then the lowest-ranked findings.
func Fit(res *schema.Result, maxBytes int) {
	if maxBytes <= 0 || size(res) <= maxBytes {
		return
	}
	res.Budget.Truncated = true
	for i := range res.Findings {
		res.Findings[i].Hosts = firstN(res.Findings[i].Hosts, 1)
	}
	for i := range res.Groups {
		res.Groups[i].Examples = nil
		res.Groups[i].Variants = firstN(res.Groups[i].Variants, 3)
	}
	for size(res) > maxBytes && len(res.Groups) > 0 {
		res.Groups = res.Groups[:len(res.Groups)-1]
		res.Omitted["groups"]++
	}
	for size(res) > maxBytes && len(res.Findings) > 1 {
		res.Findings = res.Findings[:len(res.Findings)-1]
		res.Omitted["budget"]++
	}
}

func size(res *schema.Result) int {
	b, _ := json.Marshal(res)
	return len(b)
}

func fingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}

func firstN(s []string, n int) []string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n]
}

func trim(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

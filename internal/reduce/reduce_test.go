package reduce

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/protonnegativo/raijin-scan/internal/nuclei"
	"github.com/protonnegativo/raijin-scan/internal/schema"
	"github.com/protonnegativo/raijin-scan/internal/scope"
)

func load(t *testing.T) []nuclei.Event {
	t.Helper()
	f, err := os.Open("../../testdata/sample.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	events, err := nuclei.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func ev(tmpl, matcher, sev, at string) nuclei.Event {
	e := nuclei.Event{TemplateID: tmpl, MatcherName: matcher, MatchedAt: at, Host: strings.SplitN(strings.TrimPrefix(at, "https://"), "/", 2)[0]}
	e.Info.Severity = sev
	return e
}

func TestReduce(t *testing.T) {
	events := load(t)
	if len(events) != 8 {
		t.Fatalf("parsed %d events, want 8 (the non-JSON line is skipped)", len(events))
	}
	sc, _ := scope.Parse([]string{"*.example.com"})
	opt := Defaults()
	opt.InScope = sc.Allowed

	findings, groups, omitted, all := Reduce(events, opt)

	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(findings), findings)
	}
	// high sorts before medium
	env, git := findings[0], findings[1]
	if env.ID != "exposed-env" || git.ID != "git-config" {
		t.Errorf("order = %s, %s", env.ID, git.ID)
	}
	if strings.Join(git.Locations, ",") != "https://a.example.com/.git/config,https://b.example.com/.git/config" {
		t.Errorf("git-config locations = %v", git.Locations)
	}
	if len(env.Locations) != 1 || env.Locations[0] != "https://b.example.com/.env [DB_PASSWORD=x, APP_KEY=y, AWS_KEY=z, EXTRA=w]" {
		t.Errorf("every extracted value should be kept with its location: %q", env.Locations)
	}
	if len(groups) != 1 || groups[0].ID != "tech-detect" || len(groups[0].Locations) != 3 || strings.Join(groups[0].Variants, ",") != "nginx" {
		t.Errorf("groups = %+v", groups)
	}
	if omitted["duplicates"] != 1 || omitted["out_of_scope"] != 1 {
		t.Errorf("omitted = %v", omitted)
	}
	if len(all[git.Fingerprint]) != 2 {
		t.Errorf("locations for git-config = %v", all[git.Fingerprint])
	}
}

// Two URLs on the same host are two locations, not a duplicate.
func TestSameHostDifferentURLsAreKept(t *testing.T) {
	events := []nuclei.Event{
		ev("exposed-env", "", "high", "https://a.example.com/.env"),
		ev("exposed-env", "", "high", "https://a.example.com/app/.env"),
		ev("exposed-env", "", "high", "https://a.example.com/.env"),
	}
	findings, _, omitted, _ := Reduce(events, Defaults())
	if len(findings) != 1 || len(findings[0].Locations) != 2 {
		t.Fatalf("findings = %+v", findings)
	}
	if omitted["duplicates"] != 1 {
		t.Errorf("only the repeated URL is a duplicate: %v", omitted)
	}
}

// Variants that hit the same locations share a group; a variant with other locations gets its own,
// so every variant/location pair survives.
func TestInfoGroupsKeepEveryVariantLocationPair(t *testing.T) {
	var events []nuclei.Event
	for _, m := range []string{"x-frame-options", "content-security-policy"} {
		for _, h := range []string{"a", "b"} {
			events = append(events, ev("http-missing-security-headers", m, "info", "https://"+h))
		}
	}
	events = append(events, ev("http-missing-security-headers", "strict-transport-security", "info", "https://a"))

	findings, groups, _, _ := Reduce(events, Defaults())
	if findings == nil || len(findings) != 0 {
		t.Errorf("findings should be an empty, non-nil slice: %#v", findings)
	}
	if len(groups) != 2 {
		t.Fatalf("want 2 groups (two location sets), got %+v", groups)
	}
	got := map[string]string{}
	for _, g := range groups {
		if g.ID != "http-missing-security-headers" {
			t.Errorf("group id = %s", g.ID)
		}
		got[strings.Join(g.Variants, ",")] = strings.Join(g.Locations, ",")
	}
	if got["content-security-policy,x-frame-options"] != "https://a,https://b" || got["strict-transport-security"] != "https://a" {
		t.Errorf("variant/location pairs = %v", got)
	}
}

func TestIncludeInfoAndMaxItems(t *testing.T) {
	opt := Defaults()
	opt.IncludeInfo = true
	opt.MaxItems = 1
	findings, groups, omitted, _ := Reduce(load(t), opt)
	if len(findings) != 1 || findings[0].ID != "exposed-env" {
		t.Errorf("findings = %+v", findings)
	}
	if len(groups) != 0 {
		t.Errorf("with IncludeInfo there should be no groups: %+v", groups)
	}
	// without a scope filter: exposed-env, git-config, tech-detect:nginx -> 2 cut by MaxItems
	if omitted["findings"] != 2 {
		t.Errorf("omitted = %v", omitted)
	}
}

func TestCVEAndCVSS(t *testing.T) {
	lines := `{"template-id":"CVE-2021-44228","matched-at":"https://a/x","info":{"severity":"critical","classification":{"cve-id":["cve-2021-44228"],"cvss-score":10}}}
{"template-id":"log4j-rce","matched-at":"https://a/y","info":{"severity":"critical","classification":{"cve-id":"CVE-2021-44228","cvss-score":"9.8"}}}
{"template-id":"odd-meta","matched-at":"https://a/z","info":{"severity":"high","classification":{"cve-id":{"x":1},"cvss-score":null}}}`
	events, _ := nuclei.Parse(strings.NewReader(lines))
	if len(events) != 3 {
		t.Fatalf("odd classification values must not drop events: parsed %d", len(events))
	}
	findings, _, _, _ := Reduce(events, Defaults())
	byID := map[string]schema.Finding{}
	for _, f := range findings {
		byID[f.ID] = f
	}
	if f := byID["CVE-2021-44228"]; f.CVE != nil || f.CVSS != 10 {
		t.Errorf("a CVE equal to the id is not repeated: %+v", f)
	}
	if f := byID["log4j-rce"]; strings.Join(f.CVE, ",") != "CVE-2021-44228" || f.CVSS != 9.8 {
		t.Errorf("log4j-rce = %+v", f)
	}
	if f := byID["odd-meta"]; f.CVE != nil || f.CVSS != 0 {
		t.Errorf("odd-meta = %+v", f)
	}
}

func TestLocationIsTrimmed(t *testing.T) {
	e := nuclei.Event{MatchedAt: "https://x/" + strings.Repeat("a", 500)}
	if got := Location(e, 300); len(got) != 300 || !strings.HasSuffix(got, "...") {
		t.Errorf("len = %d, suffix ok = %v", len(got), strings.HasSuffix(got, "..."))
	}
}

func TestFitCutsLeastImportantFirstAndCountsEverything(t *testing.T) {
	res := &schema.Result{Omitted: map[string]int{}, Budget: schema.Budget{MaxBytes: 3000}}
	var locs []string
	for i := 0; i < 20; i++ {
		locs = append(locs, fmt.Sprintf("https://host%02d.example.com/.git/config", i))
	}
	for i := 0; i < 5; i++ {
		res.Findings = append(res.Findings, schema.Finding{ID: fmt.Sprintf("f%d", i), Severity: "high", Locations: locs, Count: len(locs)})
	}
	res.Groups = []schema.Group{{ID: "tech-detect", Locations: locs, Count: len(locs)}}

	Fit(res, 3000)
	b, _ := json.Marshal(res)
	if len(b) > 3000 {
		t.Errorf("size %d > 3000", len(b))
	}
	if !res.Budget.Truncated {
		t.Error("truncation not reported")
	}
	if len(res.Groups) == 1 && res.Groups[0].Locations != nil {
		t.Error("group locations should go before any finding data")
	}
	if len(res.Findings) == 0 || len(res.Findings[0].Locations) != 20 {
		t.Errorf("the top finding should keep its locations while lower data can be cut: %+v", res.Findings)
	}
	if !strings.Contains(string(b), `"count":20`) {
		t.Errorf("a finding or group that lost locations must show its count: %s", b)
	}
	// every location that is not in the output is counted
	shown := 0
	for _, f := range res.Findings {
		shown += len(f.Locations)
	}
	for _, g := range res.Groups {
		shown += len(g.Locations)
	}
	cutFindings := 5 - len(res.Findings)
	cutGroups := 1 - len(res.Groups)
	if res.Omitted["findings"] != cutFindings || res.Omitted["groups"] != cutGroups {
		t.Errorf("omitted = %v, cut %d findings and %d groups", res.Omitted, cutFindings, cutGroups)
	}
	if res.Omitted["locations"]+shown < 20*len(res.Findings)+20*len(res.Groups) {
		t.Errorf("locations not accounted for: omitted=%v shown=%d", res.Omitted, shown)
	}
}

package reduce

import (
	"encoding/json"
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

func TestReduce(t *testing.T) {
	events := load(t)
	if len(events) != 8 {
		t.Fatalf("parsed %d events, want 8 (the non-JSON line is skipped)", len(events))
	}
	sc, _ := scope.Parse([]string{"*.example.com"})
	opt := Defaults()
	opt.InScope = sc.Allowed

	findings, groups, omitted, allHosts := Reduce(events, opt)

	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(findings), findings)
	}
	// high sorts before medium
	if findings[0].ID != "exposed-env" || findings[1].ID != "git-config" {
		t.Errorf("order = %s, %s", findings[0].ID, findings[1].ID)
	}
	git := findings[1]
	if git.HostsCount != 2 || strings.Join(git.Hosts, ",") != "a.example.com,b.example.com" {
		t.Errorf("git-config hosts = %v (%d)", git.Hosts, git.HostsCount)
	}
	if !strings.Contains(findings[0].Evidence, "extracted=DB_PASSWORD=x, APP_KEY=y, AWS_KEY=z") || strings.Contains(findings[0].Evidence, "EXTRA") {
		t.Errorf("evidence should keep the first 3 extracted values: %q", findings[0].Evidence)
	}
	if len(groups) != 1 || groups[0].ID != "tech-detect:nginx" || groups[0].Count != 3 || len(groups[0].Examples) != 3 {
		t.Errorf("groups = %+v", groups)
	}
	if omitted["duplicates"] != 1 || omitted["out_of_scope"] != 1 {
		t.Errorf("omitted = %v", omitted)
	}
	if len(allHosts[git.Fingerprint]) != 2 {
		t.Errorf("allHosts for git-config = %v", allHosts[git.Fingerprint])
	}
}

func TestReduceIncludeInfoAndMaxItems(t *testing.T) {
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
	if omitted["budget"] != 2 {
		t.Errorf("omitted = %v", omitted)
	}
}

func TestEvidenceIsTrimmed(t *testing.T) {
	ev := nuclei.Event{MatchedAt: "https://x/" + strings.Repeat("a", 500)}
	if got := Evidence(ev, 300); len(got) != 300 || !strings.HasSuffix(got, "...") {
		t.Errorf("len = %d, suffix ok = %v", len(got), strings.HasSuffix(got, "..."))
	}
}

func TestFit(t *testing.T) {
	res := &schema.Result{Omitted: map[string]int{}}
	for i := 0; i < 50; i++ {
		res.Findings = append(res.Findings, schema.Finding{ID: strings.Repeat("x", 100), Hosts: []string{"a", "b", "c"}})
	}
	Fit(res, 2000)
	b, _ := json.Marshal(res)
	if len(b) > 2000 {
		t.Errorf("size %d > 2000", len(b))
	}
	if !res.Budget.Truncated || res.Omitted["budget"] == 0 {
		t.Errorf("truncation not reported: %+v %v", res.Budget, res.Omitted)
	}
	if len(res.Findings[0].Hosts) != 1 {
		t.Errorf("host examples should shrink to 1 first")
	}
}

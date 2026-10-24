package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDerivableFieldsAreLeftOut(t *testing.T) {
	res := Result{
		Tool:     "raijin-scan",
		Findings: []Finding{{ID: "git-config", Hosts: []string{"a", "b"}, HostsCount: 2, Fingerprint: "fp"}},
		Groups:   []Group{{ID: "tech-detect", Count: 4}},
		Omitted:  map[string]int{},
		Errors:   []Error{},
		Next:     []string{},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000},
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"fingerprint", "hosts_count", "confidence", "engine_ref", "omitted", "errors", "next", "budget", "examples", "null"} {
		if strings.Contains(string(b), k) {
			t.Errorf("%s should be left out: %s", k, b)
		}
	}
}

func TestCountAndBudgetAppearWhenSomethingIsCut(t *testing.T) {
	res := Result{
		Findings: []Finding{{ID: "git-config", Hosts: []string{"a"}, HostsCount: 7}},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000, Truncated: true},
	}
	b, _ := json.Marshal(res)
	if !strings.Contains(string(b), `"hosts_count":7`) || !strings.Contains(string(b), `"budget":{"max_items":20,"max_bytes":8000,"truncated":true}`) {
		t.Errorf("hosts_count and budget must be written when something was cut: %s", b)
	}
	if strings.Count(string(b), "budget") != 1 {
		t.Errorf("budget written twice: %s", b)
	}
}

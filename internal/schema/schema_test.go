package schema

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestDerivableFieldsAreLeftOut(t *testing.T) {
	res := Result{
		Tool:     "raijin-scan",
		Findings: []Finding{{ID: "git-config", Locations: []string{"https://a/.git/config", "https://b/.git/config"}, Count: 2, Fingerprint: "fp"}},
		Groups:   []Group{{ID: "tech-detect", Locations: []string{"https://a"}, Count: 1}},
		Omitted:  map[string]int{},
		Errors:   []Error{},
		Next:     []string{},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000},
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"fingerprint", "count", "confidence", "engine_ref", "cve", "cvss", "omitted", "errors", "next", "raw", "budget", "variants"} {
		if strings.Contains(string(b), `"`+k+`"`) {
			t.Errorf("%s should be left out: %s", k, b)
		}
	}
	if strings.Contains(string(b), "null") {
		t.Errorf("no null values: %s", b)
	}
}

func TestCountAndBudgetAppearWhenSomethingIsCut(t *testing.T) {
	res := Result{
		Findings: []Finding{{ID: "git-config", Locations: []string{"https://a/.git/config"}, Count: 7}},
		Groups:   []Group{{ID: "tech-detect", Count: 4}},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000, Truncated: true},
	}
	b, _ := json.Marshal(res)
	s := string(b)
	if !strings.Contains(s, `"locations":["https://a/.git/config"],"count":7`) || !strings.Contains(s, `{"id":"tech-detect","count":4}`) {
		t.Errorf("count must be written when locations were cut: %s", s)
	}
	if !strings.Contains(s, `"budget":{"max_items":20,"max_bytes":8000,"truncated":true}`) || strings.Count(s, "budget") != 1 {
		t.Errorf("budget must be written once when something was cut: %s", s)
	}
}

func TestSchemaVersionIsFirstField(t *testing.T) {
	b, err := json.Marshal(Result{Tool: "raijin-scan"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(b), `{"schema_version":1,"tool":"raijin-scan"`) {
		t.Errorf("schema_version must come first: %s", b)
	}
}

// Before raijin-core, raijin-scan wrote & < > in finding strings as & < >.
func TestHTMLCharactersAreNotEscaped(t *testing.T) {
	res := Result{
		Findings: []Finding{{ID: "a", Title: "A & B <c>", Locations: []string{"https://a/?x=1&y=<2>"}}},
		Groups:   []Group{{ID: "g", Variants: []string{"a&b"}, Locations: []string{"https://a/?x=1&y=2"}}},
	}
	// Write is what the tool's output path uses; encoding/json alone would escape again.
	var buf bytes.Buffer
	if err := Write(&buf, &res, false); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	if strings.Contains(s, `\u00`) {
		t.Errorf("& < > must be written as themselves: %s", s)
	}
	for _, want := range []string{`"title":"A & B <c>"`, `https://a/?x=1&y=<2>`, `"a&b"`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in %s", want, s)
		}
	}
}

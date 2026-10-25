package nuclei

import (
	"strings"
	"testing"
)

func TestEngines(t *testing.T) {
	engines, err := Engines()
	if err != nil {
		t.Fatal(err)
	}
	e, ok := engines["nuclei"]
	if !ok || e.Go == "" {
		t.Fatalf("engines.json has no nuclei entry with a go module: %+v", engines)
	}
	if _, ok := ParseVersion(e.Version); !ok {
		t.Fatalf("unparseable tested version %q", e.Version)
	}
}

func TestParseVersion(t *testing.T) {
	// real `nuclei -version -duc` output (stderr), v3.3.9
	out := "[INF] Nuclei Engine Version: v3.3.9\n[INF] Nuclei Config Directory: /root/.config/nuclei\n[INF] Nuclei Cache Directory: /root/.cache/nuclei\n[INF] PDCP Directory: /root/.pdcp\n"
	v, ok := ParseVersion(out)
	if !ok || v != [3]int{3, 3, 9} {
		t.Fatalf("got %v %v", v, ok)
	}
	if v, ok := ParseVersion("\x1b[34mINF\x1b[0m] Nuclei Engine Version: v3.11.1"); !ok || v != [3]int{3, 11, 1} {
		t.Fatalf("colored: got %v %v", v, ok)
	}
	if _, ok := ParseVersion("flag provided but not defined: -version"); ok {
		t.Fatal("parsed a version from an error")
	}
}

func TestUntested(t *testing.T) {
	tested := [3]int{3, 3, 9}
	for _, c := range []struct {
		v    [3]int
		want bool
	}{
		{[3]int{3, 3, 9}, false},
		{[3]int{3, 3, 10}, false},
		{[3]int{3, 11, 1}, false},
		{[3]int{3, 3, 8}, true},
		{[3]int{3, 2, 12}, true},
		{[3]int{2, 9, 15}, true},
		{[3]int{4, 0, 0}, true},
	} {
		if got := Untested(c.v, tested); got != c.want {
			t.Errorf("Untested(%v) = %v, want %v", c.v, got, c.want)
		}
	}
}

func TestFormatCheck(t *testing.T) {
	good := `{"template-id":"git-config","host":"a","matched-at":"https://a/.git/config"}`
	// matched-at renamed, and a line that is not JSON
	renamed := `{"template-id":"git-config","host":"b","matched_at":"https://b/.git/config"}`
	events, st, err := ParseStats(strings.NewReader(good + "\n" + renamed + "\nnot json\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || st.Lines != 3 || st.Bad != 2 || st.Dropped != 1 {
		t.Fatalf("events=%d stats=%+v", len(events), st)
	}
	h := st.FormatHint("/tmp/raw.jsonl")
	if !strings.HasPrefix(h, "2 of 3 nuclei results had no template-id or matched-at") || !strings.HasSuffix(h, "Read /tmp/raw.jsonl for the full output") {
		t.Fatalf("hint %q", h)
	}
	if _, st, _ := ParseStats(strings.NewReader(good + "\n")); st.FormatHint("x") != "" {
		t.Fatal("hint on good output")
	}
}

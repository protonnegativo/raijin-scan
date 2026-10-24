package state

import (
	"path/filepath"
	"testing"

	"github.com/protonnegativo/raijin-scan/internal/schema"
)

func TestMarkAcrossRuns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")

	st, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	first := []schema.Finding{{ID: "git-config", Fingerprint: "fp1"}}
	if n := st.Mark(first, map[string][]string{"fp1": {"a"}}); n != 1 || !first[0].New {
		t.Fatalf("first run: n=%d new=%v", n, first[0].New)
	}
	if err := st.Save(path); err != nil {
		t.Fatal(err)
	}

	st, _ = Load(path)
	same := []schema.Finding{{ID: "git-config", Fingerprint: "fp1"}}
	if n := st.Mark(same, map[string][]string{"fp1": {"a"}}); n != 0 || same[0].New {
		t.Errorf("same finding on the same host should not be new: n=%d", n)
	}

	newHost := []schema.Finding{{ID: "git-config", Fingerprint: "fp1"}}
	if n := st.Mark(newHost, map[string][]string{"fp1": {"a", "b"}}); n != 1 || !newHost[0].New {
		t.Errorf("a new host should mark the finding as new: n=%d", n)
	}
}

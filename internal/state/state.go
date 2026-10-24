// Package state remembers findings between runs so a rerun can mark what is new.
package state

import (
	"encoding/json"
	"errors"
	"os"
	"sort"

	"github.com/protonnegativo/raijin-scan/internal/schema"
)

// State maps a finding fingerprint to the locations it was seen at.
type State struct {
	Seen map[string][]string `json:"seen"`
}

// Load reads a state file. A missing file is an empty state.
func Load(path string) (*State, error) {
	s := &State{Seen: map[string][]string{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, err
	}
	if s.Seen == nil {
		s.Seen = map[string][]string{}
	}
	return s, nil
}

// Mark flags findings that are new, or that appeared at a location not seen before, and records them. It returns how many are new.
func (s *State) Mark(findings []schema.Finding, allHosts map[string][]string) int {
	n := 0
	for i := range findings {
		fp := findings[i].Fingerprint
		known := map[string]bool{}
		for _, h := range s.Seen[fp] {
			known[h] = true
		}
		hosts := allHosts[fp]
		for _, h := range hosts {
			if !known[h] {
				findings[i].New = true
				known[h] = true
			}
		}
		if findings[i].New {
			n++
		}
		merged := make([]string, 0, len(known))
		for h := range known {
			merged = append(merged, h)
		}
		sort.Strings(merged)
		s.Seen[fp] = merged
	}
	return n
}

// Save writes the state file.
func (s *State) Save(path string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

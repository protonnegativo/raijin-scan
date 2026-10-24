// Package nuclei runs the nuclei binary and parses its JSONL output.
package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// ErrNotFound is returned when the nuclei binary is not on PATH.
var ErrNotFound = errors.New("nuclei binary not found")

// Event is the subset of a nuclei JSONL result that Raijin uses.
type Event struct {
	TemplateID       string   `json:"template-id"`
	MatcherName      string   `json:"matcher-name"`
	Host             string   `json:"host"`
	MatchedAt        string   `json:"matched-at"`
	ExtractedResults []string `json:"extracted-results"`
	Type             string   `json:"type"`
	Info             struct {
		Name           string   `json:"name"`
		Severity       string   `json:"severity"`
		Tags           []string `json:"tags"`
		Classification struct {
			CVEID     StringList      `json:"cve-id"`
			CVSSScore json.RawMessage `json:"cvss-score"`
		} `json:"classification"`
	} `json:"info"`
}

// StringList decodes a JSON array of strings, a single string or null. Anything else decodes as empty,
// so an odd value in template metadata never drops the event.
type StringList []string

func (l *StringList) UnmarshalJSON(b []byte) error {
	var many []string
	if json.Unmarshal(b, &many) == nil {
		*l = many
		return nil
	}
	var one string
	if json.Unmarshal(b, &one) == nil && one != "" {
		*l = []string{one}
	}
	return nil
}

// CVSS returns the event's CVSS score, or 0 if it has none. nuclei writes it as a number or a string.
func (e Event) CVSS() float64 {
	b := e.Info.Classification.CVSSScore
	var f float64
	if json.Unmarshal(b, &f) == nil {
		return f
	}
	var s string
	if json.Unmarshal(b, &s) == nil {
		fmt.Sscan(s, &f)
	}
	return f
}

// Options are the nuclei settings Raijin passes through.
type Options struct {
	Binary    string
	Templates []string
	Tags      string
	Severity  string
	Rate      int
	Timeout   int
	Extra     []string
	// RawPath, if set, receives nuclei's JSONL output unchanged.
	RawPath string
}

// Run scans the targets and returns every event, plus the last stderr lines if nuclei failed.
func Run(ctx context.Context, targets []string, opt Options) ([]Event, string, error) {
	bin := opt.Binary
	if bin == "" {
		bin = "nuclei"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return nil, "", ErrNotFound
	}

	list, err := os.CreateTemp("", "raijin-scan-targets-*.txt")
	if err != nil {
		return nil, "", err
	}
	defer os.Remove(list.Name())
	if _, err := io.WriteString(list, strings.Join(targets, "\n")+"\n"); err != nil {
		list.Close()
		return nil, "", err
	}
	list.Close()

	cmd := exec.CommandContext(ctx, path, Args(list.Name(), opt)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, "", err
	}
	var r io.Reader = stdout
	if opt.RawPath != "" {
		raw, err := os.Create(opt.RawPath)
		if err != nil {
			return nil, "", err
		}
		defer raw.Close()
		r = io.TeeReader(stdout, raw)
	}
	if err := cmd.Start(); err != nil {
		return nil, "", err
	}
	events, parseErr := Parse(r)
	waitErr := cmd.Wait()
	if parseErr != nil {
		return events, tail(stderr.String(), 3), parseErr
	}
	if waitErr != nil {
		return events, tail(stderr.String(), 3), fmt.Errorf("nuclei exited: %w", waitErr)
	}
	return events, "", nil
}

// Args builds the nuclei command line.
func Args(listFile string, opt Options) []string {
	args := []string{"-l", listFile, "-jsonl", "-silent", "-omit-raw", "-no-color", "-duc"}
	for _, t := range opt.Templates {
		args = append(args, "-t", t)
	}
	if opt.Tags != "" {
		args = append(args, "-tags", opt.Tags)
	}
	if opt.Severity != "" {
		args = append(args, "-severity", opt.Severity)
	}
	if opt.Rate > 0 {
		args = append(args, "-rl", fmt.Sprint(opt.Rate))
	}
	if opt.Timeout > 0 {
		args = append(args, "-timeout", fmt.Sprint(opt.Timeout))
	}
	return append(args, opt.Extra...)
}

// Parse reads nuclei JSONL. Lines that are not JSON objects are skipped.
func Parse(r io.Reader) ([]Event, error) {
	var events []Event
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}
		if ev.TemplateID == "" {
			continue
		}
		events = append(events, ev)
	}
	return events, sc.Err()
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

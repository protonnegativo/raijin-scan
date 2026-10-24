// Command raijin-scan runs nuclei and returns a small, deduplicated, ranked result for AI agents.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"github.com/protonnegativo/raijin-scan/internal/banner"
	"github.com/protonnegativo/raijin-scan/internal/nuclei"
	"github.com/protonnegativo/raijin-scan/internal/reduce"
	"github.com/protonnegativo/raijin-scan/internal/schema"
	"github.com/protonnegativo/raijin-scan/internal/scope"
	"github.com/protonnegativo/raijin-scan/internal/state"
)

const version = "0.1.0"

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("raijin-scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		targets   multi
		templates multi
	)
	fs.Var(&targets, "u", "target URL or host (repeatable)")
	list := fs.String("l", "", "file with one target per line")
	scopeFile := fs.String("scope", "", "scope file (required): domains, *.wildcards, IPs, CIDRs, !exclusions")
	fs.Var(&templates, "t", "nuclei template or directory (repeatable)")
	tags := fs.String("tags", "", "nuclei tags to run")
	severity := fs.String("severity", "", "nuclei severities to run, e.g. critical,high")
	rate := fs.Int("rate", 0, "requests per second (nuclei -rl)")
	timeout := fs.Int("timeout", 0, "request timeout in seconds")
	maxItems := fs.Int("max-items", 20, "maximum findings in the output")
	maxBytes := fs.Int("max-bytes", 8000, "maximum size of the JSON output")
	includeInfo := fs.Bool("include-info", false, "report info-level matches as findings instead of groups")
	statePath := fs.String("state", "", "state file; marks findings that are new since the last run")
	format := fs.String("format", "json", "output format: json or table")
	pretty := fs.Bool("pretty", false, "indent the JSON (compact by default, which costs fewer tokens)")
	input := fs.String("input", "", "read an existing nuclei JSONL file instead of running nuclei")
	bin := fs.String("nuclei", "nuclei", "path to the nuclei binary")
	showVersion := fs.Bool("version", false, "print the version")
	showBanner := fs.Bool("banner", false, "print the Raijin banner to stderr (off by default to keep output small)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: raijin-scan --scope scope.txt (-u target | -l targets.txt | --input results.jsonl) [flags] [-- extra nuclei args]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *showBanner {
		banner.Write(stderr, "raijin-scan", version, useColor(stderr))
	}
	if *showVersion {
		fmt.Fprintln(stdout, "raijin-scan", version)
		return 0
	}
	if *scopeFile == "" {
		fmt.Fprintln(stderr, "raijin-scan: --scope is required")
		return 1
	}
	sc, err := scope.Load(*scopeFile)
	if err != nil {
		fmt.Fprintln(stderr, "raijin-scan: scope:", err)
		return 1
	}

	res := schema.Result{
		Tool:     "raijin-scan",
		Version:  version,
		Findings: []schema.Finding{},
		Groups:   []schema.Group{},
		Omitted:  map[string]int{},
		Errors:   []schema.Error{},
		Next:     []string{},
		Budget:   schema.Budget{MaxItems: *maxItems, MaxBytes: *maxBytes},
	}

	var events []nuclei.Event
	if *input != "" {
		f, err := os.Open(*input)
		if err != nil {
			fmt.Fprintln(stderr, "raijin-scan:", err)
			return 1
		}
		events, err = nuclei.Parse(f)
		f.Close()
		if err != nil {
			fmt.Fprintln(stderr, "raijin-scan:", err)
			return 1
		}
		res.Target = *input
	} else {
		if *list != "" {
			lines, err := readLines(*list)
			if err != nil {
				fmt.Fprintln(stderr, "raijin-scan:", err)
				return 1
			}
			targets = append(targets, lines...)
		}
		inScope := filter(targets, sc, res.Omitted)
		if len(inScope) == 0 {
			fmt.Fprintln(stderr, "raijin-scan: no targets in scope")
			return 1
		}
		res.Target = targetSummary(inScope, res.Omitted["out_of_scope"])

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		var stderrTail string
		events, stderrTail, err = nuclei.Run(ctx, inScope, nuclei.Options{
			Binary: *bin, Templates: templates, Tags: *tags, Severity: *severity,
			Rate: *rate, Timeout: *timeout, Extra: fs.Args(),
		})
		switch {
		case errors.Is(err, nuclei.ErrNotFound):
			res.Errors = append(res.Errors, schema.Error{Kind: "missing_engine", Hint: "install nuclei (go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest) or pass --nuclei <path>"})
			res.Summary = "nuclei not found, nothing scanned"
			write(stdout, &res, *format, *pretty)
			return 2
		case err != nil:
			hint := err.Error()
			if stderrTail != "" {
				hint += ": " + stderrTail
			}
			res.Errors = append(res.Errors, schema.Error{Kind: "engine_error", Hint: hint})
		}
	}

	opt := reduce.Defaults()
	opt.MaxItems = *maxItems
	opt.MaxBytes = *maxBytes
	opt.IncludeInfo = *includeInfo
	opt.InScope = sc.Allowed
	findings, groups, omitted, allHosts := reduce.Reduce(events, opt)
	res.Findings, res.Groups = findings, groups
	for k, v := range omitted {
		res.Omitted[k] += v
	}

	newCount := -1
	if *statePath != "" {
		st, err := state.Load(*statePath)
		if err != nil {
			res.Errors = append(res.Errors, schema.Error{Kind: "state_error", Hint: err.Error()})
		} else {
			newCount = st.Mark(res.Findings, allHosts)
			if err := st.Save(*statePath); err != nil {
				res.Errors = append(res.Errors, schema.Error{Kind: "state_error", Hint: err.Error()})
			}
		}
	}

	res.Summary = summary(len(events), res, newCount)
	if res.Omitted["budget"] > 0 {
		res.Budget.Truncated = true
		if *severity == "" {
			res.Next = append(res.Next, "rerun with --severity critical,high to see only the top findings")
		}
	}
	reduce.Fit(&res, *maxBytes)
	write(stdout, &res, *format, *pretty)
	return 0
}

// useColor is true when w is a terminal and NO_COLOR is not set.
func useColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func filter(targets []string, sc *scope.Scope, omitted map[string]int) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		if !sc.Allowed(t) {
			omitted["out_of_scope"]++
			continue
		}
		out = append(out, t)
	}
	return out
}

func targetSummary(targets []string, skipped int) string {
	s := fmt.Sprintf("%d target(s)", len(targets))
	if len(targets) == 1 {
		s = targets[0]
	}
	if skipped > 0 {
		s += fmt.Sprintf(" (%d out of scope skipped)", skipped)
	}
	return s
}

func summary(raw int, res schema.Result, newCount int) string {
	bySev := map[string]int{}
	for _, f := range res.Findings {
		bySev[f.Severity]++
	}
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		if n := bySev[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	s := fmt.Sprintf("%d findings", len(res.Findings))
	if len(parts) > 0 {
		s += " (" + strings.Join(parts, ", ") + ")"
	}
	s += fmt.Sprintf(", %d info groups, %d raw matches", len(res.Groups), raw)
	if newCount >= 0 {
		s += fmt.Sprintf(", %d new", newCount)
	}
	return s
}

func write(w io.Writer, res *schema.Result, format string, pretty bool) {
	if format == "table" {
		fmt.Fprintln(w, res.Summary)
		for _, f := range res.Findings {
			mark := ""
			if f.New {
				mark = " [new]"
			}
			fmt.Fprintf(w, "%-8s %-40s %3d host(s)%s\n         %s\n", strings.ToUpper(f.Severity), f.ID, f.HostsCount, mark, f.Evidence)
		}
		for _, g := range res.Groups {
			fmt.Fprintf(w, "info     %-40s %3d host(s)\n", g.ID, g.Count)
		}
		for _, e := range res.Errors {
			fmt.Fprintf(w, "error    %s: %s\n", e.Kind, e.Hint)
		}
		return
	}
	enc := json.NewEncoder(w)
	if pretty {
		enc.SetIndent("", "  ")
	}
	_ = enc.Encode(res)
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}

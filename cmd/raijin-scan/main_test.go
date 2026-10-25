package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/protonnegativo/raijin-scan/internal/nuclei"
)

func scopeFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(p, []byte("*.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNoBannerByDefault(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if errb.Len() != 0 {
		t.Errorf("stderr should be empty without --banner, got %q", errb.String())
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
}

func TestBannerGoesToStderrOnly(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--banner", "--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), "TGT-LOCK") || !strings.Contains(errb.String(), "raijin-scan v"+strings.TrimPrefix(version, "v")) {
		t.Errorf("banner missing or without the version: %q", errb.String())
	}
	if strings.Contains(out.String(), "TGT-LOCK") {
		t.Error("banner leaked into stdout")
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON with --banner: %v", err)
	}
}

func TestCompactByDefault(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if n := strings.Count(out.String(), "\n"); n != 1 {
		t.Errorf("default JSON should be one line, got %d lines", n)
	}
	var pretty bytes.Buffer
	if code := run([]string{"--pretty", "--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &pretty, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(pretty.String(), "\n  \"tool\"") {
		t.Errorf("--pretty should indent: %q", pretty.String())
	}
	var a, b map[string]any
	if json.Unmarshal(out.Bytes(), &a) != nil || json.Unmarshal(pretty.Bytes(), &b) != nil || len(a) != len(b) {
		t.Error("compact and pretty should carry the same fields")
	}
}

// With only --scope, every host the scope names is scanned and wildcards get a next step.
func TestScopeAloneScansWhatTheScopeNames(t *testing.T) {
	dir := t.TempDir()
	scopePath := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(scopePath, []byte("example.com\n*.example.com\n10.0.0.0/30\n!10.0.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := filepath.Join(dir, "targets.txt")
	fake := filepath.Join(dir, "nuclei")
	script := "#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = -l ] && cp \"$2\" " + got + "; shift; done\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopePath, "--nuclei", fake, "--raw", filepath.Join(dir, "raw.jsonl")}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s %s", code, errb.String(), out.String())
	}
	b, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(strings.Fields(string(b)), ",") != "example.com,10.0.0.0,10.0.0.2,10.0.0.3" {
		t.Errorf("nuclei got targets %q", b)
	}
	var res struct{ Next []string }
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Next) != 1 || !strings.Contains(res.Next[0], "raijin-subs --scope "+scopePath+" -d example.com") {
		t.Errorf("next = %v", res.Next)
	}
}

func TestEngineVersionAndFormat(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "nuclei")
	// a nuclei one major past the tested one, whose JSONL renamed matched-at
	engines, err := nuclei.Engines()
	if err != nil {
		t.Fatal(err)
	}
	tested, _ := nuclei.ParseVersion(engines["nuclei"].Version)
	other := fmt.Sprintf("%d.0.0", tested[0]+1)
	script := "#!/bin/sh\nif [ \"$1\" = -version ]; then echo '[INF] Nuclei Engine Version: v" + other + "' >&2; exit 0; fi\n" +
		"echo '{\"template-id\":\"git-config\",\"host\":\"a.example.com\",\"matched_at\":\"https://a.example.com/.git/config\"}'\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "--nuclei", fake, "--raw", filepath.Join(dir, "raw.jsonl"), "-u", "https://a.example.com"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var v struct {
		Errors []struct{ Kind, Hint string }
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, e := range v.Errors {
		kinds[e.Kind] = e.Hint
	}
	if !strings.HasPrefix(kinds["engine_version"], "nuclei "+other+" is not the tested ") {
		t.Errorf("engine_version: %q", kinds["engine_version"])
	}
	if !strings.HasPrefix(kinds["engine_format"], "1 of 1 nuclei results") {
		t.Errorf("engine_format: %q", kinds["engine_format"])
	}
}

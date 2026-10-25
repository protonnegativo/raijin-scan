package nuclei

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"time"

	raijinscan "github.com/protonnegativo/raijin-scan"
)

// Engine is one entry of engines.json.
type Engine struct {
	Version string `json:"version"`
	Go      string `json:"go,omitempty"`
	Pip     string `json:"pip,omitempty"`
	System  string `json:"system,omitempty"`
}

// Engines parses the embedded engines.json.
func Engines() (map[string]Engine, error) {
	var m map[string]Engine
	err := json.Unmarshal(raijinscan.EnginesJSON, &m)
	return m, err
}

var versionRe = regexp.MustCompile(`v?(\d+)\.(\d+)\.(\d+)`)

// ParseVersion returns the first X.Y.Z in s, or ok=false.
func ParseVersion(s string) (v [3]int, ok bool) {
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return v, false
	}
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	return v, true
}

// Untested is true when the installed version has another major, or is older than the tested one.
// Newer minor and patch versions of the same major are left to the weekly drift job.
func Untested(installed, tested [3]int) bool {
	if installed[0] != tested[0] {
		return true
	}
	for i := 0; i < 3; i++ {
		if installed[i] != tested[i] {
			return installed[i] < tested[i]
		}
	}
	return false
}

// VersionHint runs `nuclei -version -duc` and returns a hint when the installed nuclei is not the
// tested one. It returns "" when the versions agree or the version cannot be read: it never fails a run.
func VersionHint(ctx context.Context, bin string) string {
	if bin == "" {
		bin = "nuclei"
	}
	engines, err := Engines()
	if err != nil {
		return ""
	}
	e, ok := engines["nuclei"]
	if !ok {
		return ""
	}
	tested, ok := ParseVersion(e.Version)
	if !ok {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, "-version", "-duc")
	cmd.Stdout, cmd.Stderr = &out, &out
	_ = cmd.Run()
	installed, ok := ParseVersion(out.String())
	if !ok || !Untested(installed, tested) {
		return ""
	}
	return fmt.Sprintf("nuclei %d.%d.%d is not the tested %s; results may be incomplete. Install the tested version: go install %s@v%s, or run raijin-mcp update",
		installed[0], installed[1], installed[2], e.Version, e.Go, e.Version)
}

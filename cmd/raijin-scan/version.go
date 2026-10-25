package main

import (
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/protonnegativo/raijin-scan/internal/nuclei"
)

// version is the release this binary was installed from, or "dev" for a local build.
var version = buildVersion(debug.ReadBuildInfo())

// buildVersion returns the module version when the binary was installed with `go install ...@vX.Y.Z`
// (or @latest), and otherwise "dev", plus the VCS revision and +dirty when the build settings carry them.
func buildVersion(info *debug.BuildInfo, ok bool) string {
	if !ok {
		return "dev"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" && !strings.Contains(v, "+dirty") {
		return v
	}
	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return "dev"
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if dirty {
		rev += "+dirty"
	}
	return "dev-" + rev
}

// versionLine is what --version prints: the release and the engine version it was tested with.
func versionLine() string {
	line := "raijin-scan " + version
	if engines, err := nuclei.Engines(); err == nil {
		if e, ok := engines["nuclei"]; ok {
			line += fmt.Sprintf(" (tested with nuclei %s)", e.Version)
		}
	}
	return line
}

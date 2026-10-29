package main

import (
	"bytes"
	"regexp"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/protonnegativo/raijin-scan/internal/nuclei"
)

func TestBuildVersion(t *testing.T) {
	cases := []struct {
		info *debug.BuildInfo
		ok   bool
		want string
	}{
		{nil, false, "dev"},
		{&debug.BuildInfo{Main: debug.Module{Version: "v0.1.3"}}, true, "v0.1.3"},
		{&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, true, "dev"},
		{&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "8f04ba9d1e2c3b4a5f60718293a4b5c6d7e8f901"}, {Key: "vcs.modified", Value: "false"},
		}}, true, "dev-8f04ba9d1e2c"},
		{&debug.BuildInfo{Main: debug.Module{Version: "v0.1.4-0.20261025-8f04ba9d1e2c+dirty"}, Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "8f04ba9d1e2c3b4a"}, {Key: "vcs.modified", Value: "true"},
		}}, true, "dev-8f04ba9d1e2c+dirty"},
	}
	for _, c := range cases {
		if got := buildVersion(c.info, c.ok); got != c.want {
			t.Errorf("buildVersion(%+v) = %q, want %q", c.info, got, c.want)
		}
	}
}

func TestBuildVersionPrefersReleaseVersion(t *testing.T) {
	old := releaseVersion
	defer func() { releaseVersion = old }()
	releaseVersion = "v9.9.9"
	if got := buildVersion(nil, false); got != "v9.9.9" {
		t.Errorf("buildVersion = %q, want v9.9.9", got)
	}
	info := &debug.BuildInfo{Main: debug.Module{Version: "v0.1.3"}}
	if got := buildVersion(info, true); got != "v9.9.9" {
		t.Errorf("buildVersion = %q, want v9.9.9", got)
	}
}

func TestVersionFlag(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--version"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	engines, err := nuclei.Engines()
	if err != nil {
		t.Fatal(err)
	}
	want := "raijin-scan " + version + " (tested with nuclei " + engines["nuclei"].Version + ")\n"
	if out.String() != want {
		t.Errorf("--version = %q, want %q", out.String(), want)
	}
	if !regexp.MustCompile(`^raijin-scan \S+ \(tested with nuclei \d+\.\d+\.\d+\)$`).MatchString(strings.TrimSpace(out.String())) {
		t.Errorf("--version format: %q", out.String())
	}
}

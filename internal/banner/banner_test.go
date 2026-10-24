package banner

import (
	"strings"
	"testing"
)

func TestRenderPlainHasVersionAndAlignedHUD(t *testing.T) {
	s := Render("raijin-scan", "9.8.7", false)
	if strings.Contains(s, "\x1b[") {
		t.Error("plain banner must not contain ANSI codes")
	}
	if !strings.Contains(s, "BUILD ..... raijin-scan v9.8.7") {
		t.Error("version not rendered")
	}
	// every HUD row ends at the same terminal column
	var ends []int
	for _, l := range strings.Split(s, "\n") {
		if i := strings.Index(l, "│ "); i >= 0 && strings.HasSuffix(l, "│") {
			ends = append(ends, cells(l))
		}
	}
	if len(ends) < 6 {
		t.Fatalf("found %d HUD rows", len(ends))
	}
	for _, e := range ends {
		if e != ends[0] {
			t.Errorf("HUD rows not aligned: %v", ends)
			break
		}
	}
}

func TestRenderColor(t *testing.T) {
	if !strings.Contains(Render("raijin-scan", "1.0.0", true), "\x1b[38;2;") {
		t.Error("color banner should use 24-bit color codes")
	}
}

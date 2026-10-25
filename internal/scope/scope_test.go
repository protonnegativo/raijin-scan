package scope

import (
	"strings"
	"testing"
)

func TestAllowed(t *testing.T) {
	sc, err := Parse([]string{
		"# comment",
		"example.com",
		"*.example.com",
		"!admin.example.com",
		"10.0.0.0/24",
		"192.0.2.10",
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		target string
		want   bool
	}{
		{"example.com", true},
		{"https://example.com/login", true},
		{"api.example.com:8443", true},
		{"a.b.example.com", true},
		{"admin.example.com", false},
		{"https://admin.example.com/", false},
		{"notexample.com", false},
		{"example.com.evil.com", false},
		{"10.0.0.7", true},
		{"http://10.0.0.7:8080", true},
		{"10.0.1.7", false},
		{"192.0.2.10", true},
		{"192.0.2.11", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := sc.Allowed(tt.target); got != tt.want {
			t.Errorf("Allowed(%q) = %v, want %v", tt.target, got, tt.want)
		}
	}
}

func TestTargets(t *testing.T) {
	sc, err := Parse([]string{
		"example.com",
		"*.example.com",
		"api.example.com",
		"example.com",
		"10.0.0.0/30",
		"!10.0.0.2",
		"192.0.2.10",
		"172.16.0.0/16",
	})
	if err != nil {
		t.Fatal(err)
	}
	targets, wildcards, ranges := sc.Targets()
	if got := strings.Join(targets, ","); got != "example.com,api.example.com,10.0.0.0,10.0.0.1,10.0.0.3,192.0.2.10" {
		t.Errorf("targets = %s", got)
	}
	if strings.Join(wildcards, ",") != "*.example.com" {
		t.Errorf("wildcards = %v", wildcards)
	}
	if strings.Join(ranges, ",") != "172.16.0.0/16" {
		t.Errorf("ranges larger than a /24 are not expanded: %v", ranges)
	}
}

func TestParseRejects(t *testing.T) {
	if _, err := Parse([]string{"!only-an-exclusion.com"}); err == nil {
		t.Error("expected an error for a scope with no include rules")
	}
	if _, err := Parse([]string{"10.0.0.0/99"}); err == nil {
		t.Error("expected an error for an invalid CIDR")
	}
}

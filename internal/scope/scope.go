// Package scope decides whether a target is allowed to be scanned.
//
// A scope file has one rule per line:
//
//	example.com        the domain itself
//	*.example.com      any subdomain (not the apex)
//	10.0.0.0/24        an IP range
//	192.0.2.10         a single IP
//	!admin.example.com an exclusion; exclusions win over inclusions
//
// Blank lines and lines starting with # are ignored.
package scope

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

type rule struct {
	exclude  bool
	domain   string
	wildcard bool
	ipnet    *net.IPNet
}

// Scope is a parsed set of include and exclude rules.
type Scope struct {
	rules []rule
}

// Load reads a scope file.
func Load(path string) (*Scope, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return Parse(lines)
}

// Parse builds a Scope from rule lines.
func Parse(lines []string) (*Scope, error) {
	s := &Scope{}
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		r := rule{}
		if strings.HasPrefix(line, "!") {
			r.exclude = true
			line = strings.TrimSpace(line[1:])
		}
		line = strings.ToLower(line)
		switch {
		case strings.Contains(line, "/"):
			_, ipnet, err := net.ParseCIDR(line)
			if err != nil {
				return nil, fmt.Errorf("scope line %d: invalid CIDR %q", i+1, line)
			}
			r.ipnet = ipnet
		case net.ParseIP(line) != nil:
			ip := net.ParseIP(line)
			bits := 128
			if ip.To4() != nil {
				ip = ip.To4()
				bits = 32
			}
			r.ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		case strings.HasPrefix(line, "*."):
			r.wildcard = true
			r.domain = strings.TrimPrefix(line, "*.")
		default:
			r.domain = strings.TrimSuffix(line, ".")
		}
		s.rules = append(s.rules, r)
	}
	if len(s.includes()) == 0 {
		return nil, fmt.Errorf("scope has no include rules")
	}
	return s, nil
}

func (s *Scope) includes() []rule {
	var out []rule
	for _, r := range s.rules {
		if !r.exclude {
			out = append(out, r)
		}
	}
	return out
}

// Allowed reports whether a target (a hostname, host:port, IP or URL) is in scope.
func (s *Scope) Allowed(target string) bool {
	host := Hostname(target)
	if host == "" {
		return false
	}
	included := false
	for _, r := range s.rules {
		if !r.match(host) {
			continue
		}
		if r.exclude {
			return false
		}
		included = true
	}
	return included
}

func (r rule) match(host string) bool {
	if r.ipnet != nil {
		ip := net.ParseIP(host)
		return ip != nil && r.ipnet.Contains(ip)
	}
	if r.wildcard {
		return strings.HasSuffix(host, "."+r.domain)
	}
	return host == r.domain
}

// Hostname extracts the lowercase hostname from a URL, host:port or bare host.
func Hostname(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return ""
	}
	if !strings.Contains(t, "://") {
		t = "scheme://" + t
	}
	u, err := url.Parse(t)
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
}

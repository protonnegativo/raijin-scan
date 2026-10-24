// Package banner renders the optional startup banner: a storm thunderbird in a target-lock frame,
// the RAIJIN name and a small HUD. It is only printed when the user asks for it (--banner).
package banner

import (
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

type rgb struct{ r, g, b int }

var (
	cyan   = rgb{80, 220, 255}
	violet = rgb{170, 90, 255}
	frame  = rgb{120, 200, 255}
	text   = rgb{190, 225, 255}
	light  = rgb{200, 225, 255}
)

const hudWidth = 50

// Render returns the banner. With color false it is plain text (for NO_COLOR or non-terminals).
func Render(tool, version string, color bool) string {
	p := painter{color: color}

	left := p.portrait()
	right := p.name()
	right = append(right, "")
	right = append(right, p.hud(tool, version)...)

	var b strings.Builder
	width := 0
	for _, l := range left {
		width = max(width, visible(l))
	}
	top := 2
	for i := 0; i < max(len(left), len(right)+top); i++ {
		line := ""
		if i < len(left) {
			line = left[i]
		}
		line += strings.Repeat(" ", width-visible(line))
		if j := i - top; j >= 0 && j < len(right) {
			line += "   " + right[j]
		}
		b.WriteString(strings.TrimRight(line, " ") + "\n")
	}
	b.WriteString(p.paint("AI-native offensive security tools.", light) + "\n")
	b.WriteString(p.paint("Signal, not noise.", violet) + "\n")
	return b.String()
}

// Write prints the banner to w.
func Write(w io.Writer, tool, version string, color bool) {
	fmt.Fprint(w, Render(tool, version, color))
}

type painter struct{ color bool }

func (p painter) paint(s string, c rgb) string {
	if !p.color || s == "" {
		return s
	}
	return fmt.Sprintf("\x1b[38;2;%d;%d;%dm%s\x1b[0m", c.r, c.g, c.b, s)
}

func (p painter) portrait() []string {
	w := 0
	for _, row := range Bird {
		w = max(w, utf8.RuneCountInString(row))
	}
	lines := []string{p.paint("┏━━"+strings.Repeat(" ", w-2)+"━━┓", frame)}
	mid := len(Bird) / 2
	for i, row := range Bird {
		side := " "
		switch {
		case i == mid:
			side = "╋"
		case i < 2 || i > len(Bird)-3:
			side = "┃"
		}
		row += strings.Repeat(" ", w-utf8.RuneCountInString(row))
		lines = append(lines, p.paint(side+" ", frame)+p.paint(row, mix(cyan, violet, float64(i)/float64(len(Bird))))+p.paint(" "+side, frame))
	}
	lines = append(lines, p.paint("┗━━"+strings.Repeat(" ", w-2)+"━━┛", frame))
	lines = append(lines, p.paint(" TGT-LOCK ▸ 0x"+hex.EncodeToString([]byte("RAIJIN")), violet))
	return lines
}

func (p painter) name() []string {
	var out []string
	for _, row := range Name {
		if !p.color {
			out = append(out, row)
			continue
		}
		runes := []rune(row)
		var b strings.Builder
		for x, r := range runes {
			if r == ' ' {
				b.WriteRune(r)
				continue
			}
			b.WriteString(p.paint(string(r), mix(cyan, violet, float64(x)/float64(max(1, len(runes)-1)))))
		}
		out = append(out, b.String())
	}
	return out
}

func (p painter) hud(tool, version string) []string {
	row := func(s string, c rgb) string {
		return p.paint("│ "+s+strings.Repeat(" ", hudWidth-1-cells(s))+"│", c)
	}
	return []string{
		p.paint("╭─ TARGET "+strings.Repeat("─", hudWidth-9)+"╮", frame),
		row("ID ........ RAIJIN // 雷神", text),
		row("CLASS ..... thunder god · AI-native · offensive", text),
		row("SIGNAL .... "+strings.Repeat("█", 18)+"░░ 90%", cyan),
		row("NOISE ..... "+strings.Repeat("░", 20)+" ~0", text),
		row("OUTPUT .... Raijin Schema · JSON", text),
		row("BUILD ..... "+tool+" v"+version, text),
		p.paint("╰"+strings.Repeat("─", hudWidth)+"╯", frame),
	}
}

// cells is the terminal width of s: CJK ideographs take two cells.
func cells(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x2E80 && r <= 0x9FFF {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// visible is the width of s without ANSI color codes.
func visible(s string) int {
	n, esc := 0, false
	for _, r := range s {
		switch {
		case r == '\x1b':
			esc = true
		case esc:
			if r == 'm' {
				esc = false
			}
		default:
			n++
		}
	}
	return n
}

func mix(a, b rgb, t float64) rgb {
	t = min(1, max(0, t))
	return rgb{a.r + int(float64(b.r-a.r)*t), a.g + int(float64(b.g-a.g)*t), a.b + int(float64(b.b-a.b)*t)}
}

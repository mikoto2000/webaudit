package audit

import (
	"regexp/syntax"
	"strings"
	"testing"
)

func allSourcePatterns() []sourcePattern {
	var out []sourcePattern
	for _, patterns := range dataPatterns {
		out = append(out, patterns...)
	}
	out = append(out, auraPatterns...)
	for _, r := range compiled {
		out = append(out, r.matcher)
	}
	return out
}

// Matching witnesses cover alternates and optional branches that random
// strings rarely reach. Each concat varies one child at a time.
func patternWitnesses(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		return []string{string(re.Rune)}
	case syntax.OpCharClass:
		return []string{string(re.Rune[0]), string(re.Rune[len(re.Rune)-1])}
	case syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		return []string{"a"}
	case syntax.OpCapture:
		return patternWitnesses(re.Sub[0])
	case syntax.OpAlternate:
		var out []string
		for _, sub := range re.Sub {
			out = append(out, patternWitnesses(sub)...)
		}
		return out
	case syntax.OpConcat:
		children := make([][]string, len(re.Sub))
		for i, sub := range re.Sub {
			children[i] = patternWitnesses(sub)
		}
		var out []string
		for i, choices := range children {
			for _, choice := range choices {
				var b strings.Builder
				for j, child := range children {
					if i == j {
						b.WriteString(choice)
					} else {
						b.WriteString(child[0])
					}
				}
				out = append(out, b.String())
			}
		}
		return out
	case syntax.OpStar, syntax.OpQuest:
		return append([]string{""}, patternWitnesses(re.Sub[0])...)
	case syntax.OpPlus:
		return patternWitnesses(re.Sub[0])
	case syntax.OpRepeat:
		var out []string
		for _, witness := range patternWitnesses(re.Sub[0]) {
			out = append(out, strings.Repeat(witness, re.Min))
		}
		if re.Min == 0 {
			out = append(out, patternWitnesses(re.Sub[0])...)
		}
		return out
	}
	return []string{""}
}

func TestSourcePatternFilterPreservesRE2Results(t *testing.T) {
	patterns := allSourcePatterns()
	for _, expression := range []string{`(?i)(foo|bar)baz`, `(?i)(foo|a*)`, `(?i)(foo)?bar`, `(?i)(foo){0,2}`, `(?i)(foo){2,3}`, `(?i)k.s`, `(?i)σ`, `�`, `(?i)(?P<name>abc)+`} {
		patterns = append(patterns, newSourcePattern(expression))
	}
	for _, p := range patterns {
		parsed, err := syntax.Parse(p.rx.String(), syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		corpus := []string{"", "Mozilla/5.0", "/api/items/1?nonce=1234", "İıſKΣςσ", string([]byte{0xff, 0xfe}), strings.Repeat("a", 3000)}
		corpus = append(corpus, patternWitnesses(parsed)...)
		for _, s := range corpus {
			for _, candidate := range []string{s, "prefix" + s + "suffix", strings.ToUpper(s), strings.ToLower(s), strings.ReplaceAll(strings.ReplaceAll(s, "s", "ſ"), "k", "K"), "İıſKΣςσ" + s, string([]byte{0xff}) + s} {
				if got, want := p.match(candidate, patternInput(candidate)), p.rx.MatchString(candidate); got != want {
					t.Fatalf("prefilter changed RE2 result for %q on %q: got %v, want %v", p.rx.String(), candidate, got, want)
				}
			}
		}
	}
}

func TestFoldedSourceListsPreserveContains(t *testing.T) {
	for name, folded := range upperSourceLists {
		if len(folded) != len(sourceLists[name]) {
			t.Fatal(name)
		}
		corpus := append([]string{"", "ordinary request", "İıſKΣςσ"}, sourceLists[name]...)
		for _, value := range corpus {
			for _, s := range []string{value, strings.ToLower(value), "prefix" + strings.ToUpper(value) + "suffix"} {
				want := false
				for _, p := range sourceLists[name] {
					if strings.Contains(strings.ToUpper(s), strings.ToUpper(p)) {
						want = true
						break
					}
				}
				if got := listContains(name, s, true); got != want {
					t.Fatalf("%s on %q: got %v want %v", name, s, got, want)
				}
			}
		}
	}
}

func FuzzSourcePattern(f *testing.F) {
	for _, s := range []string{"Mozilla/5.0", "sqlmap", "İıſKΣςσ", strings.Repeat("a", 3000), "union+select", "${jndi:ldap://host}", "/.env", "/../../etc/passwd", string([]byte{0xff})} {
		f.Add(s)
	}
	patterns := allSourcePatterns()
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 8192 {
			return
		}
		folded := patternInput(s)
		for _, p := range patterns {
			if got, want := p.match(s, folded), p.rx.MatchString(s); got != want {
				t.Fatalf("prefilter changed %q on %q", p.rx.String(), s)
			}
		}
	})
}

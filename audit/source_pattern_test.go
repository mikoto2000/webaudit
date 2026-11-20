package audit

import (
	"regexp/syntax"
	"strings"
	"testing"
)

func TestSourcePatternFilterPreservesRE2Results(t *testing.T) {
	for _, patterns := range dataPatterns {
		for _, p := range patterns {
			parsed, err := syntax.Parse(p.rx.String(), syntax.Perl)
			if err != nil {
				t.Fatal(err)
			}
			literal := patternLiteral(parsed)
			for _, s := range []string{literal, "Mozilla/5.0 " + literal, strings.Repeat("a", 3000) + literal, strings.ToUpper(literal), "İıſKΣςσ" + literal} {
				want := p.rx.MatchString(s)
				got := matchPatterns([]sourcePattern{p}, s)
				if got != want {
					t.Fatalf("prefilter changed RE2 result for %q", p.rx.String())
				}
			}
		}
	}
}

func FuzzSourcePattern(f *testing.F) {
	for _, s := range []string{"Mozilla/5.0", "sqlmap", "İıſKΣςσ", strings.Repeat("a", 3000)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 8192 {
			return
		}
		for _, patterns := range dataPatterns {
			for _, p := range patterns {
				if got, want := matchPatterns([]sourcePattern{p}, s), p.rx.MatchString(s); got != want {
					t.Fatalf("prefilter changed %q", p.rx.String())
				}
			}
		}
	})
}

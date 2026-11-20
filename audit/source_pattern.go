package audit

import (
	"regexp"
	"regexp/syntax"
	"strings"
)

// A literal from a mandatory concat/repetition branch can reject a candidate
// before RE2 scans a long field. Alternations/optional branches yield no filter.
// RE2 still decides every candidate that passes, so this never relaxes a rule.
type sourcePattern struct {
	rx      *regexp.Regexp
	literal string
}

func patternLiteral(re *syntax.Regexp) string {
	switch re.Op {
	case syntax.OpLiteral:
		return string(re.Rune)
	case syntax.OpCapture, syntax.OpPlus:
		return patternLiteral(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min > 0 {
			return patternLiteral(re.Sub[0])
		}
	case syntax.OpConcat:
		longest := ""
		for _, sub := range re.Sub {
			s := patternLiteral(sub)
			if len(s) > len(longest) {
				longest = s
			}
		}
		return longest
	}
	return ""
}
func foldFilter(s string) string { return strings.ToLower(strings.ToUpper(s)) }
func newSourcePattern(p string) sourcePattern {
	parsed, err := syntax.Parse(p, syntax.Perl)
	if err != nil {
		panic(err)
	}
	return sourcePattern{regexp.MustCompile(p), foldFilter(patternLiteral(parsed))}
}
func matchPatterns(patterns []sourcePattern, s string) bool {
	folded := foldFilter(s)
	for _, p := range patterns {
		if p.literal != "" && !strings.Contains(folded, p.literal) {
			continue
		}
		if p.rx.MatchString(s) {
			return true
		}
	}
	return false
}

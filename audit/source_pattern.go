package audit

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode/utf8"
)

// Necessary literals reject candidates before RE2 scans a field. Alternations
// are filtered only when every branch supplies a necessary literal.
// RE2 still decides every candidate that passes, so this never relaxes a rule.
type sourcePattern struct {
	rx           *regexp.Regexp
	alternatives []string
}

func foldFilter(s string) string { return strings.ToLower(strings.ToUpper(s)) }
func newSourcePattern(p string) sourcePattern {
	parsed, err := syntax.Parse(p, syntax.Perl)
	if err != nil {
		panic(err)
	}
	return sourcePattern{rx: regexp.MustCompile(p), alternatives: requiredLiterals(parsed)}
}

// requiredLiterals returns an OR of necessary literals. An empty result means
// no safe rejection is available. For concat, any mandatory child suffices;
// every alternative must be represented before an alternation can be filtered.
func requiredLiterals(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		if len(re.Rune) > 0 {
			return []string{foldFilter(string(re.Rune))}
		}
	case syntax.OpCapture, syntax.OpPlus:
		return requiredLiterals(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min > 0 {
			return requiredLiterals(re.Sub[0])
		}
	case syntax.OpConcat:
		var best []string
		bestScore := 0
		for _, sub := range re.Sub {
			candidates := requiredLiterals(sub)
			if len(candidates) == 0 {
				continue
			}
			score := len(candidates[0])
			for _, candidate := range candidates {
				if len(candidate) < score {
					score = len(candidate)
				}
			}
			if score > bestScore {
				best, bestScore = candidates, score
			}
		}
		return best
	case syntax.OpAlternate:
		var out []string
		seen := map[string]bool{}
		for _, sub := range re.Sub {
			candidates := requiredLiterals(sub)
			if len(candidates) == 0 {
				return nil
			}
			for _, candidate := range candidates {
				if !seen[candidate] {
					seen[candidate] = true
					out = append(out, candidate)
				}
			}
		}
		return out
	}
	return nil
}

// ASCII inputs admit cheap folding. For Unicode or invalid UTF-8, defer to
// RE2 so its SimpleFold and RuneError semantics remain authoritative.
func patternInput(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return ""
		}
	}
	return strings.ToLower(s)
}
func (p sourcePattern) match(s, folded string) bool {
	if folded != "" && len(p.alternatives) > 0 {
		possible := false
		for _, literal := range p.alternatives {
			if strings.Contains(folded, literal) {
				possible = true
				break
			}
		}
		if !possible {
			return false
		}
	}
	return p.rx.MatchString(s)
}
func matchPatterns(patterns []sourcePattern, s string) bool {
	folded := patternInput(s)
	for _, p := range patterns {
		if p.match(s, folded) {
			return true
		}
	}
	return false
}

package audit

import (
	_ "embed"
	"encoding/json"
	"strings"
)

//go:embed rules.json
var ruleData []byte

type Rule struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Required    []string `json:"required"`
	Pattern     string   `json:"pattern"`
	Field       string   `json:"field"`
	Source      string   `json:"source"`
	Exclude     []string `json:"exclude,omitempty"`
	matcher     sourcePattern
}

var compiled = func() []Rule {
	var r []Rule
	if err := json.Unmarshal(ruleData, &r); err != nil {
		panic(err)
	}
	for i := range r {
		r[i].matcher = newSourcePattern("(?i)" + r[i].Pattern)
	}
	return r
}()

func Rules() []Rule { return append([]Rule(nil), compiled...) }
func Detect(e Event) ([]Rule, Normalized) {
	n := Normalize(e.Target)
	var hits []Rule
	// Fold each field once, shared across all rules using that field.
	foldedVariants := make([]string, len(n.Variants))
	for i, v := range n.Variants {
		foldedVariants[i] = patternInput(v)
	}
	foldedUA, foldedReferer := patternInput(val(e.UA)), patternInput(val(e.Referer))
	foldedMethod, foldedProtocol := patternInput(val(e.Method)), patternInput(val(e.Protocol))
	for _, r := range compiled {
		var values, folded []string
		switch r.Field {
		case "ua":
			if e.UA != nil {
				values, folded = []string{*e.UA}, []string{foldedUA}
			}
		case "method":
			if e.Method != nil {
				values, folded = []string{*e.Method}, []string{foldedMethod}
			}
		case "protocol":
			if e.Protocol != nil {
				values, folded = []string{*e.Protocol}, []string{foldedProtocol}
			}
		default:
			values, folded = n.Variants, foldedVariants
			if r.Field == "url_headers" {
				values = append(append([]string(nil), values...), val(e.UA), val(e.Referer))
				folded = append(append([]string(nil), folded...), foldedUA, foldedReferer)
			}
		}
		for i, v := range values {
			excluded := false
			for _, x := range r.Exclude {
				if strings.EqualFold(x, v) {
					excluded = true
					break
				}
			}
			if excluded {
				continue
			}
			if r.matcher.match(v, folded[i]) {
				hits = append(hits, r)
				break
			}
		}
	}
	return hits, n
}

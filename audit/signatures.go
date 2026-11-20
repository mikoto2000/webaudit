package audit

import (
	_ "embed"
	"encoding/json"
	"regexp"
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
	rx          *regexp.Regexp
}

var compiled = func() []Rule {
	var r []Rule
	if err := json.Unmarshal(ruleData, &r); err != nil {
		panic(err)
	}
	for i := range r {
		r[i].rx = regexp.MustCompile("(?i)" + r[i].Pattern)
	}
	return r
}()

func Rules() []Rule { return append([]Rule(nil), compiled...) }
func Detect(e Event) ([]Rule, Normalized) {
	n := Normalize(e.Target)
	var hits []Rule
	for _, r := range compiled {
		var values []string
		switch r.Field {
		case "ua":
			if e.UA != nil {
				values = []string{*e.UA}
			}
		case "method":
			if e.Method != nil {
				values = []string{*e.Method}
			}
		case "protocol":
			if e.Protocol != nil {
				values = []string{*e.Protocol}
			}
		default:
			values = n.Variants
			if r.Field == "url_headers" {
				values = append(append([]string(nil), values...), val(e.UA), val(e.Referer))
			}
		}
		for _, v := range values {
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
			if r.rx.MatchString(v) {
				hits = append(hits, r)
				break
			}
		}
	}
	return hits, n
}

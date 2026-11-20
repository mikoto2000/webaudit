package audit

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Outcome struct {
	Verdict    string   `json:"verdict"`
	Confidence float64  `json:"confidence"`
	Reasons    []string `json:"reasons"`
	Missing    []string `json:"missing"`
	Next       []string `json:"next"`
}
type Evidence struct {
	Event         Event      `json:"event"`
	Normalization Normalized `json:"normalization"`
}
type Incident struct {
	ID            string     `json:"id"`
	IP            string     `json:"ip"`
	Host          *string    `json:"host"`
	UA            *string    `json:"user_agent"`
	First         time.Time  `json:"first"`
	Last          time.Time  `json:"last"`
	Count         int64      `json:"count"`
	Severity      string     `json:"severity"`
	Score         int        `json:"attack_score"`
	Phase         string     `json:"phase"`
	Rules         []Rule     `json:"rules"`
	Categories    []string   `json:"categories"`
	Correlation   []string   `json:"correlation"`
	Reasons       []string   `json:"reasons"`
	Evidence      []Evidence `json:"evidence"`
	Outcome       Outcome    `json:"outcome"`
	blocked, good int64
	resources     map[string]*resource
}
type resource struct {
	blockedAt *time.Time
	goodAt    []time.Time
}
type Correlator struct {
	o        Options
	items    map[string]*Incident
	warnings []string
}

func NewCorrelator(o Options) *Correlator {
	return &Correlator{o: o.defaults(), items: map[string]*Incident{}}
}
func (c *Correlator) Warnings() []string { return append([]string(nil), c.warnings...) }
func family(r Rule) string {
	switch r.Category {
	case "sensitive_file", "cve_probe", "iis_aspnet", "recon_probe", "scanner":
		return "reconnaissance"
	case "webshell":
		return "webshell_probe"
	default:
		if strings.HasPrefix(r.ID, "WB-") || strings.HasPrefix(r.ID, "WS-") {
			return r.ID
		}
		return "exploitation_attempt"
	}
}
func (c *Correlator) get(e Event, group string) *Incident {
	key := e.IP + "\x00" + val(e.Host) + "\x00" + val(e.UA) + "\x00" + group + "\x00" + strconv.FormatInt(e.Time.Unix()/300, 10)
	if f := c.items[key]; f != nil {
		return f
	}
	if len(c.items) >= c.o.MaxFindings {
		if len(c.warnings) == 0 {
			c.warnings = append(c.warnings, "Incident limit reached; incident counts and evidence are incomplete")
		}
		return nil
	}
	hash := sha256.Sum256([]byte(key))
	f := &Incident{ID: fmt.Sprintf("WA-%x", hash[:8]), IP: e.IP, Host: e.Host, UA: e.UA, First: e.Time, Last: e.Time, Severity: "low", Phase: group, resources: map[string]*resource{}, Correlation: []string{"Same recorded peer IP, target host (when available), User-Agent, technique family and five-minute event-time partition; this is a hypothesis, not verified identity"}}
	c.items[key] = f
	return f
}
func (c *Correlator) Add(e Event, hits []Rule, n Normalized) {
	groups := map[string][]Rule{}
	for _, h := range hits {
		groups[family(h)] = append(groups[family(h)], h)
	}
	for group, rules := range groups {
		f := c.get(e, group)
		if f == nil {
			continue
		}
		f.Count++
		if e.Time.Before(f.First) {
			f.First = e.Time
		}
		if e.Time.After(f.Last) {
			f.Last = e.Time
		}
		for _, r := range rules {
			addRule(f, r)
		}
		addEvidence(f, e, n)
		status := val(e.Status)
		if status == 403 || status == 404 {
			f.blocked++
		}
		if status >= 200 && status < 300 {
			f.good++
		}
		sensitive := false
		for _, r := range rules {
			if r.Category == "sensitive_file" {
				sensitive = true
			}
		}
		if sensitive {
			res := f.resources[e.Path]
			if res == nil && len(f.resources) < 128 {
				res = &resource{}
				f.resources[e.Path] = res
			}
			if res != nil {
				if status == 403 || status == 404 {
					if res.blockedAt == nil || e.Time.Before(*res.blockedAt) {
						res.blockedAt = ptr(e.Time)
					}
				}
				if status >= 200 && status < 300 && val(e.Bytes) > 0 && len(res.goodAt) < 8 {
					res.goodAt = append(res.goodAt, e.Time)
				}
			}
		}
	}
}
func (c *Correlator) AddSignal(s Signal) {
	f := c.get(s.Event, family(s.Rule))
	if f == nil {
		return
	}
	addRule(f, s.Rule)
	if s.Count > f.Count {
		f.Count = s.Count
	}
	if s.Start.Before(f.First) {
		f.First = s.Start
	}
	if s.End.After(f.Last) {
		f.Last = s.End
	}
	uniqueAppend(&f.Reasons, s.Reason)
	if len(f.Evidence) == 0 {
		addEvidence(f, s.Event, Normalize(s.Event.Target))
	}
}
func uniqueAppend(dst *[]string, s string) {
	for _, x := range *dst {
		if x == s {
			return
		}
	}
	*dst = append(*dst, s)
}
func weight(severity string) int {
	switch severity {
	case "critical":
		return 40
	case "high":
		return 30
	case "medium":
		return 15
	default:
		return 5
	}
}
func addRule(f *Incident, r Rule) {
	for _, x := range f.Rules {
		if x.ID == r.ID {
			return
		}
	}
	f.Rules = append(f.Rules, r)
	uniqueAppend(&f.Categories, r.Category)
	f.Score += weight(r.Severity)
	if f.Score > 100 {
		f.Score = 100
	}
	if weight(r.Severity) > weight(f.Severity) {
		f.Severity = r.Severity
	}
	uniqueAppend(&f.Reasons, r.Description)
}
func addEvidence(f *Incident, e Event, n Normalized) {
	v := Evidence{e, n}
	if len(f.Evidence) < 8 {
		f.Evidence = append(f.Evidence, v)
	} else {
		f.Evidence[7] = v
	}
}
func infer(f *Incident) Outcome {
	o := Outcome{Verdict: "unknown", Confidence: 0.2, Reasons: []string{"Access logs show requests and response metadata, not server-side execution or returned content"}, Missing: []string{"Response content and expected resource semantics", "Request body, application/authentication audit trail", "Backend/proxy status mapping and filesystem/process/network evidence"}, Next: []string{"Inspect the referenced original logs and confirm request routing and proxy configuration", "Correlate application/authentication and error logs for the same time and resource", "For payload probes inspect server files, processes and outbound connections"}}
	for _, r := range f.resources {
		if r.blockedAt == nil {
			continue
		}
		after := 0
		for _, t := range r.goodAt {
			if t.After(*r.blockedAt) {
				after++
			}
		}
		if after >= 2 {
			o.Verdict = "possible_success"
			o.Confidence = 0.55
			o.Reasons = append(o.Reasons, "Same sensitive resource changed from blocked/not-found to repeated nonempty 2xx responses; soft-404, redirects, generic pages or legitimate changes remain possible")
			o.Next = append(o.Next, "Verify actual returned sensitive bytes against a nonexistent-path response; preserve response/application evidence")
			return o
		}
	}
	if f.blocked >= 3 && f.good == 0 {
		o.Verdict = "likely_failed"
		o.Confidence = 0.5
		o.Reasons = append(o.Reasons, "At least three blocked/not-found observations and no observed 2xx within this activity; status mapping and unobserved attempts prevent confirmation")
	}
	return o
}
func (c *Correlator) Finish() []Incident {
	out := make([]Incident, 0, len(c.items))
	for _, f := range c.items {
		x := *f
		x.Outcome = infer(f)
		sort.Slice(x.Rules, func(i, j int) bool { return x.Rules[i].ID < x.Rules[j].ID })
		sort.Strings(x.Categories)
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if (a.Outcome.Verdict == "possible_success") != (b.Outcome.Verdict == "possible_success") {
			return a.Outcome.Verdict == "possible_success"
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if !a.First.Equal(b.First) {
			return a.First.Before(b.First)
		}
		return a.ID < b.ID
	})
	return out
}
func Analyze(paths []string, o Options) Report {
	o = o.defaults()
	a := NewAnalysis(o)
	c := NewCorrelator(o)
	fingerprints := make(map[[32]byte]bool)
	queue := make([][32]byte, 0, o.MaxKeys)
	cursor := 0
	var duplicates int64
	var previous time.Time
	outOfOrder := false
	r := Stream(paths, o, func(e Event) {
		if !previous.IsZero() && e.Time.Before(previous) {
			outOfOrder = true
		}
		previous = e.Time
		hash := sha256.Sum256([]byte(e.Raw))
		if fingerprints[hash] {
			duplicates++
			return
		}
		fingerprints[hash] = true
		if len(queue) < o.MaxKeys {
			queue = append(queue, hash)
		} else {
			delete(fingerprints, queue[cursor])
			queue[cursor] = hash
			cursor = (cursor + 1) % o.MaxKeys
		}
		hits, n := Detect(e)
		c.Add(e, hits, n)
		a.Observe(e, hits)
	})
	for _, s := range a.Finish() {
		c.AddSignal(s)
	}
	r.Findings = c.Finish()
	r.Duplicates = duplicates
	r.Outcomes = map[string]int{"confirmed_success": 0, "possible_success": 0, "unknown": 0, "likely_failed": 0, "confirmed_failure": 0}
	r.Categories = map[string]int{}
	r.Severities = map[string]int{}
	for _, f := range r.Findings {
		r.Outcomes[f.Outcome.Verdict]++
		r.Severities[f.Severity]++
		for _, cat := range f.Categories {
			r.Categories[cat]++
		}
	}
	for _, w := range append(a.Warnings(), c.Warnings()...) {
		r.warn(w)
		if strings.Contains(w, "limit reached") {
			r.Partial = true
		}
	}
	if outOfOrder {
		r.warn("Input time order is incomplete; correlations use bounded fixed event-time partitions")
	}
	if duplicates > 0 {
		r.warn("Exact raw-line duplicates excluded within bounded fingerprint horizon; identical legitimate requests can be indistinguishable")
	}
	for field, count := range r.Missing {
		if count > 0 {
			r.warn(fmt.Sprintf("Missing %s in %d parsed requests reduces related detection coverage", field, count))
		}
	}
	return r
}

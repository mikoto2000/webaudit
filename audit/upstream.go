package audit

import (
	"embed"
	"encoding/json"
	"net"
	"regexp"
	"strings"
	"time"
)

//go:embed upstream/* upstream/data/*
var upstreamFiles embed.FS

type SourceRule struct {
	ID                              string `json:"name"`
	Type                            string `json:"type"`
	Capacity                        int    `json:"capacity"`
	CacheSize                       int    `json:"cache_size,omitempty"`
	Leak                            string `json:"leakspeed"`
	Blackhole                       string `json:"blackhole"`
	Distinct                        string `json:"distinct"`
	Group                           string `json:"groupby"`
	Description                     string `json:"description"`
	File                            string `json:"file"`
	Filter                          string `json:"filter"`
	Supported                       bool   `json:"supported"`
	leakDuration, blackholeDuration time.Duration
}
type EventRef struct {
	File string `json:"file"`
	Line int64  `json:"line"`
}
type SourceAlert struct {
	Evidence          []SourceEvidence  `json:"evidence,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
	Source            string            `json:"source"`
	RuleID            string            `json:"rule_id"`
	IP                string            `json:"ip"`
	Group             string            `json:"group"`
	First             *time.Time        `json:"first"`
	Last              *time.Time        `json:"last"`
	WallFirst         string            `json:"wall_first,omitempty"`
	WallLast          string            `json:"wall_last,omitempty"`
	TimezoneUnknown   bool              `json:"timezone_unknown,omitempty"`
	Count             int64             `json:"count"`
	Events            []EventRef        `json:"events"`
	EvidenceTruncated bool              `json:"evidence_truncated,omitempty"`
}
type upstreamBucket struct {
	capacity    int
	leak        time.Duration
	domain      string
	tokens      float64
	first, last time.Time
	count       int64
	seen        map[string]bool
	refs        []EventRef
	samples     []SourceEvidence
}
type Upstream struct {
	evidence      *upstreamEvidence
	observed      int64
	o             Options
	buckets       map[string]*upstreamBucket
	blocked       map[string]sourceSuppression
	alerts        []SourceAlert
	aura          map[string]*SourceAlert
	warnings      []string
	distinctCount int
}
type sourceSuppression struct {
	Until  time.Time
	Domain string
}

var sourceRules []SourceRule
var upstreamCommits = map[string]string{}
var sourceLists = map[string][]string{}
var sourceRegex = map[string]*regexp.Regexp{}
var dataPatterns = map[string][]sourcePattern{}
var auraSource struct {
	Signatures []struct{ ID, Severity, Pattern, Description string }
	ScannerUAs []string `json:"scanner_uas"`
	Methods    []string
}

func init() {
	manifest, err := upstreamFiles.ReadFile("upstream/manifest.json")
	if err != nil {
		panic(err)
	}
	var m map[string]json.RawMessage
	if err = json.Unmarshal(manifest, &m); err != nil {
		panic(err)
	}
	for _, k := range []string{"hub", "crowdsec", "AuraDFIR", "sec-lists"} {
		var v string
		if err = json.Unmarshal(m[k], &v); err != nil {
			panic(err)
		}
		upstreamCommits[k] = v
	}
	b, err := upstreamFiles.ReadFile("upstream/hub.json")
	if err != nil {
		panic(err)
	}
	if err = json.Unmarshal(b, &sourceRules); err != nil {
		panic(err)
	}
	b, err = upstreamFiles.ReadFile("upstream/aura.json")
	if err != nil {
		panic(err)
	}
	if err = json.Unmarshal(b, &auraSource); err != nil {
		panic(err)
	}
	for i := range sourceRules {
		r := &sourceRules[i]
		r.leakDuration, _ = time.ParseDuration(r.Leak)
		r.blackholeDuration, _ = time.ParseDuration(r.Blackhole)
	}
	for _, s := range auraSource.Signatures {
		sourceRegex["aura/"+s.ID] = regexp.MustCompile("(?i)" + s.Pattern)
	}
	files, err := upstreamFiles.ReadDir("upstream/data")
	if err != nil {
		panic(err)
	}
	for _, f := range files {
		b, err = upstreamFiles.ReadFile("upstream/data/" + f.Name())
		if err != nil {
			panic(err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				sourceLists[f.Name()] = append(sourceLists[f.Name()], line)
			}
		}
	}
	for _, name := range []string{"technology_probing.json", "trendy_cves_uris.json"} {
		for _, line := range sourceLists[name] {
			var row map[string]string
			if json.Unmarshal([]byte(line), &row) != nil {
				panic("invalid embedded lookup entry")
			}
			sourceLookups[name] = append(sourceLookups[name], row)
		}
	}
	for _, name := range []string{"bad_user_agents.regex.txt", "thinkphp_cve_2018-20062.txt"} {
		for _, p := range sourceLists[name] {
			dataPatterns[name] = append(dataPatterns[name], newSourcePattern(p))
		}
	}
}
func NewUpstream(o Options) *Upstream {
	o = o.defaults()
	var evidence *upstreamEvidence
	if o.RetainUpstreamEvidence {
		evidence = &upstreamEvidence{limit: int64(o.MaxEvidenceBytes)}
	}
	return &Upstream{evidence: evidence, o: o, buckets: map[string]*upstreamBucket{}, blocked: map[string]sourceSuppression{}, aura: map[string]*SourceAlert{}}
}
func (u *Upstream) warning(s string) { uniqueAppend(&u.warnings, s) }
func (u *Upstream) AlertsFor(id string) []SourceAlert {
	var out []SourceAlert
	for _, a := range u.alerts {
		if a.RuleID == id {
			out = append(out, a)
		}
	}
	return out
}
func sourceField(e Event, s string) string {
	full := e.Target
	if e.RequestMalformed {
		full = val(e.RawRequest)
	}
	req := full
	if e.SourceRequest != nil {
		req = val(e.SourceRequest)
	}
	args := ""
	if i := strings.LastIndexByte(req, '?'); i >= 0 {
		req, args = req[:i], req[i+1:]
	}
	switch s {
	case "evt.Meta.http_path":
		return full
	case "evt.Parsed.request":
		return req
	case "evt.Parsed.http_args":
		return args
	case "evt.Parsed.file_name":
		_, frag, ext := sourceFile(req)
		return frag + ext
	case "evt.Parsed.http_user_agent":
		return sourceUA(e)
	}
	return ""
}
func sourceGroup(e Event, s string) string {
	if strings.Contains(s, "http_path") {
		return e.IP + " " + sourceField(e, "evt.Meta.http_path")
	}
	if strings.Contains(s, "target_fqdn") {
		host := val(e.Host)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		return e.IP + "/" + host
	}
	return e.IP
}
func sourceUA(e Event) string {
	if e.RecordedUA != nil {
		return val(e.RecordedUA)
	}
	return val(e.UA)
}
func sourceReferer(e Event) string {
	if e.RecordedReferer != nil {
		return val(e.RecordedReferer)
	}
	return val(e.Referer)
}
func (u *Upstream) reset(key string) {
	if b := u.buckets[key]; b != nil {
		u.distinctCount -= len(b.seen)
	}
	delete(u.buckets, key)
}
func sourceAlert(e Event, id, group string, b *upstreamBucket) SourceAlert {
	group, cut := clipped(group, 4096)
	a := SourceAlert{EvidenceTruncated: cut, Source: "hub", RuleID: id, IP: strings.Clone(e.IP), Group: group, Count: b.count, Events: append([]EventRef(nil), b.refs...), First: ptr(b.first), Last: ptr(b.last)}
	if e.TimezoneUnknown {
		a.First = nil
		a.Last = nil
		a.TimezoneUnknown = true
		a.WallFirst = b.first.Format("2006-01-02T15:04:05.999999999")
		a.WallLast = b.last.Format("2006-01-02T15:04:05.999999999")
	}
	return a
}
func (u *Upstream) Observe(e Event) {
	u.observed++
	if u.observed%5000 == 0 {
		domain := "instant"
		if e.TimezoneUnknown {
			domain = "wall:" + e.File
		}
		for key, b := range u.buckets {
			if b.domain != domain || b.leak <= 0 {
				continue
			}
			tokens := b.tokens
			if e.Time.After(b.last) {
				tokens += e.Time.Sub(b.last).Seconds() * (1 / b.leak.Seconds())
			}
			if tokens+1e-9 >= float64(b.capacity) {
				u.reset(key)
			}
		}
	}
	u.observeAura(e)
	v := makeSourceView(e)
	for _, r := range sourceRules {
		if !r.Supported || !sourceMatchView(r, e, v) {
			continue
		}
		group := sourceGroup(e, r.Group)
		key := r.ID + "\x00" + group
		domain := "instant"
		if e.TimezoneUnknown {
			domain = "wall:" + e.File
			key += "\x00" + domain
		}
		leak, blackhole := r.leakDuration, r.blackholeDuration
		key = digest(key)
		b := u.buckets[key]
		if b != nil && e.Time.After(b.last.Add(time.Duration(r.Capacity+1)*leak)) {
			u.reset(key)
			b = nil
		}
		if b == nil {
			if len(u.buckets)+len(u.blocked) >= u.o.MaxKeys {
				u.warning("Upstream state limit reached; source alerts are incomplete")
				continue
			}
			b = &upstreamBucket{capacity: r.Capacity, leak: leak, domain: domain, tokens: float64(r.Capacity), first: e.Time, last: e.Time, seen: map[string]bool{}}
			u.buckets[key] = b
		}
		if r.Distinct != "" {
			v := digest(sourceField(e, r.Distinct))
			if b.seen[v] {
				continue
			}
			if u.distinctCount >= u.o.MaxKeys*8 {
				u.warning("Upstream distinct limit reached; source alerts are incomplete")
				continue
			}
			b.seen[v] = true
			u.distinctCount++
		}
		if e.Time.Before(b.last) {
			u.warning("Upstream event time moved backwards; source bucket parity requires ordered input")
		}
		if leak > 0 && e.Time.After(b.last) {
			b.tokens += e.Time.Sub(b.last).Seconds() * (1 / leak.Seconds())
			if b.tokens > float64(r.Capacity) {
				b.tokens = float64(r.Capacity)
			}
		}
		b.last = e.Time
		b.count++
		b.refs = append(b.refs, EventRef{e.File, e.Line})
		u.evidence.add(&b.samples, e)
		cache := r.Capacity
		if r.CacheSize > 0 && r.CacheSize <= cache {
			cache = r.CacheSize
		}
		if len(b.refs) > cache+1 && cache > 0 {
			b.refs = b.refs[1:]
		}
		overflow := r.Type == "trigger" || b.tokens < 1
		if !overflow {
			b.tokens--
			continue
		}
		if suppression := u.blocked[key]; !e.Time.Before(suppression.Until) {
			if len(u.alerts) >= u.o.MaxFindings {
				u.warning("Upstream alert limit reached; source alerts are incomplete")
			} else {
				alert := sourceAlert(e, r.ID, group, b)
				u.evidence.attach(&alert, b.samples)
				if r.ID == "crowdsecurity/http-technology-probing" {
					alert.Metadata = map[string]string{"target_technology": lookupTag("technology_probing.json", v.full)}
				}
				if r.ID == "crowdsecurity/http-cve-probing" {
					for _, row := range sourceLookups["trendy_cves_uris.json"] {
						if strings.Contains(v.full, row["uri"]) {
							alert.Metadata = map[string]string{"cve": row["cve"]}
							break
						}
					}
				}
				u.alerts = append(u.alerts, alert)
			}
			if blackhole > 0 {
				u.blocked[key] = sourceSuppression{e.Time.Add(blackhole), domain}
			}
		}
		u.reset(key)
	}
	// Expired suppression entries have no further effect and need not occupy memory.
	domain := "instant"
	if e.TimezoneUnknown {
		domain = "wall:" + e.File
	}
	for k, suppression := range u.blocked {
		if suppression.Domain == domain && !e.Time.Before(suppression.Until) {
			delete(u.blocked, k)
		}
	}
}
func (u *Upstream) observeAura(e Event) {
	add := func(id string) {
		key := id + "\x00" + e.IP
		if e.TimezoneUnknown {
			key += "\x00wall:" + e.File
		}
		a := u.aura[key]
		if a == nil {
			if len(u.aura) >= u.o.MaxKeys {
				u.warning("Aura match limit reached; source matches are incomplete")
				return
			}
			v := sourceAlert(e, id, e.IP, &upstreamBucket{first: e.Time, last: e.Time})
			v.Source = "AuraDFIR"
			a = &v
			u.aura[key] = a
		}
		a.Count++
		if a.Last != nil {
			if e.Time.Before(*a.First) {
				a.First = ptr(e.Time)
			}
			if e.Time.After(*a.Last) {
				a.Last = ptr(e.Time)
			}
		} else {
			wall := e.Time.Format("2006-01-02T15:04:05.999999999")
			if wall < a.WallFirst {
				a.WallFirst = wall
			}
			if wall > a.WallLast {
				a.WallLast = wall
			}
		}
		u.evidence.add(&a.Evidence, e)
		if u.evidence != nil && a.Count > int64(len(a.Evidence)) {
			a.EvidenceTruncated = true
		}
		if len(a.Events) < 8 {
			a.Events = append(a.Events, EventRef{e.File, e.Line})
		} else {
			a.EvidenceTruncated = true
		}
	}
	target := e.Target
	if strings.ContainsAny(target, "İı") {
		target = strings.Map(func(r rune) rune {
			if r == 'İ' || r == 'ı' {
				return 'i'
			}
			return r
		}, target)
	}
	for _, s := range auraSource.Signatures {
		if sourceRegex["aura/"+s.ID].MatchString(target) {
			add(s.ID)
		}
	}
	low := strings.ToLower(strings.ReplaceAll(val(e.UA), "İ", "i\u0307"))
	for _, s := range auraSource.ScannerUAs {
		if strings.Contains(low, s) {
			add("scanner_ua")
			break
		}
	}
	for _, s := range auraSource.Methods {
		if val(e.Method) == s {
			add("dangerous_method")
			break
		}
	}
}

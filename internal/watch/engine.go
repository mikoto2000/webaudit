package watch

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"webaudit/audit"
)

type EngineOptions struct {
	AllowedLateness, Retention time.Duration
	MaxEvents, MaxIncidents    int
	GeoIP                      *audit.GeoIP
	Warn                       func(string)
}

// Record retains rule IDs and hashed grouping fields, never raw requests/headers.
type Record struct {
	Event      audit.Event
	RuleIDs    []string
	ReceivedAt time.Time
}
type IncidentEvent struct {
	SchemaVersion int              `json:"schema_version"`
	EventType     string           `json:"event_type"`
	EventID       string           `json:"event_id"`
	Sequence      uint64           `json:"sequence"`
	IncidentID    string           `json:"incident_id"`
	Revision      uint64           `json:"revision"`
	CreatedAt     time.Time        `json:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at"`
	First         time.Time        `json:"first_event_at"`
	Last          time.Time        `json:"last_event_at"`
	Severity      string           `json:"severity"`
	Category      string           `json:"category"`
	Outcome       string           `json:"outcome"`
	Confidence    float64          `json:"confidence"`
	SourceIPs     []string         `json:"source_ips"`
	Evidence      []audit.EventRef `json:"evidence"`
	RuleIDs       []string         `json:"rule_ids"`
	Count         int64            `json:"count"`
	GeoIP         *audit.GeoIPInfo `json:"geoip,omitempty"`
	Notify        bool             `json:"-"`
}
type IncidentState struct {
	Event       IncidentEvent
	Fingerprint string
	Closed      bool
}
type Engine struct {
	Records        []Record
	Incidents      map[string]*IncidentState
	MaxTime        time.Time
	FinalizedUntil time.Time
	Sequence       uint64
	o              EngineOptions
	rules          map[string]audit.Rule
	dirty          bool
}

func NewEngine(o EngineOptions) *Engine {
	if o.AllowedLateness == 0 {
		o.AllowedLateness = 30 * time.Second
	}
	if o.Retention == 0 {
		o.Retention = 15 * time.Minute
	}
	if o.MaxEvents == 0 {
		o.MaxEvents = 8192
	}
	if o.MaxIncidents == 0 {
		o.MaxIncidents = 2000
	}
	e := &Engine{o: o, Incidents: map[string]*IncidentState{}, rules: map[string]audit.Rule{}}
	for _, r := range audit.Rules() {
		e.rules[r.ID] = r
	}
	return e
}
func hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func (e *Engine) warn(s string) {
	if e.o.Warn != nil {
		e.o.Warn(s)
	}
}
func sanitized(v audit.Event) audit.Event {
	p := hash(v.Path)
	lower := strings.ToLower(v.Path)
	if lower == "/login" || lower == "/signin" || strings.HasSuffix(lower, "/wp-login.php") || strings.HasSuffix(lower, "/login") {
		p = "/" + p + "/login"
	}
	r := audit.Event{Time: v.Time, IP: strings.Clone(v.IP), Path: p, Method: v.Method, Status: v.Status, Bytes: v.Bytes, File: strings.Clone(v.File), Line: v.Line, LogType: v.LogType, RequestMalformed: v.RequestMalformed}
	if v.UA != nil {
		s := hash(*v.UA)
		r.UA = &s
	}
	if v.Host != nil {
		s := hash(*v.Host)
		r.Host = &s
	}
	if v.Method != nil {
		m := *v.Method
		switch m {
		case "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE":
			m = strings.Clone(m)
		default:
			m = hash(m)
		}
		r.Method = &m
	}
	return r
}
func (e *Engine) Observe(v audit.Event, received time.Time) bool {
	if v.Time.After(received.Add(5 * time.Minute)) {
		e.warn("event more than five minutes in future discarded")
		return false
	}
	if v.Time.Before(e.FinalizedUntil) {
		e.warn("event in finalized partition discarded")
		return false
	}
	if v.TimezoneUnknown || v.LogType != "http_access-log" {
		e.warn("watch accepts timestamped access logs only")
		return false
	}
	if !e.MaxTime.IsZero() && v.Time.Before(e.MaxTime.Add(-e.o.AllowedLateness)) {
		e.warn("late event older than watermark discarded")
		return false
	}
	if v.Time.After(e.MaxTime) {
		e.MaxTime = v.Time
	}
	h, _ := audit.Detect(v)
	r := Record{Event: sanitized(v), ReceivedAt: received.UTC()}
	for _, x := range h {
		r.RuleIDs = append(r.RuleIDs, x.ID)
	}
	if len(e.Records) >= e.o.MaxEvents {
		clear(e.Records[:1])
		e.Records = e.Records[1:]
		e.warn("event retention count limit reached; detection coverage reduced")
	}
	e.Records = append(e.Records, r)
	e.dirty = true
	return true
}
func rank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}
func (e *Engine) stamp(v *IncidentEvent, kind string, now time.Time) {
	e.Sequence++
	v.SchemaVersion = 1
	v.EventType = kind
	v.Sequence = e.Sequence
	v.UpdatedAt = now.UTC()
	v.EventID = "evt-" + hash(fmt.Sprintf("%s/%d/%s", v.IncidentID, v.Revision, kind))[:32]
}
func (e *Engine) Flush(now time.Time) []IncidentEvent {
	var out []IncidentEvent
	if e.dirty {
		sorted := append([]Record(nil), e.Records...)
		sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Event.Time.Before(sorted[j].Event.Time) })
		o := audit.Options{MaxFindings: e.o.MaxIncidents, MaxEvidenceBytes: 2 << 20}
		a := audit.NewAnalysis(o)
		c := audit.NewCorrelator(o)
		for _, r := range sorted {
			var hits []audit.Rule
			for _, id := range r.RuleIDs {
				if h, ok := e.rules[id]; ok {
					hits = append(hits, h)
				}
			}
			a.Observe(r.Event, hits)
			c.Add(r.Event, hits, audit.Normalized{})
		}
		for _, s := range a.Finish() {
			c.AddSignal(s)
		}
		for _, w := range append(a.Warnings(), c.Warnings()...) {
			if strings.Contains(w, "limit") {
				e.warn(w)
			}
		}
		findings := c.Finish()
		sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
		for _, f := range findings {
			v := IncidentEvent{IncidentID: f.ID, First: f.First, Last: f.Last, Severity: f.Severity, Category: strings.Join(f.Categories, ","), Outcome: f.Outcome.Verdict, Confidence: f.Outcome.Confidence, SourceIPs: []string{f.IP}, Count: f.Count}
			for _, r := range f.Rules {
				v.RuleIDs = append(v.RuleIDs, r.ID)
			}
			for _, r := range f.Evidence {
				v.Evidence = append(v.Evidence, audit.EventRef{File: r.Event.File, Line: r.Event.Line})
			}
			b, _ := json.Marshal(v)
			fingerprint := hash(string(b))
			prev := e.Incidents[f.ID]
			if prev != nil && (prev.Closed || prev.Fingerprint == fingerprint) {
				continue
			}
			if prev == nil && len(e.Incidents) >= e.o.MaxIncidents {
				e.warn("incident retention limit reached")
				continue
			}
			kind := "incident_created"
			v.CreatedAt = now.UTC()
			v.Revision = 1
			v.Notify = true
			if prev != nil {
				kind = "incident_updated"
				v.CreatedAt = prev.Event.CreatedAt
				v.Revision = prev.Event.Revision + 1
				v.Notify = rank(v.Severity) > rank(prev.Event.Severity) || v.Outcome != prev.Event.Outcome
			}
			if e.o.GeoIP != nil {
				g := e.o.GeoIP.Lookup(f.IP)
				v.GeoIP = &g
			}
			e.stamp(&v, kind, now)
			e.Incidents[f.ID] = &IncidentState{Event: v, Fingerprint: fingerprint}
			out = append(out, v)
		}
		e.dirty = false
	}
	ids := make([]string, 0, len(e.Incidents))
	for id := range e.Incidents {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		s := e.Incidents[id]
		end := s.Event.Last.Truncate(5 * time.Minute).Add(5*time.Minute + e.o.AllowedLateness)
		if !s.Closed && (e.MaxTime.After(end) || now.Sub(s.Event.UpdatedAt) > 5*time.Minute+e.o.AllowedLateness) {
			final := s.Event.Last.Truncate(5 * time.Minute).Add(5 * time.Minute)
			if final.After(e.FinalizedUntil) {
				e.FinalizedUntil = final
			}
			v := s.Event
			v.Revision++
			v.Notify = false
			e.stamp(&v, "incident_closed", now)
			s.Event = v
			s.Closed = true
			out = append(out, v)
		}
		if s.Closed && now.Sub(s.Event.UpdatedAt) > e.o.Retention {
			delete(e.Incidents, id)
		}
	}
	kept := e.Records[:0]
	cutoff := e.MaxTime.Add(-e.o.Retention)
	for _, r := range e.Records {
		if r.Event.Time.Before(cutoff) || now.Sub(r.ReceivedAt) > e.o.Retention {
			e.dirty = true
			continue
		}
		kept = append(kept, r)
	}
	clear(e.Records[len(kept):])
	e.Records = kept
	return out
}

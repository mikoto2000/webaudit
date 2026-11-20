// Package audit analyzes untrusted access logs without network access.
package audit

import "time"

const Version = "0.2.0"
const RulesVersion = "2026.11.20.2"

type Event struct {
	SourceRequest     *string   `json:"source_request,omitempty"`
	SubType           string    `json:"sub_type,omitempty"`
	RawRequest        *string   `json:"raw_request"`
	RequestMalformed  bool      `json:"request_malformed,omitempty"`
	LogType           string    `json:"log_type"`
	AuthFailure       bool      `json:"auth_failure,omitempty"`
	TimezoneUnknown   bool      `json:"timezone_unknown,omitempty"`
	WallTime          *string   `json:"wall_time,omitempty"`
	Envelope          *string   `json:"syslog_envelope,omitempty"`
	Suffix            *string   `json:"unmapped_suffix,omitempty"`
	EvidenceTruncated bool      `json:"evidence_truncated,omitempty"`
	Time              time.Time `json:"time"`
	IP                string    `json:"ip"`
	Host              *string   `json:"host"`
	Method            *string   `json:"method"`
	Target            string    `json:"target"`
	Path              string    `json:"path"`
	Query             *string   `json:"query"`
	Protocol          *string   `json:"protocol"`
	Status            *int      `json:"status"`
	Bytes             *int64    `json:"bytes"`
	UA                *string   `json:"user_agent"`
	Referer           *string   `json:"referer"`
	File              string    `json:"file"`
	Line              int64     `json:"line"`
	Raw               string    `json:"raw"`
}
type Options struct {
	ErrorTimezone    string
	DeduplicateFiles bool
	Now              func() time.Time
	MaxEvidenceBytes int
	MaxLineBytes     int
	MaxFileBytes     int64
	MaxKeys          int
	MaxFindings      int
	LogRegex         string
}

func (o Options) defaults() Options {
	if o.MaxLineBytes <= 0 {
		o.MaxLineBytes = 64 * 1024
	}
	if o.MaxFileBytes <= 0 {
		o.MaxFileBytes = 8 << 30
	}
	if o.MaxKeys <= 0 {
		o.MaxKeys = 4096
	}
	if o.MaxFindings <= 0 {
		o.MaxFindings = 2000
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.MaxEvidenceBytes <= 0 {
		o.MaxEvidenceBytes = 32 << 20
	}
	return o
}

type Input struct {
	DuplicateOf string `json:"duplicate_of,omitempty"`
	Path        string `json:"path"`
	Parsed      int64  `json:"parsed"`
	Unparsed    int64  `json:"unparsed"`
	Error       string `json:"error,omitempty"`
}
type Report struct {
	UpstreamSources map[string]string `json:"upstream_sources"`
	ErrorTimezone   string            `json:"error_timezone,omitempty"`
	AuraAnalysis    []SourceAlert     `json:"aura_analysis"`
	UpstreamAlerts  []SourceAlert     `json:"upstream_alerts"`
	AuraMatches     []SourceAlert     `json:"aura_matches"`
	UpstreamRules   []SourceRule      `json:"upstream_rules"`
	Findings        []Incident        `json:"findings"`
	Categories      map[string]int    `json:"categories"`
	Outcomes        map[string]int    `json:"outcomes"`
	Severities      map[string]int    `json:"severities"`
	Schema          string            `json:"schema"`
	Version         string            `json:"version"`
	RulesVersion    string            `json:"rules_version"`
	AnalyzedAt      time.Time         `json:"analyzed_at"`
	Files           []Input           `json:"files"`
	Parsed          int64             `json:"requests"`
	Unparsed        int64             `json:"unparsed"`
	Duplicates      int64             `json:"duplicates"`
	First           *time.Time        `json:"first"`
	Last            *time.Time        `json:"last"`
	Warnings        []string          `json:"warnings"`
	Partial         bool              `json:"partial"`
	Missing         map[string]int64  `json:"missing_fields"`
}

func (r *Report) warn(s string) {
	for _, x := range r.Warnings {
		if x == s {
			return
		}
	}
	if len(r.Warnings) < 50 {
		r.Warnings = append(r.Warnings, s)
	}
}
func ptr[T any](v T) *T { return &v }
func val[T any](p *T) T {
	if p != nil {
		return *p
	}
	var z T
	return z
}

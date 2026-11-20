// Package audit analyzes untrusted access logs without network access.
package audit

import "time"

const Version = "0.1.0"
const RulesVersion = "2026.11.20.1"

type Event struct {
 EvidenceTruncated bool `json:"evidence_truncated,omitempty"`
	Time     time.Time `json:"time"`
	IP       string    `json:"ip"`
	Host     *string   `json:"host"`
	Method   *string   `json:"method"`
	Target   string    `json:"target"`
	Path     string    `json:"path"`
	Query    *string   `json:"query"`
	Protocol *string   `json:"protocol"`
	Status   *int      `json:"status"`
	Bytes    *int64    `json:"bytes"`
	UA       *string   `json:"user_agent"`
	Referer  *string   `json:"referer"`
	File     string    `json:"file"`
	Line     int64     `json:"line"`
	Raw      string    `json:"raw"`
}
type Options struct {
	MaxLineBytes int
	MaxFileBytes int64
	MaxKeys      int
	MaxFindings  int
	LogRegex     string
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
	return o
}

type Input struct {
	Path     string `json:"path"`
	Parsed   int64  `json:"parsed"`
	Unparsed int64  `json:"unparsed"`
	Error    string `json:"error,omitempty"`
}
type Report struct {
	Findings     []Incident       `json:"findings"`
	Categories   map[string]int   `json:"categories"`
	Outcomes     map[string]int   `json:"outcomes"`
	Severities   map[string]int   `json:"severities"`
	Schema       string           `json:"schema"`
	Version      string           `json:"version"`
	RulesVersion string           `json:"rules_version"`
	AnalyzedAt   time.Time        `json:"analyzed_at"`
	Files        []Input          `json:"files"`
	Parsed       int64            `json:"requests"`
	Unparsed     int64            `json:"unparsed"`
	Duplicates   int64            `json:"duplicates"`
	First        *time.Time       `json:"first"`
	Last         *time.Time       `json:"last"`
	Warnings     []string         `json:"warnings"`
	Partial      bool             `json:"partial"`
	Missing      map[string]int64 `json:"missing_fields"`
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

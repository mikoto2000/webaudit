package audit

import "strings"

// SourceEvidence is a bounded raw log sample captured during input parsing.
type SourceEvidence struct {
	File              string `json:"file"`
	Line              int64  `json:"line"`
	Raw               string `json:"raw"`
	EvidenceTruncated bool   `json:"evidence_truncated,omitempty"`
}

type upstreamEvidence struct{ limit, retained int64 }

func (b *upstreamEvidence) add(samples *[]SourceEvidence, e Event) {
	if b == nil || len(*samples) >= 8 {
		return
	}
	raw, cut := clipped(e.Raw, 4096)
	size := int64(len(raw)) + int64(len(e.File)) + 64
	if size > b.limit-b.retained {
		return
	}
	b.retained += size
	*samples = append(*samples, SourceEvidence{File: strings.Clone(e.File), Line: e.Line, Raw: strings.Clone(raw), EvidenceTruncated: cut || e.EvidenceTruncated})
}

func (b *upstreamEvidence) attach(a *SourceAlert, samples []SourceEvidence) {
	if b == nil {
		return
	}
	a.Evidence = append([]SourceEvidence(nil), samples...)
	if a.Count > int64(len(samples)) {
		a.EvidenceTruncated = true
	}
}

package audit

import (
	"crypto/sha256"
	"strings"
	"unicode/utf8"
)

// Digest keys bound attacker-controlled cardinality entry size. Full source
// records remain on disk, referenced by file and line.
func digest(s string) string { v := sha256.Sum256([]byte(s)); return string(v[:]) }
func clipped(s string, n int) (string, bool) {
	cut := len(s) > n
	if cut {
		s = s[:n]
		for !utf8.ValidString(s) && len(s) > 0 {
			s = s[:len(s)-1]
		}
	}
	return strings.Clone(s), cut
}
func compactEvent(e Event) Event {
	clip := func(s string, n int) string {
		v, cut := clipped(s, n)
		e.EvidenceTruncated = e.EvidenceTruncated || cut
		return v
	}
	optional := func(s *string, n int) *string {
		if s == nil {
			return nil
		}
		return ptr(clip(*s, n))
	}
	e.SourceRequest = optional(e.SourceRequest, 4096)
	e.RawRequest = optional(e.RawRequest, 4096)
	e.Envelope = optional(e.Envelope, 1024)
	e.Suffix = optional(e.Suffix, 1024)
	e.Raw = clip(e.Raw, 4096)
	e.Target = clip(e.Target, 4096)
	e.Path = clip(e.Path, 1024)
	e.IP = strings.Clone(e.IP)
	e.UA = optional(e.UA, 512)
	e.Host = optional(e.Host, 255)
	e.Referer = optional(e.Referer, 512)
	e.Query = optional(e.Query, 2048)
	e.Method = optional(e.Method, 32)
	e.Protocol = optional(e.Protocol, 32)
	return e
}
func compactNormalized(n Normalized) Normalized {
	n.Original, _ = clipped(n.Original, 4096)
	v := make([]string, len(n.Variants))
	for i, s := range n.Variants {
		v[i], _ = clipped(s, 1024)
	}
	n.Variants = v
	return n
}
func evidenceSize(v Evidence) int {
	e := v.Event
	n := v.Normalization
	size := len(e.Raw) + len(e.Target) + len(e.Path) + len(val(e.Query)) + len(val(e.UA)) + len(val(e.Host)) + len(val(e.Referer)) + len(n.Original)
	size += len(val(e.RawRequest)) + len(val(e.Envelope)) + len(val(e.Suffix)) + len(val(e.WallTime))
	for _, s := range n.Variants {
		size += len(s)
	}
	return size
}

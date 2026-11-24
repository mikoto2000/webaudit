package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundleStatisticsUseAllRequestsAndPreserveZeroAndMissing(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "access.log")
	text := `{"remote_addr":"192.0.2.1","time_iso8601":"2026-11-01T00:00:00Z","request":"GET /healthy HTTP/1.1","status":200,"body_bytes_sent":0,"request_time":"0","http_user_agent":"Browser"}` + "\n" +
		`192.0.2.2 - - [01/Nov/2026:00:01:00 +0000] "HEAD /.env HTTP/1.1" 404 42 "-" "Browser"` + "\n" +
		`192.0.2.2 - - [01/Nov/2026:00:02:00 +0000] "POST /healthy HTTP/1.1" 500 84` + "\n"
	if err := os.WriteFile(input, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "report")
	r, err := GenerateBundle([]string{input}, target, Options{}, BundleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	stats := r.Statistics
	if stats.TotalRequests != 3 || stats.UniqueIPs != 2 || stats.ResponseBytes.Count != 3 || stats.ResponseBytes.Min == nil || *stats.ResponseBytes.Min != 0 || stats.ResponseBytes.Mean == nil || *stats.ResponseBytes.Mean != 42 {
		t.Fatalf("bad full statistics: %+v", stats)
	}
	if stats.RequestDuration.Count != 1 || stats.RequestDuration.Missing != 2 || stats.RequestDuration.Min == nil || *stats.RequestDuration.Min != 0 {
		t.Fatal(stats.RequestDuration)
	}
	for _, dimension := range []string{"method", "status", "status_class", "ip", "host", "uri", "user_agent"} {
		var sum int64
		for _, row := range stats.Dimensions[dimension] {
			sum += row.Requests
		}
		if sum != 3 {
			t.Fatal("inconsistent denominator", dimension, sum)
		}
	}
	if len(stats.Timeline) != 3 || stats.TimelineResolutionSeconds != 60 {
		t.Fatal(stats.Timeline)
	}
	rows := bundleCSV(t, filepath.Join(target, "statistics", "method-summary.csv"))
	if len(rows) != 3 {
		t.Fatal(rows)
	}
	limited, err := GenerateBundle([]string{input}, filepath.Join(dir, "limited"), Options{}, BundleOptions{MaxSpoolBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if limited.Statistics.TotalRequests != 3 || limited.EvidenceComplete {
		t.Fatal("spool limit changed whole-input request count")
	}
}
func TestBundleStatisticsBoundCardinalityAndAdaptTimeline(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "access.log")
	lines := []string{
		`192.0.2.1 - - [01/Jan/2026:00:00:00 +0000] "GET /one HTTP/1.1" 200 0`,
		`192.0.2.2 - - [01/Jun/2026:00:00:00 +0000] "GET /two HTTP/1.1" 200 0`,
		`192.0.2.3 - - [01/Nov/2026:00:00:00 +0000] "GET /three HTTP/1.1" 200 0`,
	}
	if err := os.WriteFile(input, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := GenerateBundle([]string{input}, filepath.Join(dir, "report"), Options{MaxKeys: 2}, BundleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Statistics.Truncated || r.Statistics.UniqueIPQuality != "lower_bound" || r.Statistics.TimelineResolutionSeconds < 86400 {
		t.Fatal(r.Statistics)
	}
	for _, dim := range []string{"ip", "uri"} {
		var sum int64
		for _, row := range r.Statistics.Dimensions[dim] {
			sum += row.Requests
		}
		if sum != 3 || len(r.Statistics.Dimensions[dim]) > 3 {
			t.Fatal("lost or unbounded groups", dim)
		}
	}
}

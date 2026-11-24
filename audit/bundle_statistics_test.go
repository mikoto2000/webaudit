package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStatisticsCSVSeparatesSuspiciousCountQuality(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "access.log")
	if err := os.WriteFile(input, []byte(`192.0.2.1 - - [01/Nov/2026:00:00:00 +0000] "GET /healthy HTTP/1.1" 200 0`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "report")
	if _, err := GenerateBundle([]string{input}, target, Options{}, BundleOptions{MaxSpoolBytes: 1}); err != nil {
		t.Fatal(err)
	}
	for _, row := range bundleCSV(t, filepath.Join(target, "statistics", "method-summary.csv")) {
		if row["suspicious_count_quality"] != "lower_bound" {
			t.Fatal("incomplete suspicious count presented without its quality", row)
		}
	}
}

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

func TestBundleStatisticsGeoAndInvalidDuration(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "access.log")
	raw := `{"remote_addr":"8.8.8.8","time_iso8601":"2026-11-01T00:00:00Z","request":"GET /.env HTTP/1.1","status":404,"body_bytes_sent":0,"request_time":"NaN"}`
	if err := os.WriteFile(input, []byte(raw+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := GenerateBundle([]string{input}, filepath.Join(dir, "report"), Options{GeoIP: testGeo(t, 64)}, BundleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Statistics.GeoIPEnabled || len(r.Statistics.Dimensions["country"]) != 1 || len(r.Statistics.Dimensions["asn"]) != 1 {
		t.Fatal(r.Statistics)
	}
	if r.Statistics.RequestDuration.Count != 0 || r.Statistics.RequestDuration.Invalid != 1 || r.Statistics.RequestDuration.Missing != 0 || r.Statistics.RequestDuration.Min != nil {
		t.Fatal("invalid duration fabricated", r.Statistics.RequestDuration)
	}
	country := r.Statistics.Dimensions["country"][0]
	if country.Requests != 1 || country.SuspiciousRequests != 1 || country.UniqueIPs == nil || *country.UniqueIPs != 1 {
		t.Fatal(country)
	}
}

func TestBundleRecordsMatchedParserAndHandlesNumericOverflow(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "access.log")
	jsonLine := `{"remote_addr":"192.0.2.1","time_iso8601":"2026-11-01T00:00:00Z","request":"GET / HTTP/1.1","status":200,"body_bytes_sent":0,"request_time":"1e308"}`
	text := jsonLine + "\n" + jsonLine + "\n" + `192.0.2.1 - - [01/Nov/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 0` + "\n"
	if err := os.WriteFile(input, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := GenerateBundle([]string{input}, filepath.Join(dir, "report"), Options{}, BundleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Statistics.RequestDuration.Mean != nil || r.Statistics.RequestDuration.SumQuality != "overflow" {
		t.Fatal("nonfinite sum hidden", r.Statistics.RequestDuration)
	}
	formats := strings.Join(r.Inventory[0].Formats, ";")
	if !strings.Contains(formats, "nginx-json") || !strings.Contains(formats, "apache-nginx-common") {
		t.Fatal("matched parser not recorded", formats)
	}
}

package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCoverageSeparatesNoHitUnsupportedAndPartialHit(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "access.log")
	line := `192.0.2.1 - - [01/Nov/2026:00:00:00 +0000] "GET /.env HTTP/1.1" 404 0`
	if err := os.WriteFile(input, []byte(line+"\nbad record\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := GenerateBundle([]string{input}, filepath.Join(dir, "report"), Options{}, BundleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]CoverageRow{}
	for _, row := range r.Coverage {
		byID[row.ID] = row
	}
	sensitive := byID["ASPECT-sensitive_file"]
	if !sensitive.HasDetections || sensitive.Complete || sensitive.Status != "partial" || sensitive.DetectedRequests == nil || *sensitive.DetectedRequests != 1 {
		t.Fatal(sensitive)
	}
	reputation := byID["ASPECT-ip_reputation"]
	if reputation.Status != "unsupported" || reputation.HasDetections {
		t.Fatal(reputation)
	}
	if byID["RULE-webaudit-WA-method"].Status != "partial" {
		t.Fatal("partial input reported complete")
	}
	if byID["RULE-webaudit-WA-scanner"].Status != "unable" {
		t.Fatal("absent UA reported no-hit")
	}
	// Every embedded source and independent signature is represented even without hits.
	for _, rule := range Rules() {
		if _, ok := byID["RULE-webaudit-"+rule.ID]; !ok {
			t.Fatal("rule missing", rule.ID)
		}
	}
	for _, rule := range sourceRules {
		if _, ok := byID["RULE-hub-"+rule.ID]; !ok {
			t.Fatal("source rule missing", rule.ID)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "report", "analysis-coverage.csv")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "report", "analysis-rules.csv")); err != nil {
		t.Fatal(err)
	}
}
func TestCoverageNoHitAndInsufficientStatisticalBaseline(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "access.log")
	line := `192.0.2.1 - - [01/Nov/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 0 "-" "Browser"`
	if err := os.WriteFile(input, []byte(line+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := GenerateBundle([]string{input}, filepath.Join(dir, "report"), Options{}, BundleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range r.Coverage {
		if row.ID == "RULE-webaudit-WA-sqli" && (row.Status != "no_detection" || !row.Complete) {
			t.Fatal(row)
		}
		if row.ID == "RULE-webaudit-WS-ip" && row.Status != "unable" {
			t.Fatal("insufficient peers treated as evaluated", row)
		}
	}
}

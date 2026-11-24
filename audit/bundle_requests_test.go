package audit

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func bundleCSV(t *testing.T, path string) []map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("no header")
	}
	var out []map[string]string
	for _, row := range rows[1:] {
		m := map[string]string{}
		for i, v := range row {
			m[rows[0][i]] = v
		}
		out = append(out, m)
	}
	return out
}
func TestFullRequestExportPreservesDistinctObservationsAndSeparatesRelated(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "access.log")
	var text strings.Builder
	for i := 0; i < 25; i++ {
		fmt.Fprintln(&text, `192.0.2.1 - - [01/Nov/2026:00:00:00 +0000] "GET /.env?x=<script> HTTP/1.1" 404 0 "-" "Browser"`)
	}
	for i := 0; i < 600; i++ {
		fmt.Fprintln(&text, `192.0.2.1 - - [01/Nov/2026:00:00:00 +0000] "GET /healthy HTTP/1.1" 200 0 "-" "Browser"`)
	}
	if err := os.WriteFile(input, []byte(text.String()), 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "report")
	r, err := GenerateBundle([]string{input}, target, Options{}, BundleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	suspicious := bundleCSV(t, filepath.Join(target, "suspicious-requests.csv"))
	related := bundleCSV(t, filepath.Join(target, "related-requests.csv"))
	detections := bundleCSV(t, filepath.Join(target, "detections.csv"))
	if len(suspicious) != 25 {
		t.Fatalf("expected 25 direct observations, got %d", len(suspicious))
	}
	ids := map[string]bool{}
	for _, row := range suspicious {
		if ids[row["request_id"]] {
			t.Fatal("duplicated request")
		}
		ids[row["request_id"]] = true
		if row["source_line"] == "" || row["source_file_id"] == "" || row["finding_ids"] == "" || row["detection_ids"] == "" {
			t.Fatal("missing traceability", row)
		}
		if _, ok := row["outcome"]; ok {
			t.Fatal("incident outcome copied to request")
		}
	}
	if len(related) < 600 || len(detections) <= 25 || !r.EvidenceComplete {
		t.Fatalf("missing late analysis: related=%d detections=%d complete=%v", len(related), len(detections), r.EvidenceComplete)
	}
	foundNormal := false
	for _, row := range related {
		foundNormal = foundNormal || row["request_uri"] == "/healthy"
	}
	if !foundNormal {
		t.Fatal("aggregate context missing")
	}
	if leftovers, _ := filepath.Glob(filepath.Join(target, ".requests-*")); len(leftovers) > 0 {
		t.Fatal("private spool remains", leftovers)
	}
}
func TestLateStatisticalEvidenceAndSpoolLimit(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "access.log")
	var text strings.Builder
	for ip := 1; ip <= 21; ip++ {
		n := 1
		if ip == 21 {
			n = 200
		}
		for i := 0; i < n; i++ {
			fmt.Fprintf(&text, "192.0.2.%d - - [01/Nov/2026:00:00:00 +0000] \"GET /healthy HTTP/1.1\" 200 0 \"-\" \"Browser\"\n", ip)
		}
	}
	if err := os.WriteFile(input, []byte(text.String()), 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "report")
	r, err := GenerateBundle([]string{input}, target, Options{}, BundleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rows := bundleCSV(t, filepath.Join(target, "related-requests.csv"))
	found := false
	for _, row := range rows {
		if row["source_ip"] == "192.0.2.21" && strings.Contains(row["rule_ids"], "WS-ip") {
			found = true
		}
	}
	if !found || !r.EvidenceComplete {
		t.Fatal("end-of-analysis statistics not associated", r.EvidenceComplete)
	}
	limited := filepath.Join(dir, "limited")
	r, err = GenerateBundle([]string{input}, limited, Options{}, BundleOptions{MaxSpoolBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if r.EvidenceComplete || r.Complete || r.Status != "partial" {
		t.Fatal("spool truncation hidden")
	}
	if leftovers, _ := filepath.Glob(filepath.Join(limited, ".requests-*")); len(leftovers) > 0 {
		t.Fatal("spool remains")
	}
}

func TestHubMembershipDistinguishesSuppressedAndDistinctCandidates(t *testing.T) {
	// Use an existing matcher with small bucket settings to exercise full membership.
	original := sourceRules
	defer func() { sourceRules = original }()
	sourceRules = []SourceRule{{ID: "crowdsecurity/http-probing", Type: "leaky", Capacity: 2, Distinct: "evt.Meta.http_path", Group: "evt.Meta.source_ip", Supported: true, blackholeDuration: time.Minute, leakDuration: time.Minute}}
	dir := t.TempDir()
	input := filepath.Join(dir, "a.log")
	var text strings.Builder
	for _, path := range []string{"/a", "/a", "/b", "/c", "/d", "/e", "/f"} {
		fmt.Fprintf(&text, "192.0.2.1 - - [01/Nov/2026:00:00:00 +0000] \"GET %s HTTP/1.1\" 404 0\n", path)
	}
	if err := os.WriteFile(input, []byte(text.String()), 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "report")
	r, err := GenerateBundle([]string{input}, target, Options{}, BundleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rows := bundleCSV(t, filepath.Join(target, "suspicious-requests.csv"))
	var sourceLines []string
	for _, row := range rows {
		if strings.Contains(row["detection_engines"], "hub") {
			sourceLines = append(sourceLines, row["source_line"])
		}
	}
	if strings.Join(sourceLines, ",") != "1,3,4" {
		t.Fatal("duplicate or suppressed candidate treated as emitted detection", sourceLines)
	}
	if len(r.Analysis.UpstreamAlerts) != 1 {
		t.Fatal(r.Analysis.UpstreamAlerts)
	}
}

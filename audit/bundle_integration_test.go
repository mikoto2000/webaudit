package audit

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBundleRotatedGzipOutOfOrderAndSharedCounts(t *testing.T) {
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "access.log.1.gz"), filepath.Join(dir, "access.log")}
	for part, p := range paths {
		var text strings.Builder
		for i := 0; i < 350; i++ {
			fmt.Fprintf(&text, "192.0.2.1 - - [01/Nov/2026:00:00:%02d +0000] \"GET /.env HTTP/1.1\" 200 42 \"-\" \"Browser\"\n", (699-part*350-i)%60)
		}
		if part == 0 {
			f, err := os.Create(p)
			if err != nil {
				t.Fatal(err)
			}
			z := gzip.NewWriter(f)
			if _, err = z.Write([]byte(text.String())); err != nil {
				t.Fatal(err)
			}
			if err = z.Close(); err != nil {
				t.Fatal(err)
			}
			if err = f.Close(); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(p, []byte(text.String()), 0600); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(dir, "bundle")
	r, err := GenerateBundle(paths, target, Options{}, BundleOptions{Language: "en"})
	if err != nil {
		t.Fatal(err)
	}
	rows := bundleCSV(t, filepath.Join(target, "suspicious-requests.csv"))
	if len(rows) != 700 || r.Summary.TotalRequests != 700 || r.Summary.SuspiciousRequests != 700 {
		t.Fatal("source observations lost", len(rows), r.Summary)
	}
	files := map[string]bool{}
	ids := map[string]bool{}
	for _, row := range rows {
		if ids[row["request_id"]] {
			t.Fatal("duplicate observation")
		}
		ids[row["request_id"]] = true
		files[row["source_file_id"]] = true
	}
	if len(files) != 2 {
		t.Fatal("rotated source trace lost")
	}
	found := false
	for _, row := range r.Coverage {
		if row.ID == "ASPECT-rate" {
			found = true
			if row.DetectedRequests == nil || row.RelatedRequests == nil || *row.RelatedRequests != 700 || row.Detections == nil || *row.Detections == 0 {
				t.Fatal("aggregate perspective lacks exact request membership", row)
			}
		}
	}
	if !found {
		t.Fatal("rate perspective absent")
	}
	var common InvestigationReport
	data, err := os.ReadFile(filepath.Join(target, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &common); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(common.Summary, r.Summary) {
		t.Fatal("serialized summary differs")
	}
	for _, f := range r.Analysis.Findings {
		if f.Outcome.Verdict == "confirmed_success" {
			t.Fatal("HTTP200 confirmed intrusion")
		}
	}
	if matches, _ := filepath.Glob(filepath.Join(target, ".requests-*")); len(matches) != 0 {
		t.Fatal("private spool retained")
	}
}

func TestBundleNoHitEmptyAndFormulaSafeMetadata(t *testing.T) {
	for _, raw := range []string{"", `192.0.2.1 - - [01/Nov/2026:00:00:00 +0000] "GET /healthy HTTP/1.1" 200 0` + "\n"} {
		dir := t.TempDir()
		p := filepath.Join(dir, "normal.log")
		if err := os.WriteFile(p, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		r, err := GenerateBundle([]string{p}, filepath.Join(dir, "report"), Options{}, BundleOptions{Title: "=HYPERLINK(\"evil\")"})
		if err != nil {
			t.Fatal(err)
		}
		if r.Summary.SuspiciousRequests != 0 || len(r.Analysis.Findings) != 0 {
			t.Fatal("invented malicious request")
		}
		html, err := os.ReadFile(filepath.Join(dir, "report", "report.html"))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(html), "<script") || strings.Contains(string(html), "https://cdn.") {
			t.Fatal("active external content")
		}
	}
	if got := csvSafe("=HYPERLINK(\"evil\")"); !strings.HasPrefix(got, "'") {
		t.Fatal("formula not guarded", got)
	}
}

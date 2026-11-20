package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"webaudit/audit"
)

const logLine = `192.0.2.1 - - [01/Nov/2026:00:00:00 +0000] "GET /.env HTTP/1.1" 200 42`

func TestCLI(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "access.log")
	_ = os.WriteFile(p, []byte(logLine+"\n"), 0600)
	for _, args := range [][]string{{p}, {p, "--verbose"}, {p, "--format", "json"}, {"--format=csv", p}} {
		var out, err bytes.Buffer
		if code := run(args, &out, &err); code != 0 {
			t.Fatalf("%v code %d %s", args, code, err.String())
		}
		if out.Len() == 0 {
			t.Fatal("empty output")
		}
	}
	entries, _ := os.ReadDir(d)
	if len(entries) != 1 {
		t.Fatal("unsolicited output file")
	}
	outPath := filepath.Join(d, "report.html")
	var out, err bytes.Buffer
	if run([]string{p, "-o", outPath}, &out, &err) != 0 {
		t.Fatal(err.String())
	}
	b, _ := os.ReadFile(outPath)
	if !strings.Contains(string(b), "<!doctype html>") {
		t.Fatal(string(b))
	}
	if run([]string{p, "-o", p}, &out, &err) != 2 {
		t.Fatal("input overwrite")
	}
	orig, _ := os.ReadFile(p)
	if string(orig) != logLine+"\n" {
		t.Fatal("changed original")
	}
	if run([]string{p, "-o", outPath}, &out, &err) != 2 {
		t.Fatal("report overwrite")
	}
	if run(nil, &out, &err) != 2 || run([]string{p, "--format", "invalid"}, &out, &err) != 2 || run([]string{p, "--max-keys", "-1"}, &out, &err) != 2 {
		t.Fatal("bad arguments accepted")
	}
	if run([]string{filepath.Join(d, "missing")}, &out, &err) != 1 {
		t.Fatal("missing input successful")
	}
}

func TestGeoIPCLI(t *testing.T) {
	p := filepath.Join(t.TempDir(), "access.log")
	os.WriteFile(p, []byte(strings.Replace(logLine, "192.0.2.1", "8.8.8.8", 1)+"\n"), 0600)
	for _, format := range []string{"json", "csv", "html", "summary"} {
		args := []string{p, "--geoip-country", "../../audit/testdata/geoip/country.mmdb", "--geoip-asn", "../../audit/testdata/geoip/asn.mmdb"}
		if format != "summary" {
			args = append(args, "--format", format)
		}
		var out, err bytes.Buffer
		if code := run(args, &out, &err); code != 0 {
			t.Fatalf("%s: %d %s", format, code, err.String())
		}
		if !strings.Contains(out.String(), "64500") {
			t.Fatal("missing ASN", format)
		}
	}
	for _, path := range []string{filepath.Join(t.TempDir(), "missing.mmdb"), p} {
		var out, err bytes.Buffer
		if run([]string{p, "--geoip-country", path}, &out, &err) != 2 || !strings.Contains(err.String(), "GeoIP country database") || out.Len() != 0 {
			t.Fatalf("explicit invalid DB: %s %s", out.String(), err.String())
		}
	}
}

func TestFailedReportFileIsRemovedAndCanBeRetried(t *testing.T) {
	for _, failure := range []string{"write", "close"} {
		t.Run(failure, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "report.html")
			f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			injected := errors.New("injected write failure")
			err = writeAndCloseReport(f, func(w io.Writer) error {
				if _, err := io.WriteString(w, "partial sensitive report"); err != nil {
					return err
				}
				if failure == "close" {
					return f.Close()
				}
				return injected
			})
			if err == nil || failure == "write" && !errors.Is(err, injected) {
				t.Fatal("failure lost", err)
			}
			if _, err = os.Lstat(path); !os.IsNotExist(err) {
				t.Fatal("failed output remains", err)
			}
			log := filepath.Join(t.TempDir(), "access.log")
			if err = os.WriteFile(log, []byte(logLine+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			var out, stderr bytes.Buffer
			if code := run([]string{log, "-o", path}, &out, &stderr); code != 0 {
				t.Fatal("cannot retry", code, stderr.String())
			}
		})
	}
}

type failedSummaryWriter struct{}

func (failedSummaryWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestSuccessfulReportSurvivesSummaryFailure(t *testing.T) {
	log := filepath.Join(t.TempDir(), "access.log")
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(log, []byte(logLine+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := run([]string{log, "-o", path, "--format", "json"}, failedSummaryWriter{}, &stderr); code != 1 {
		t.Fatal(code, stderr.String())
	}
	data, err := os.ReadFile(path)
	var r audit.Report
	if err != nil || json.Unmarshal(data, &r) != nil || r.Parsed != 1 {
		t.Fatal("successful report removed or incomplete", err)
	}
}

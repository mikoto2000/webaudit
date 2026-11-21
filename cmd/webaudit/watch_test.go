package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"webaudit/internal/watch"
)

func TestWatchHelp(t *testing.T) {
	var out, errout bytes.Buffer
	if code := run([]string{"watch", "--help"}, &out, &errout); code != 0 || !strings.Contains(errout.String(), "--from") {
		t.Fatalf("%d %s", code, errout.String())
	}
}

type cancelWriter struct {
	bytes.Buffer
	cancel context.CancelFunc
}

func (w *cancelWriter) Write(b []byte) (int, error) {
	n, e := w.Buffer.Write(b)
	w.cancel()
	return n, e
}
func watchOnce(t *testing.T, args []string) (watch.IncidentEvent, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out := &cancelWriter{cancel: cancel}
	var errout bytes.Buffer
	code := runWatchContext(ctx, args, out, &errout)
	if code != 0 {
		t.Fatalf("watch code %d: %s", code, errout.String())
	}
	var v watch.IncidentEvent
	if e := json.Unmarshal(out.Bytes(), &v); e != nil {
		t.Fatalf("not one JSON event: %q %v", out.String(), e)
	}
	return v, errout.String()
}
func TestWatchCLIJSONRestartAndGeoIP(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateDir)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	p := filepath.Join(t.TempDir(), "access.log")
	line := func(i, status int) string {
		return fmt.Sprintf("8.8.8.8 - - [01/Nov/2026:00:00:%02d +0000] \"GET /.env?token=SECRET HTTP/1.1\" %d 100\n", i, status)
	}
	if e := os.WriteFile(p, []byte(line(0, 404)), 0600); e != nil {
		t.Fatal(e)
	}
	country, _ := filepath.Abs("../../audit/testdata/geoip/country.mmdb")
	asn, _ := filepath.Abs("../../audit/testdata/geoip/asn.mmdb")
	args := []string{p, "--format", "jsonl", "--from", "beginning", "--geoip-country", country, "--geoip-asn", asn}
	first, diagnostics := watchOnce(t, args)
	if first.GeoIP == nil || first.GeoIP.ASN == nil || strings.Contains(diagnostics, "SECRET") {
		t.Fatal(first, diagnostics)
	}
	f, e := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	f.WriteString(line(1, 200) + line(2, 200))
	f.Close()
	updated, _ := watchOnce(t, args)
	if updated.IncidentID != first.IncidentID || updated.Revision != 2 || updated.Outcome != "possible_success" {
		t.Fatal(first, updated)
	}
	reset, _ := watchOnce(t, append(args, "--reset-state"))
	if reset.Revision != 1 {
		t.Fatal(reset)
	}
}
func TestWatchCLINoState(t *testing.T) {
	d := filepath.Join(t.TempDir(), "must-not-exist")
	t.Setenv("XDG_STATE_HOME", d)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	p := filepath.Join(t.TempDir(), "access.log")
	os.WriteFile(p, []byte("8.8.8.8 - - [01/Nov/2026:00:00:00 +0000] \"GET /.env HTTP/1.1\" 404 0\n"), 0600)
	v, _ := watchOnce(t, []string{p, "--from", "beginning", "--format", "jsonl", "--no-state"})
	if v.Revision != 1 {
		t.Fatal(v)
	}
	if _, e := os.Stat(d); !os.IsNotExist(e) {
		t.Fatal("no-state persisted", e)
	}
}

func TestWatchCLIDeduplicatesDiagnostics(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	p := filepath.Join(t.TempDir(), "access.log")
	os.WriteFile(p, []byte(strings.Repeat("unparseable\n", 1000)), 0600)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	var out, errout bytes.Buffer
	if code := runWatchContext(ctx, []string{p, "--no-state", "--from", "beginning"}, &out, &errout); code != 0 {
		t.Fatal(code, errout.String())
	}
	if count := strings.Count(errout.String(), "unparsed access log line"); count != 1 {
		t.Fatal("diagnostic flood", count)
	}
	if !strings.Contains(errout.String(), "999 repeated/excess diagnostics suppressed") {
		t.Fatal(errout.String())
	}
}

type diagnosticCancelWriter struct {
	bytes.Buffer
	cancel context.CancelFunc
}

func (w *diagnosticCancelWriter) Write(b []byte) (int, error) {
	n, e := w.Buffer.Write(b)
	if bytes.Contains(b, []byte("unparsed access log line")) {
		w.cancel()
	}
	return n, e
}
func TestWatchCLICancelFlushesConsumedEvents(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	p := filepath.Join(t.TempDir(), "access.log")
	line := "8.8.8.8 - - [01/Nov/2026:00:00:00 +0000] \"GET /.env HTTP/1.1\" 404 0\n"
	os.WriteFile(p, []byte(line+strings.Repeat("bad\n", 10000)), 0600)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errout := &diagnosticCancelWriter{cancel: cancel}
	var out bytes.Buffer
	if code := runWatchContext(ctx, []string{p, "--no-state", "--from", "beginning", "--format", "jsonl"}, &out, errout); code != 0 {
		t.Fatal(code, errout.String())
	}
	var v watch.IncidentEvent
	if e := json.Unmarshal(out.Bytes(), &v); e != nil || v.EventType != "incident_created" {
		t.Fatal("consumed detection lost on cancel", out.String(), e)
	}
}

func TestWatchHookArguments(t *testing.T) {
	var out, errout bytes.Buffer
	if code := run([]string{"watch", "--help"}, &out, &errout); code != 0 || !strings.Contains(errout.String(), "on-detect-arg") {
		t.Fatalf("%d %s", code, errout.String())
	}
	errout.Reset()
	if code := run([]string{"watch", "--on-detect-arg=-File", "access.log"}, &out, &errout); code != 2 || !strings.Contains(errout.String(), "preceding --on-detect") {
		t.Fatalf("%d %s", code, errout.String())
	}
}

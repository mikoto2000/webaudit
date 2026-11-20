package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

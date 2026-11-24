package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerboseInputProgress(t *testing.T) {
	for _, bundle := range []bool{false, true} {
		for _, verbose := range []bool{false, true} {
			d := t.TempDir()
			p := filepath.Join(d, "access.log")
			if err := os.WriteFile(p, []byte(logLine+"\n"), 0600); err != nil { t.Fatal(err) }
			args := []string{p}
			if bundle { args = append(args, "--report-dir", filepath.Join(d, "bundle")) } else { args = append(args, "--format", "json") }
			if verbose { args = append(args, "--verbose") }
			var out, stderr bytes.Buffer
			if code := run(args, &out, &stderr); code != 0 { t.Fatal(code, stderr.String()) }
			if strings.Contains(stderr.String(), "Input files [") != verbose { t.Fatal("verbose progress", stderr.String()) }
			if verbose && (!strings.Contains(stderr.String(), "0/1 files, 0 lines") || !strings.Contains(stderr.String(), "1/1 files, 1 lines\n")) { t.Fatal(stderr.String()) }
			if !bundle && !json.Valid(out.Bytes()) { t.Fatal("invalid JSON stdout", out.String()) }
		}
	}
}

func TestVerboseProgressPartialAndEmpty(t *testing.T) {
	for _, content := range []string{"", "invalid\n"} {
		p := filepath.Join(t.TempDir(), "access.log")
		os.WriteFile(p, []byte(content), 0600)
		var out, stderr bytes.Buffer
		code := run([]string{p, "--verbose"}, &out, &stderr)
		if (content == "" && code != 0) || (content != "" && code != 1) || !strings.Contains(stderr.String(), "1/1 files,") { t.Fatal(code, stderr.String()) }
	}
	var out, stderr bytes.Buffer
	if run([]string{t.TempDir(), "--verbose"}, &out, &stderr) != 1 || !strings.Contains(stderr.String(), "0/0 files, 0 lines\n") { t.Fatal(stderr.String()) }
}

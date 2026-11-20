package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLILanguage(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "access.log")
	if err := os.WriteFile(input, []byte(logLine+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, language := range []string{"default", "ja", "en"} {
		for _, fileOutput := range []bool{false, true} {
			t.Run(language+map[bool]string{false: "-stdout", true: "-file"}[fileOutput], func(t *testing.T) {
				args := []string{input}
				if language == "ja" {
					args = append([]string{"--lang", "ja"}, args...)
				}
				if language == "en" {
					args = append(args, "--lang=en")
				}
				path := filepath.Join(t.TempDir(), "report.html")
				if fileOutput {
					args = append(args, "-o", path)
				} else {
					args = append(args, "--format", "html")
				}
				var out, errout bytes.Buffer
				if code := run(args, &out, &errout); code != 0 {
					t.Fatalf("exit %d: %s", code, errout.String())
				}
				content := out.String()
				if fileOutput {
					b, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					content = string(b)
					if !strings.Contains(out.String(), "Top findings:") {
						t.Fatal("console summary changed")
					}
				}
				lang := language
				if lang == "default" {
					lang = "ja"
				}
				if !strings.Contains(content, `<html lang="`+lang+`"`) || strings.Contains(content, "概要") != (lang == "ja") {
					t.Fatal("incorrect language", content)
				}
			})
		}
	}
	for _, value := range []string{"fr", "JA", "", "ja-JP"} {
		path := filepath.Join(t.TempDir(), "report.html")
		var out, errout bytes.Buffer
		// The missing input ensures invalid language wins before input analysis.
		code := run([]string{filepath.Join(dir, "missing.log"), "--lang=" + value, "-o", path}, &out, &errout)
		if code != 2 || out.Len() != 0 || !strings.Contains(errout.String(), "--lang must be ja or en") {
			t.Fatalf("invalid language %q: %d %s", value, code, errout.String())
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("invalid language created a report")
		}
	}
	var out, errout bytes.Buffer
	if code := run([]string{"--help"}, &out, &errout); code != 0 || !strings.Contains(errout.String(), "-lang") {
		t.Fatal("language missing from help")
	}
}

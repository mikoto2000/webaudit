package main

import (
	"fmt"
	"io"
	"strings"
	"time"
	"webaudit/audit"
)

func newInputProgress(out io.Writer) func(audit.InputProgress) {
	return inputProgress(out, time.Now)
}

func inputProgress(out io.Writer, now func() time.Time) func(audit.InputProgress) {
	var last time.Time
	lastFiles := -1
	return func(p audit.InputProgress) {
		t := now()
		if p.CompletedFiles == lastFiles && t.Sub(last) < 100*time.Millisecond {
			return
		}
		last, lastFiles = t, p.CompletedFiles
		filled := 20
		if p.TotalFiles > 0 {
			filled = 20 * p.CompletedFiles / p.TotalFiles
		}
		fmt.Fprintf(out, "\rInput files [%s%s] %d/%d files, %d lines", strings.Repeat("=", filled), strings.Repeat(" ", 20-filled), p.CompletedFiles, p.TotalFiles, p.Lines)
		if p.CompletedFiles == p.TotalFiles {
			fmt.Fprintln(out)
		}
	}
}

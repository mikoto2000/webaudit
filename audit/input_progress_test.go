package audit

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestInputProgressStreamingGzipDuplicatesAndFailures(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "a.log.gz")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	z := gzip.NewWriter(f)
	z.Write([]byte("\ninvalid\n"))
	z.Close()
	f.Close()
	b, _ := os.ReadFile(p)
	os.WriteFile(filepath.Join(d, "b.log.gz"), b, 0600)
	os.WriteFile(filepath.Join(d, "c.log.gz"), []byte{0x1f, 0x8b}, 0600)
	var updates []InputProgress
	r := Stream([]string{d}, Options{DeduplicateFiles: true, Progress: func(p InputProgress) { updates = append(updates, p) }}, func(Event) {})
	if !r.Partial || len(r.Files) != 3 || r.Files[1].DuplicateOf == "" || r.Files[2].Error == "" {
		t.Fatal(r.Files)
	}
	if len(updates) < 6 || updates[0] != (InputProgress{TotalFiles: 3}) || updates[1].CompletedFiles != 0 || updates[1].Lines != 1 || updates[len(updates)-1] != (InputProgress{TotalFiles: 3, CompletedFiles: 3, Lines: 2}) {
		t.Fatal(updates)
	}
}

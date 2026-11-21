package watch

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func put(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0600); err != nil {
		t.Fatal(err)
	}
}
func appendLog(t *testing.T, p, s string) {
	t.Helper()
	f, e := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.WriteString(s)
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
}
func poll(t *testing.T, r *Reader) []string {
	t.Helper()
	var got []string
	if e := r.Poll(context.Background(), func(l Line) error { got = append(got, l.Text); return nil }); e != nil {
		t.Fatal(e)
	}
	return got
}
func TestReaderStartPartialAndAppend(t *testing.T) {
	for _, begin := range []bool{false, true} {
		t.Run(map[bool]string{true: "beginning", false: "end"}[begin], func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "access.log")
			put(t, p, "old\n")
			r, e := NewReader([]string{p}, ReaderOptions{Beginning: begin})
			if e != nil {
				t.Fatal(e)
			}
			defer r.Close()
			got := poll(t, r)
			if begin && !reflect.DeepEqual(got, []string{"old"}) || !begin && len(got) != 0 {
				t.Fatal(got)
			}
			appendLog(t, p, "par")
			if len(poll(t, r)) != 0 {
				t.Fatal("partial emitted")
			}
			appendLog(t, p, "tial\none\ntwo\n")
			if got = poll(t, r); !reflect.DeepEqual(got, []string{"partial", "one", "two"}) {
				t.Fatal(got)
			}
			if len(poll(t, r)) != 0 {
				t.Fatal("duplicate")
			}
		})
	}
}
func TestReaderRotationDeleteAndTruncate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "access.log")
	put(t, p, "")
	var warnings []string
	r, e := NewReader([]string{p}, ReaderOptions{Beginning: true, Warn: func(s string) { warnings = append(warnings, s) }})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	appendLog(t, p, "old\n")
	if e = os.Rename(p, p+".1"); e != nil {
		t.Fatal(e)
	}
	put(t, p, "new\n")
	if got := poll(t, r); !reflect.DeepEqual(got, []string{"old", "new"}) {
		t.Fatal(got)
	}
	put(t, p, "x\n")
	if got := poll(t, r); !reflect.DeepEqual(got, []string{"x"}) || len(warnings) == 0 {
		t.Fatal(got, warnings)
	}
	if e = os.Remove(p); e != nil {
		t.Fatal(e)
	}
	poll(t, r)
	put(t, p, "recreated\n")
	if got := poll(t, r); !reflect.DeepEqual(got, []string{"recreated"}) {
		t.Fatal(got)
	}
}
func TestReaderDirectoryLimitsAndCancel(t *testing.T) {
	d := t.TempDir()
	put(t, filepath.Join(d, "access.log"), "a\n")
	put(t, filepath.Join(d, "error.log"), "error\n")
	put(t, filepath.Join(d, "notes.txt"), "notes\n")
	put(t, filepath.Join(d, "access.log.1"), "rotated\n")
	r, e := NewReader([]string{d}, ReaderOptions{Beginning: true, MaxLineBytes: 8})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if got := poll(t, r); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatal(got)
	}
	put(t, filepath.Join(d, "site_access.log"), strings.Repeat("x", 30)+"\nok\n")
	if got := poll(t, r); !reflect.DeepEqual(got, []string{"ok"}) {
		t.Fatal(got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r.Poll(ctx, func(Line) error { return nil }) != context.Canceled {
		t.Fatal("cancel ignored")
	}
}

func TestReaderDrainsOldBeforeReplacement(t *testing.T) {
	p := filepath.Join(t.TempDir(), "access.log")
	put(t, p, "")
	r, e := NewReader([]string{p}, ReaderOptions{Beginning: true})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	appendLog(t, p, strings.Repeat("old\n", 300000))
	if e = os.Rename(p, p+".1"); e != nil {
		t.Fatal(e)
	}
	put(t, p, "new\n")
	got := poll(t, r)
	for _, s := range got {
		if s == "new" {
			t.Fatal("replacement consumed before old file drained")
		}
	}
	got = poll(t, r)
	if len(got) == 0 || got[len(got)-1] != "new" {
		t.Fatal("replacement not consumed after drain")
	}
}

func TestReaderEndSkipsExistingPartialLine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "access.log")
	put(t, p, "existing unfinished")
	r, e := NewReader([]string{p}, ReaderOptions{})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	appendLog(t, p, " tail\nnew\n")
	if got := poll(t, r); !reflect.DeepEqual(got, []string{"new"}) {
		t.Fatal(got)
	}
}

func TestReaderRepeatedRotationAndIncludes(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "custom.txt")
	put(t, p, "")
	put(t, filepath.Join(d, "skip.txt"), "skip\n")
	r, e := NewReader([]string{d}, ReaderOptions{Beginning: true, Include: "*.txt", Exclude: "skip*", MaxFiles: 4})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	for i := 0; i < 10; i++ {
		appendLog(t, p, "old\n")
		rot := filepath.Join(d, "rotated")
		if e = os.Rename(p, rot); e != nil {
			t.Fatal(e)
		}
		put(t, p, "new\n")
		got := poll(t, r)
		if !reflect.DeepEqual(got, []string{"old", "new"}) {
			t.Fatal(i, got)
		}
		os.Remove(rot)
		for _, f := range r.files {
			if !f.detached.IsZero() {
				f.detached = f.detached.Add(-3 * time.Second)
			}
		}
		poll(t, r)
	}
	if len(r.files) > 4 {
		t.Fatal("handles exceeded limit")
	}
}

func TestReaderCancellationDuringHandleCleanupPreservesUniqueCursors(t *testing.T) {
	d := t.TempDir()
	var paths []string
	for _, name := range []string{"a_access.log", "b_access.log", "c_access.log"} {
		p := filepath.Join(d, name)
		put(t, p, "")
		paths = append(paths, p)
	}
	r, e := NewReader(paths, ReaderOptions{Beginning: true})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	os.Remove(paths[0])
	r.files[0].detached = time.Now().Add(-3 * time.Second)
	appendLog(t, paths[1], "b\n")
	appendLog(t, paths[2], "c\n")
	_ = r.Poll(context.Background(), func(l Line) error {
		if l.File == paths[2] {
			return context.Canceled
		}
		return nil
	})
	seen := map[string]bool{}
	for _, f := range r.files {
		if seen[f.ID] {
			t.Fatal("cleanup cancellation duplicated cursor")
		}
		seen[f.ID] = true
	}
	if len(r.files) != 2 {
		t.Fatal("closed handle retained", len(r.files))
	}
}

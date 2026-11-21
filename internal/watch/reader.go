// Package watch provides explicit, bounded, offline access-log monitoring.
package watch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Line struct {
	Text, File string
	Number     int64
}
type ReaderOptions struct {
	Beginning              bool
	MaxFiles, MaxLineBytes int
	Include, Exclude       string
	Warn                   func(string)
}
type Cursor struct {
	Path, ID       string
	Offset, Number int64
	LineKnown      bool
	Partial        []byte
	Discard        bool
	Anchor         string
}
type trackedFile struct {
	Cursor
	file     *os.File
	detached time.Time
}
type Reader struct {
	Targets     []string
	o           ReaderOptions
	files       []*trackedFile
	initialized bool
	open func(string)(*os.File,error)
}

func NewReader(paths []string, o ReaderOptions) (*Reader, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("watch needs an input")
	}
	if o.MaxFiles == 0 {
		o.MaxFiles = 64
	}
	if o.MaxLineBytes == 0 {
		o.MaxLineBytes = 64 << 10
	}
	if o.MaxFiles < 1 || o.MaxFiles > 4096 || o.MaxLineBytes < 1 || o.MaxLineBytes > 16<<20 {
		return nil, fmt.Errorf("invalid reader limits")
	}
	for _, g := range []string{o.Include, o.Exclude} {
		if _, e := filepath.Match(g, ""); e != nil {
			return nil, e
		}
	}
	r := &Reader{o: o,open:openLog}
	for _, p := range paths {
		a, e := filepath.Abs(p)
		if e != nil {
			return nil, e
		}
		r.Targets = append(r.Targets, filepath.Clean(a))
	}
	sort.Strings(r.Targets)
	r.Targets = unique(r.Targets)
	if e := r.discover(); e != nil {
		r.Close()
		return nil, e
	}
	r.initialized = true
	return r, nil
}
func unique(xs []string) []string {
	var out []string
	for _, x := range xs {
		if len(out) == 0 || out[len(out)-1] != x {
			out = append(out, x)
		}
	}
	return out
}
func (r *Reader) warn(s string) {
	if r.o.Warn != nil {
		r.o.Warn(s)
	}
}
func accessName(n string) bool {
	n = strings.ToLower(n)
	return n == "access" || n == "access.log" || strings.HasSuffix(n, "_access.log") || strings.HasSuffix(n, "-access.log") || strings.HasSuffix(n, ".access.log")
}
func (r *Reader) candidates() ([]string, error) {
	var paths []string
	for _, p := range r.Targets {
		st, e := os.Lstat(p)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			r.warn("input unavailable: " + p)
			continue
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("symlink input rejected: %s", p)
		}
		if st.IsDir() {
			d, e := os.Open(p)
			if e != nil {
				r.warn("directory unavailable: " + p)
				continue
			}
			for {
				entries, er := d.ReadDir(128)
				for _, v := range entries {
					if !v.Type().IsRegular() {
						continue
					}
					n := v.Name()
					match := accessName(n)
					if r.o.Include != "" {
						match, _ = filepath.Match(r.o.Include, n)
					}
					excluded, _ := filepath.Match(r.o.Exclude, n)
					if match && !excluded && !strings.HasSuffix(strings.ToLower(n), ".gz") {
						paths = append(paths, filepath.Join(p, n))
						if len(paths) >= r.o.MaxFiles {
							r.warn("file discovery limit reached")
							break
						}
					}
				}
				if er != nil || len(paths) >= r.o.MaxFiles {
					break
				}
			}
			d.Close()
		} else if st.Mode().IsRegular() {
			if strings.HasSuffix(strings.ToLower(p), ".gz") {
				return nil, fmt.Errorf("compressed watch input rejected")
			}
			paths = append(paths, p)
		} else {
			return nil, fmt.Errorf("nonregular watch input rejected")
		}
	}
	sort.Strings(paths)
	return unique(paths), nil
}
func (r *Reader) discover() error {
	paths, e := r.candidates()
	if e != nil {
		return e
	}
	active := map[string]bool{}
	for _, p := range paths {
		f, e := r.open(p)
		if e != nil {
			r.warn("cannot open input: " + p)
			continue
		}
		st, e := f.Stat()
		ls, le := os.Lstat(p)
		if e != nil || le != nil || !st.Mode().IsRegular() || ls.Mode()&os.ModeSymlink != 0 || !os.SameFile(st, ls) {
			f.Close()
			r.warn("input changed during open: " + p)
			continue
		}
		id, e := fileID(f)
		if e != nil {
			f.Close()
			r.warn("file identity unavailable: " + p)
			continue
		}
		active[id] = true
		var found *trackedFile
		for _, v := range r.files {
			if v.ID == id {
				found = v
				break
			}
		}
		if found != nil {
			found.detached = time.Time{}
			f.Close()
			continue
		}
		if len(r.files) >= r.o.MaxFiles {
			f.Close()
			r.warn("open file limit reached")
			continue
		}
		v := &trackedFile{Cursor: Cursor{Path: p, ID: id, LineKnown: true}, file: f}
		if !r.initialized && !r.o.Beginning {
			v.Offset = st.Size()
			v.LineKnown = v.Offset == 0
			v.Anchor = anchor(f, v.Offset)
			if v.Offset > 0 {
				var last [1]byte
				if _, e := f.ReadAt(last[:], v.Offset-1); e == nil && last[0] != '\n' {
					v.Discard = true
				}
			}
		}
		r.files = append(r.files, v)
	}
	now := time.Now()
	for _, v := range r.files {
		if !active[v.ID] && v.detached.IsZero() {
			v.detached = now
		}
	}
	return nil
}
func anchor(f *os.File, offset int64) string {
	n := int64(128)
	if offset < n {
		n = offset
	}
	b := make([]byte, int(n))
	if _, e := f.ReadAt(b, offset-n); e != nil && e != io.EOF {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (r *Reader) Poll(ctx context.Context, consume func(Line) error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := r.discover(); e != nil {
		return e
	}
	kept := make([]*trackedFile, 0, len(r.files))
	blocked := map[string]bool{}
	// Existing handles precede newly discovered replacements, draining old data first.
	for i, v := range r.files {
		if blocked[v.Path] {
			kept = append(kept, v)
			continue
		}
		if e := r.read(ctx, v, consume); e != nil {
			r.files = append(kept, r.files[i:]...)
			return e
		}
		st, e := v.file.Stat()
		if !v.detached.IsZero() && e == nil && v.Offset < st.Size() {
			blocked[v.Path] = true
		}
		if !v.detached.IsZero() && time.Since(v.detached) > 2*time.Second && e == nil && v.Offset >= st.Size() {
			if len(v.Partial) > 0 {
				r.warn("incomplete rotated line discarded")
			}
			v.file.Close()
			continue
		}
		kept = append(kept, v)
	}
	r.files = kept
	return nil
}
func (r *Reader) read(ctx context.Context, v *trackedFile, consume func(Line) error) error {
	st, e := v.file.Stat()
	if e != nil {
		r.warn("stat failed: " + v.Path)
		return nil
	}
	if st.Size() < v.Offset || (v.Anchor != "" && anchor(v.file, v.Offset) != v.Anchor) {
		r.warn("copytruncate or rewritten content detected; producer race can lose data: " + v.Path)
		v.Offset = 0
		v.Number = 0
		v.LineKnown = true
		v.Partial = nil
		v.Discard = false
	}
	b := make([]byte, 32<<10)
	budget := 1 << 20
	for budget > 0 {
		if e = ctx.Err(); e != nil {
			return e
		}
		n, er := v.file.ReadAt(b, v.Offset)
		if n == 0 {
			if er != nil && er != io.EOF {
				r.warn("read failed: " + v.Path)
			}
			break
		}
		budget -= n
		for _, c := range b[:n] {
			v.Offset++
			if c == '\n' {
				v.Number++
				if !v.Discard {
					text := strings.TrimSuffix(string(v.Partial), "\r")
					number := v.Number
					if !v.LineKnown {
						number = 0
					}
					if e = consume(Line{text, v.Path, number}); e != nil {
						return e
					}
				}
				v.Partial = nil
				v.Discard = false
			} else if !v.Discard {
				if len(v.Partial) >= r.o.MaxLineBytes {
					v.Partial = nil
					v.Discard = true
					r.warn("oversize log line discarded")
				} else {
					v.Partial = append(v.Partial, c)
				}
			}
		}
		if er != nil {
			if er != io.EOF {
				r.warn("read failed: " + v.Path)
			}
			break
		}
	}
	v.Anchor = anchor(v.file, v.Offset)
	return nil
}
func (r *Reader) Close() {
	for _, v := range r.files {
		v.file.Close()
	}
	r.files = nil
}

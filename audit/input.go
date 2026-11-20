package audit

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var logName = regexp.MustCompile(`(?i)(\.log(?:\.[0-9]+)?(?:\.gz)?$|\.gz$|^access(?:\.[0-9]+)?$)`)

func Stream(paths []string, options Options, consume func(Event)) Report {
	o := options.defaults()
	r := Report{Schema: "webaudit/1", Version: Version, RulesVersion: RulesVersion, AnalyzedAt: time.Now().UTC(), Missing: map[string]int64{}}
	files := map[string]bool{}
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			r.warn(err.Error())
			r.Partial = true
			continue
		}
		st, err := os.Lstat(abs)
		if err != nil {
			r.Files = append(r.Files, Input{Path: abs, Error: err.Error()})
			r.Partial = true
			continue
		}
		if st.IsDir() {
			err = filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					r.warn(fmt.Sprintf("directory %s: %v", path, err))
					r.Partial = true
					return nil
				}
				if !d.IsDir() && d.Type().IsRegular() && logName.MatchString(d.Name()) {
					files[path] = true
				}
				return nil
			})
			if err != nil {
				r.warn(err.Error())
				r.Partial = true
			}
		} else if st.Mode().IsRegular() {
			files[abs] = true
		} else {
			r.warn("Skipped non-regular input: " + abs)
			r.Partial = true
		}
	}
	sorted := make([]string, 0, len(files))
	for p := range files {
		sorted = append(sorted, p)
	}
	sort.Strings(sorted)
	if len(sorted) == 0 {
		r.warn("No regular log files found")
		r.Partial = true
	}
	for _, p := range sorted {
		in := Input{Path: p}
		err := readLog(p, o, func(line string, n int64, tooLong bool) {
			if tooLong {
				in.Unparsed++
				r.warn("Oversized line skipped (max-line-bytes)")
				return
			}
			if strings.TrimSpace(line) == "" {
				return
			}
			e, err := Parse(line, p, n, o.LogRegex)
			if err != nil {
				in.Unparsed++
				if in.Unparsed <= 3 {
					r.warn(fmt.Sprintf("%s:%d: %v", p, n, err))
				}
				return
			}
			in.Parsed++
			if r.First == nil || e.Time.Before(*r.First) {
				r.First = ptr(e.Time)
			}
			if r.Last == nil || e.Time.After(*r.Last) {
				r.Last = ptr(e.Time)
			}
			for name, missing := range map[string]bool{"status": e.Status == nil, "bytes": e.Bytes == nil, "user_agent": e.UA == nil, "referer": e.Referer == nil, "method": e.Method == nil, "protocol": e.Protocol == nil} {
				if missing {
					r.Missing[name]++
				}
			}
			consume(e)
		})
		if err != nil {
			in.Error = err.Error()
			r.warn(fmt.Sprintf("%s: %v", p, err))
			r.Partial = true
		}
		r.Parsed += in.Parsed
		r.Unparsed += in.Unparsed
		r.Files = append(r.Files, in)
	}
	if r.Unparsed > 0 {
		r.warn("Unparsed lines reduce detection coverage; inspect file/line diagnostics and --log-regex")
	}
	r.warn("Request bodies and response contents are unavailable; authentication results and compromise cannot be verified")
	r.warn("Client address is the recorded peer; forwarded headers are untrusted and proxy topology is unknown")
	return r
}
func readLog(path string, o Options, line func(string, int64, bool)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	b := bufio.NewReader(f)
	var reader io.Reader = b
	magic, _ := b.Peek(2)
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		z, err := gzip.NewReader(b)
		if err != nil {
			return fmt.Errorf("gzip: %w", err)
		}
		defer z.Close()
		reader = z
	}
	limit := &io.LimitedReader{R: reader, N: o.MaxFileBytes + 1}
	br := bufio.NewReaderSize(limit, 64*1024)
	var n int64
	for {
		var data []byte
		long := false
		var er error
		for {
			chunk, e := br.ReadSlice('\n')
			if len(data)+len(chunk) <= o.MaxLineBytes+1 && !long {
				data = append(data, chunk...)
			} else {
				long = true
				data = nil
			}
			er = e
			if e != bufio.ErrBufferFull {
				break
			}
		}
		if o.MaxFileBytes+1-limit.N > o.MaxFileBytes {
			return fmt.Errorf("decompressed file limit reached; analysis incomplete")
		}
		if len(data) > 0 || long {
			n++
			s := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
			if len(s) > o.MaxLineBytes {
				long = true
			}
			line(s, n, long)
		}
		if er == io.EOF {
			return nil
		}
		if er != nil {
			return er
		}
	}
}

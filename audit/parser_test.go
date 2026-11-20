package audit

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const common = `192.0.2.1 - - [01/Nov/2026:00:00:00 +0000] "GET /index?q=1 HTTP/1.1" 200 42`

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		name, line string
		ok         bool
		ua         bool
	}{
		{"common", common, true, false},
		{"combined", common + ` "-" "Mozilla/5.0"`, true, true},
		{"vhost", "example.org:443 " + common, true, false},
		{"ipv6", strings.Replace(common, "192.0.2.1", "2001:db8::1", 1), true, false},
		{"unknown suffix", common + ` "198.51.100.9"`, false, false},
		{"invalid IP", strings.Replace(common, "192.0.2.1", "999.1.1.1", 1), false, false},
		{"invalid status", strings.Replace(common, "200 42", "999 42", 1), false, false},
		{"malformed", "garbage", false, false},
		{"json", `{"remote_addr":"192.0.2.1","time_iso8601":"2026-11-01T00:00:00Z","request":"GET / HTTP/2.0","status":200,"body_bytes_sent":42,"http_user_agent":"browser","http_x_forwarded_for":"203.0.113.5"}`, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, err := Parse(tc.line, "test.log", 7, "")
			if (err == nil) != tc.ok {
				t.Fatalf("%+v %v", e, err)
			}
			if !tc.ok {
				return
			}
			if e.File != "test.log" || e.Line != 7 || e.Raw != tc.line || e.IP == "203.0.113.5" {
				t.Fatal(e)
			}
			if (e.UA != nil) != tc.ua {
				t.Fatal(e)
			}
		})
	}
	e, err := Parse(strings.Replace(common, "200 42", "200 -", 1), "x", 1, "")
	if err != nil || e.Bytes != nil || e.UA != nil || e.Referer != nil {
		t.Fatalf("missing fields: %+v %v", e, err)
	}
}
func TestCustomParser(t *testing.T) {
	e, err := Parse("192.0.2.2 2026-11-01T00:00:00Z /a", "custom", 1, `^(?P<ip>\S+) (?P<time>\S+) (?P<target>\S+)$`)
	if err != nil || e.Status != nil || e.Method != nil || e.Path != "/a" {
		t.Fatalf("%+v %v", e, err)
	}
}
func TestStream(t *testing.T) {
	d := t.TempDir()
	a := filepath.Join(d, "access.log")
	if err := os.WriteFile(a, []byte(common+"\n"+strings.Repeat("x", 300)+"\n"+common+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(d, "rotate.gz"))
	if err != nil {
		t.Fatal(err)
	}
	z := gzip.NewWriter(f)
	_, _ = z.Write([]byte(common + "\n"))
	_ = z.Close()
	_ = f.Close()
	n := 0
	r := Stream([]string{d}, Options{MaxLineBytes: 256}, func(e Event) { n++ })
	if n != 3 || r.Parsed != 3 || r.Unparsed != 1 || len(r.Files) != 2 {
		t.Fatalf("n=%d %+v", n, r)
	}
	r = Stream([]string{filepath.Join(d, "missing"), a}, Options{MaxFileBytes: 10}, func(Event) {})
	if !r.Partial || len(r.Warnings) == 0 {
		t.Fatal(r)
	}
}
func TestBadUTF8AndRecovery(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "a.log")
	_ = os.WriteFile(p, append([]byte{255, '\n'}, []byte(common)...), 0600)
	r := Stream([]string{p}, Options{}, func(Event) {})
	if r.Unparsed != 1 || r.Parsed != 1 {
		t.Fatal(r)
	}
}

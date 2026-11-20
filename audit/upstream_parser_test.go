package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpstreamSyslogAndExtraFields(t *testing.T) {
	combined := common + ` "-" "Browser"`
	for _, s := range []string{combined + ` "203.0.113.5"`, combined + ` 12`, `Sep 15 16:13:46 host nginx[2869]: ` + combined, `<14>1 2026-11-01T00:00:00Z host nginx 2869 - - ` + combined} {
		e, err := Parse(s, "a.log", 3, "")
		if err != nil {
			t.Fatal(err, s)
		}
		if e.IP != "192.0.2.1" || e.Raw != s || val(e.UA) != "Browser" {
			t.Fatal(e)
		}
	}
}
func TestUpstreamOpaqueRequest(t *testing.T) {
	s := strings.Replace(common, `GET /index?q=1 HTTP/1.1`, `\x16\x03\x01`, 1)
	e, err := Parse(s, "a", 1, "")
	if err != nil {
		t.Fatal(err)
	}
	if !e.RequestMalformed || e.RawRequest == nil || e.Method != nil || e.Protocol != nil || e.Target != "" || val(e.Status) != 200 {
		t.Fatal(e)
	}
}
func TestUpstreamNginxError(t *testing.T) {
	s := `2021/09/30 09:23:53 [error] 1925800#1925800: *17 user "foo" was not found in "/tmp/a.htpasswd", client: 127.0.0.1, server: _, request: "GET / HTTP/1.1", host: "localhost"`
	e, err := Parse(s, "error.log", 1, "")
	if err != nil {
		t.Fatal(err)
	}
	if e.IP != "127.0.0.1" || e.LogType != "http_error-log" || !e.AuthFailure || !e.TimezoneUnknown || e.Status != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(e)
	if !strings.Contains(string(b), `"time":null`) {
		t.Fatal(string(b))
	}
}
func TestUpstreamNPMplus(t *testing.T) {
	e, err := Parse(`[10/Feb/2024:21:23:32 +0100] mx.example.org 192.168.1.100 0.227 "REPORT /calendar HTTP/2.0" 207 125 440 - Mozilla/5.0 Thunderbird`, "a", 1, "")
	if err != nil || e.IP != "192.168.1.100" || val(e.Bytes) != 125 || val(e.UA) != "Mozilla/5.0 Thunderbird" {
		t.Fatalf("%+v %v", e, err)
	}
}
func TestRepeatedRequestsAndDuplicateFiles(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "a.log")
	q := filepath.Join(d, "rotation.log")
	data := []byte(common + "\n" + common + "\n")
	_ = os.WriteFile(p, data, 0600)
	_ = os.WriteFile(q, data, 0600)
	r := Analyze([]string{p}, Options{})
	if r.Duplicates != 0 {
		t.Fatal("repeated requests were removed", r.Duplicates)
	}
	r = Analyze([]string{p, q}, Options{})
	if r.Duplicates != 0 {
		t.Fatal("upstream input multiplicity changed", r.Duplicates)
	}
	r = Analyze([]string{p, q}, Options{DeduplicateFiles: true})
	if r.Duplicates != 2 {
		t.Fatal("explicit complete-file deduplication", r.Duplicates)
	}
}

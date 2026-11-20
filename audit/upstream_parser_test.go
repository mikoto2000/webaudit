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
func TestApacheOptionalRequestProtocol(t *testing.T) {
 e,err:=Parse(strings.Replace(common," HTTP/1.1","",1),"apache.log",1,"");if err!=nil||e.RequestMalformed||val(e.Method)!="GET"||e.Target!="/index?q=1"||e.Protocol!=nil {t.Fatal("Apache's request protocol is optional",err)}
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
func TestUpstreamAdditionalErrorAndAccessShapes(t *testing.T) {
	for _, line := range []string{
		`192.0.2.1 - [01/Nov/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "Browser"`,
		`2026/11/01 00:00:00 [error] 12#12: user "a": password mismatch, client: 2001:db8::1, server: _, request: "GET /", host: "example.org"`,
		`[Sun Nov 01 00:00:00.000000 2026] [auth_basic:error] [pid 12] [client 192.0.2.1:123] AH01617: user a: authentication failure for "/private": Password Mismatch`,
	} {
		e, err := Parse(line, "error.log", 1, "")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(line, "password mismatch") || strings.Contains(line, "Password Mismatch") {
			if !e.AuthFailure || e.Method != nil && val(e.Method) != "GET" || e.Protocol != nil {
				t.Fatal(e)
			}
		}
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
func TestErrorTimezoneAndUnknownIncident(t *testing.T) {
	line := `2026/11/01 00:00:00 [error] 12#12: user "a": password mismatch, client: 192.0.2.1, server: _, request: "GET /.env HTTP/1.1", host: "example.org"`
	p := filepath.Join(t.TempDir(), "error.log")
	if err := os.WriteFile(p, []byte(line+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r := Analyze([]string{p}, Options{})
	if r.First != nil || len(r.Findings) != 1 {
		t.Fatal("unknown clock must not establish an instant")
	}
	b, _ := json.Marshal(r.Findings[0])
	if !strings.Contains(string(b), `"first":null`) || r.Findings[0].Outcome.Verdict != "unknown" {
		t.Fatal(string(b))
	}
	r = Analyze([]string{p}, Options{ErrorTimezone: "Asia/Tokyo"})
	if r.First == nil || r.First.UTC().Format("2006-01-02T15:04:05Z") != "2026-10-31T15:00:00Z" {
		t.Fatal("explicit zone not applied")
	}
	if !Analyze([]string{p}, Options{ErrorTimezone: "invalid-zone"}).Partial {
		t.Fatal("invalid zone was ignored")
	}
}

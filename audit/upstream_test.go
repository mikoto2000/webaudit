package audit

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

func sourceEvent(i int) Event {
	return Event{Time: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Second), IP: "192.0.2.1", LogType: "http_access-log", Method: ptr("POST"), Target: "/login", Path: "/login", Status: ptr(401), File: "access.log", Line: int64(i + 1)}
}

func TestAuraSourceGolden(t *testing.T) {
	var rows []struct {
		Target   string
		Expected []string
	}
	b, err := os.ReadFile("testdata/upstream/aura-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		u := NewUpstream(Options{})
		e := sourceEvent(0)
		e.Target = row.Target
		u.Observe(e)
		got := []string{}
		for _, a := range u.aura {
			got = append(got, a.RuleID)
		}
		sort.Strings(got)
		sort.Strings(row.Expected)
		if !reflect.DeepEqual(got, row.Expected) {
			t.Errorf("target %q: got %v want %v", row.Target, got, row.Expected)
		}
	}
}
func TestAuraPythonCaseSemantics(t *testing.T) {
	u := NewUpstream(Options{})
	e := sourceEvent(0)
	e.Target = "/?x=İNFORMATıON_SCHEMA"
	e.UA = ptr("NİKTO")
	u.Observe(e)
	hits := map[string]bool{}
	for _, a := range u.aura {
		hits[a.RuleID] = true
	}
	if !hits["sqli"] || hits["scanner_ua"] {
		t.Fatal("Python IGNORECASE and str.lower have different dotted-I semantics", hits)
	}
}
func TestSourceCaseAndMalformedRequestBoundaries(t *testing.T) {
	rule := func(id string) SourceRule {
		for _, r := range sourceRules {
			if r.ID == id {
				return r
			}
		}
		t.Fatal("missing source rule")
		return SourceRule{}
	}
	e := sourceEvent(0)
	e.Target = "/autodıscover/autodiscover.json?x=powershell"
	if !sourceMatch(rule("crowdsecurity/CVE-2022-41082"), e) {
		t.Fatal("source Upper() semantics were changed")
	}
	e.Target = "HTTP://example.org/"
	e.Status = ptr(400)
	e.Method = ptr("GET")
	if sourceMatch(rule("crowdsecurity/http-open-proxy"), e) {
		t.Fatal("source proxy regexp is case-sensitive")
	}
	e, err := Parse(strings.Replace(common, "HTTP/1.1", "HTTP/garbage", 1), "a", 1, "")
	if err != nil || !e.RequestMalformed || e.Protocol != nil {
		t.Fatal("nonnumeric source protocol belongs to raw request", err)
	}
}
func TestHubSourceGolden(t *testing.T) {
	var rows []struct {
		Name              string
		Group             string
		Files, Configured []string
		Expected          []struct{ Rule, IP string }
		Count             *int
		Alerts            []struct {
			Rule, IP string
			Count    int64
			Metadata map[string]map[string]string
		}
	}
	b, err := os.ReadFile("testdata/upstream/hub-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		t.Run(row.Name, func(t *testing.T) {
			if row.Group != "apache_nginx" {
				t.Skip("Requires another product's acquisition/parser; retained for an explicit scope record")
			}
			u := NewUpstream(Options{})
			var paths []string
			for _, f := range row.Files {
				paths = append(paths, filepath.Join("testdata/upstream", f))
			}
			events := map[EventRef]Event{}
			report := Stream(paths, Options{}, func(e Event) { events[EventRef{e.File, e.Line}] = e; u.Observe(e) })
			for _, want := range row.Expected {
				found := false
				for _, a := range u.alerts {
					if a.RuleID == want.Rule && a.IP == want.IP {
						found = true
					}
				}
				if !found {
					t.Errorf("missing %s %s; parsed=%d unparsed=%d", want.Rule, want.IP, report.Parsed, report.Unparsed)
				}
			}
			var actual []SourceAlert
			for _, a := range u.alerts {
				for _, id := range row.Configured {
					if a.RuleID == id {
						actual = append(actual, a)
						break
					}
				}
			}
			if row.Count != nil && len(actual) != *row.Count {
				t.Errorf("alert count %d want %d", len(actual), *row.Count)
			}
			used := map[int]bool{}
			for _, want := range row.Alerts {
				found := -1
				for i, a := range actual {
					if !used[i] && a.RuleID == want.Rule && a.IP == want.IP && a.Count == want.Count {
						found = i
						break
					}
				}
				if found < 0 {
					t.Errorf("no original alert rule=%s ip=%s count=%d; actual=%+v", want.Rule, want.IP, want.Count, actual)
					continue
				}
				used[found] = true
				a := actual[found]
				for index, fields := range want.Metadata {
					i, _ := strconv.Atoi(index)
					if i >= len(a.Events) {
						t.Errorf("missing evidence %d", i)
						continue
					}
					e := events[a.Events[i]]
					for key, value := range fields {
						got := ""
						switch key {
						case "http_path":
							got = sourceField(e, "evt.Meta.http_path")
						case "source_ip":
							got = e.IP
						case "http_status":
							got = strconv.Itoa(val(e.Status))
						case "http_verb":
							got = val(e.Method)
						case "log_type":
							got = e.LogType
						case "http_args_len":
							got = strconv.Itoa(len(sourceField(e, "evt.Parsed.http_args")))
						default:
							continue
						}
						if got != value {
							t.Errorf("%s event %d %s got %q want %q", want.Rule, i, key, got, value)
						}
					}
				}
			}
		})
	}
}
func TestUpstreamMultiplicityAndGrouping(t *testing.T) {
	u := NewUpstream(Options{})
	for i := 0; i < 6; i++ {
		e := sourceEvent(0)
		e.Line = int64(i + 1)
		u.Observe(e)
	}
	a := u.AlertsFor("LePresidente/http-generic-401-bf")
	if len(a) != 1 || a[0].Count != 6 || len(a[0].Events) != 6 {
		t.Fatalf("same requests must overflow capacity 5: %+v", a)
	}
	u = NewUpstream(Options{})
	for i := 0; i < 12; i++ {
		e := sourceEvent(0)
		e.Target = "/" + strings.Repeat("x", i)
		u.Observe(e)
	}
	if len(u.AlertsFor("LePresidente/http-generic-401-bf")) != 0 {
		t.Fatal("401 bucket must group by IP AND full target")
	}
}
func TestUpstreamRulesWithoutNativeAlertFixture(t *testing.T) {
	u := NewUpstream(Options{})
	for i := 0; i < 6; i++ {
		e := sourceEvent(0)
		e.Target = "/xmlrpc.php"
		u.Observe(e)
	}
	if a := u.AlertsFor("crowdsecurity/http-bf-wordpress_bf_xmlrpc"); len(a) != 1 || a[0].Count != 6 {
		t.Fatal(a)
	}
	u = NewUpstream(Options{})
	for i := 0; i < 6; i++ {
		e := sourceEvent(0)
		e.Status = ptr(403)
		u.Observe(e)
	}
	if len(u.AlertsFor("LePresidente/http-generic-403-bf")) != 1 {
		t.Fatal("403 rule")
	}
	u = NewUpstream(Options{})
	for i := 0; i < 41; i++ {
		e := sourceEvent(0)
		e.Method = ptr("GET")
		e.Host = ptr("example.org:443")
		e.Target = fmt.Sprintf("/p/%d.php", i)
		u.Observe(e)
	}
	a := u.AlertsFor("crowdsecurity/http-crawl-non_statics")
	if len(a) != 1 || a[0].Count != 41 || len(a[0].Events) != 6 || a[0].Group != "192.0.2.1/example.org" {
		t.Fatal(a)
	}
	u = NewUpstream(Options{})
	e := sourceEvent(0)
	e.Target = "/AUTODISCOVER/autodiscover.json?x=PowerShell"
	u.Observe(e)
	if len(u.AlertsFor("crowdsecurity/CVE-2022-41082")) != 1 {
		t.Fatal("Exchange predicate")
	}
}
func TestUpstreamLeakDistinctAndBlackhole(t *testing.T) {
	u := NewUpstream(Options{})
	for i := 0; i < 20; i++ {
		u.Observe(sourceEvent(i * 11))
	}
	if len(u.AlertsFor("LePresidente/http-generic-401-bf")) != 0 {
		t.Fatal("tokens must refill")
	}
	u = NewUpstream(Options{})
	for _, sec := range []int{0, 1, 2, 3, 4, 5, 20, 21, 22, 23, 24, 25, 61, 62, 63, 64, 65, 66} {
		u.Observe(sourceEvent(sec))
	}
	if len(u.AlertsFor("LePresidente/http-generic-401-bf")) != 2 {
		t.Fatalf("suppressed overflow must reset bucket without extending blackhole: %+v", u.AlertsFor("LePresidente/http-generic-401-bf"))
	}
	u = NewUpstream(Options{})
	for i := 0; i < 12; i++ {
		e := sourceEvent(0)
		e.Status = ptr(404)
		e.Target = "/wp-a.php"
		u.Observe(e)
	}
	if len(u.AlertsFor("crowdsecurity/http-wordpress-scan")) != 0 {
		t.Fatal("distinct target required")
	}
	for _, p := range []string{"/wp-b.php", "/wp-c.php", "/wp-d.php"} {
		e := sourceEvent(0)
		e.Status = ptr(404)
		e.Target = p
		u.Observe(e)
	}
	if len(u.AlertsFor("crowdsecurity/http-wordpress-scan")) != 1 {
		t.Fatal("four distinct targets overflow capacity three")
	}
}
func TestUpstreamVendoredManifest(t *testing.T) {
	var manifest struct{ Files map[string]string }
	b, err := os.ReadFile("upstream/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &manifest); err != nil || len(manifest.Files) < 18 {
		t.Fatal("missing pinned source data", err)
	}
	for file, want := range manifest.Files {
		b, err := upstreamFiles.ReadFile("upstream/" + file)
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprintf("%x", sha256.Sum256(b)) != want {
			t.Fatalf("embedded source hash mismatch: %s", file)
		}
	}
}
func TestPinnedFixtureHashes(t *testing.T) {
	var manifest struct{ Files map[string]string }
	b, err := os.ReadFile("testdata/upstream/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &manifest); err != nil {
		t.Fatal(err)
	}
	for file, want := range manifest.Files {
		b, err := os.ReadFile(filepath.Join("testdata/upstream", file))
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprintf("%x", sha256.Sum256(b)) != want {
			t.Fatalf("source fixture changed: %s", file)
		}
	}
}

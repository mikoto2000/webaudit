package audit

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestHTMLCoverageOverview(t *testing.T) {
	for _, partial := range []bool{false, true} {
		for _, lang := range []string{"ja", "en"} {
			r := Report{Partial: partial, UpstreamAlerts: make([]SourceAlert, 2), AuraMatches: make([]SourceAlert, 3), AuraAnalysis: make([]SourceAlert, 4)}
			var b bytes.Buffer
			if err := WriteReportWithLanguage(&b, r, "html", lang); err != nil {
				t.Fatal(err)
			}
			s := b.String()
			tr := reportTranslator{language: lang}
			state := "Completed"
			if partial {
				state = "Partial"
			}
			for _, want := range []string{tr.text(state), tr.text("WebAudit incidents:") + " 0", tr.text("Hub alerts:") + " 2", tr.text("Aura signature groups:") + " 3", tr.text("Aura analysis findings:") + " 4", tr.text("Zero WebAudit incidents does not mean zero Hub or Aura detections. Counts use different aggregation units and must not be added."), `href="#coverage"`} {
				if at := strings.Index(s, want); at < 0 || at > strings.Index(s, `id="incident-list"`) {
					t.Errorf("partial=%t lang=%s: overview missing %q", partial, lang, want)
				}
			}
			for _, id := range []string{"coverage", "input-files"} {
				if !strings.Contains(s, `id="`+id+`"`) {
					t.Errorf("missing link target %s", id)
				}
			}
		}
	}
}

func TestHTMLUnknownTimezonePeriod(t *testing.T) {
	for _, retained := range []bool{false, true} {
		f := Incident{ID: "WA-wall", TimezoneUnknown: true}
		if retained {
			f.First = time.Date(2026, 11, 1, 12, 3, 4, 0, time.UTC)
			f.Last = f.First.Add(time.Minute)
		}
		for _, lang := range []string{"ja", "en"} {
			var b bytes.Buffer
			if err := WriteReportWithLanguage(&b, Report{Findings: []Incident{f}}, "html", lang); err != nil {
				t.Fatal(err)
			}
			s := b.String()
			s = s[strings.Index(s, `<article id="WA-wall"`):]
			if retained {
				if !strings.Contains(s, "2026-11-01T12:03:04 — 2026-11-01T12:04:04") || strings.Contains(s, "+0000") || strings.Contains(s, "12:03:04Z") {
					t.Fatal("wall-clock range missing or given an unverified timezone", s)
				}
			} else if !strings.Contains(s, `href="#evidence-WA-wall"`) || !strings.Contains(s, `id="evidence-WA-wall"`) || strings.Contains(s, "0001-01-01") {
				t.Fatal("missing-time fallback is broken", s)
			}
			tr := reportTranslator{language: lang}
			if !strings.Contains(s, tr.text("Wall clock; timezone unknown; cannot convert to UTC")) || !strings.Contains(s, tr.text("Evidence-strength indicator. This is not the probability of success.")) {
				t.Fatal("missing interpretation guidance", s)
			}
		}
	}
}

func TestReports(t *testing.T) {
	c := NewCorrelator(Options{})
	e := incidentEvent(1, 200)
	e.Raw = `<script>alert("bad")</script>`
	e.IP = "=HYPERLINK(1)"
	h, n := Detect(e)
	c.Add(e, h, n)
	r := Report{Version: Version, RulesVersion: RulesVersion, Findings: c.Finish(), Warnings: []string{"Test warning"}, Outcomes: map[string]int{"unknown": 1}, Categories: map[string]int{"sensitive_file": 1}}
	for _, format := range []string{"html", "json", "csv", "summary"} {
		t.Run(format, func(t *testing.T) {
			var b bytes.Buffer
			if err := WriteReport(&b, r, format); err != nil {
				t.Fatal(err)
			}
			s := b.String()
			if format == "html" && (strings.Contains(s, "<script>") || strings.Contains(s, "https://cdn") || !strings.Contains(s, "&lt;script&gt;")) {
				t.Fatal("unsafe HTML", s)
			}
			if format == "json" {
				var v Report
				if err := json.Unmarshal(b.Bytes(), &v); err != nil || len(v.Findings) != 1 {
					t.Fatal(err)
				}
			}
			if format == "csv" {
				rows, err := csv.NewReader(strings.NewReader(s)).ReadAll()
				if err != nil || len(rows) < 3 {
					t.Fatal(err)
				}
				if !strings.Contains(s, "'=HYPERLINK") {
					t.Fatal("spreadsheet formula not neutralized")
				}
			}
		})
	}
	if WriteReport(&bytes.Buffer{}, r, "bad") == nil {
		t.Fatal("unknown format")
	}
}

func TestHTMLMissingFieldsAndZeroValues(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "present"}[present], func(t *testing.T) {
			e := Event{}
			f := Incident{IP: "192.0.2.1"}
			if present {
				f.Host = ptr("<target>")
				f.UA = ptr("<browser>")
				e.Status = ptr(0)
				e.Bytes = ptr(int64(0))
			}
			f.Evidence = []Evidence{{Event: e}}
			var b bytes.Buffer
			if err := WriteReportWithLanguage(&b, Report{Findings: []Incident{f}}, "html", "en"); err != nil {
				t.Fatal(err)
			}
			s := b.String()
			if strings.Contains(s, "&lt;nil&gt;") || strings.Contains(s, "<nil>") {
				t.Fatal("nil leaked into HTML")
			}
			want := []string{"Target unknown", "UA unknown", "Status unknown", "Bytes unknown"}
			if present {
				want = []string{"Target &lt;target&gt;", "UA &lt;browser&gt;", "Status 0", "Bytes 0"}
			}
			for _, v := range want {
				if !strings.Contains(s, v) {
					t.Fatalf("missing %q", v)
				}
			}
		})
	}
}

func TestTerminalSafeBidiControls(t *testing.T) {
	for _, r := range []rune{0x061c, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069} {
		if got := TerminalSafe("a" + string(r) + "b"); got != "a�b" {
			t.Errorf("U+%04X retained: %q", r, got)
		}
	}
	if got := TerminalSafe("日本語 العربية אבג"); got != "日本語 العربية אבג" {
		t.Fatal("ordinary text altered", got)
	}
}

func TestReportAddWarningDeduplicatesAndBounds(t *testing.T) {
	r := Report{}
	r.warn("existing")
	r.AddWarning("existing")
	for i := 0; i < 60; i++ {
		r.AddWarning(fmt.Sprintf("GeoIP warning %d", i))
	}
	if len(r.Warnings) != 50 || r.Warnings[0] != "existing" || r.Warnings[49] != "GeoIP warning 48" {
		t.Fatal(r.Warnings)
	}
	if r.Partial {
		t.Fatal("adding a warning must not change coverage state")
	}
}

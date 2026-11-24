package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestUpstreamSourceEvidenceAndBounds(t *testing.T) {
	u := NewUpstream(Options{RetainUpstreamEvidence: true})
	e := sourceEvent(0)
	e.Target = "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
	e.Path = e.Target
	e.Raw = "source <script>bad</script>"
	u.Observe(e)
	if len(u.alerts) == 0 || len(u.aura) == 0 {
		t.Fatalf("expected Hub and Aura matches: %v %v", u.alerts, u.aura)
	}
	alerts := append([]SourceAlert(nil), u.alerts...)
	for _, a := range u.aura {
		alerts = append(alerts, *a)
	}
	for _, a := range alerts {
		if len(a.Evidence) != 1 || a.Evidence[0].Raw != e.Raw || a.Evidence[0].File != e.File || a.Evidence[0].Line != e.Line {
			t.Fatalf("missing source evidence: %+v", a)
		}
	}
	// Machine-report defaults retain their existing schema.
	plain := NewUpstream(Options{})
	plain.Observe(e)
	for _, a := range plain.alerts {
		b, _ := json.Marshal(a)
		if strings.Contains(string(b), `"evidence":`) {
			t.Fatal("unsolicited raw logs in machine reports")
		}
	}
	budget := &upstreamEvidence{limit: 4200}
	var samples []SourceEvidence
	e.Raw = strings.Repeat("あ", 2000)
	budget.add(&samples, e)
	budget.add(&samples, e)
	if len(samples) != 1 || len(samples[0].Raw) > 4096 || !utf8.ValidString(samples[0].Raw) || !samples[0].EvidenceTruncated {
		t.Fatal("byte limit or truncation failed")
	}
	a := SourceAlert{Count: 2}
	budget.attach(&a, samples)
	if !a.EvidenceTruncated {
		t.Fatal("missing sample limit warning")
	}
	samples = nil
	(&upstreamEvidence{limit: 0}).add(&samples, e)
	if len(samples) != 0 {
		t.Fatal("exceeded empty budget")
	}
}

func TestAuraAggregationEvidenceMatchesEachCategory(t *testing.T) {
	a := newAuraAnalysis(Options{})
	a.evidence = &upstreamEvidence{limit: 32 << 20}
	for i := 0; i < 50; i++ {
		e := sourceEvent(i)
		e.Status = ptr(404)
		e.Raw = "404 source"
		a.Observe(e)
		if i < 20 {
			e.Status = ptr(403)
			e.Raw = "403 source"
			a.Observe(e)
		}
	}
	e := sourceEvent(51)
	e.UA = ptr("RareBrowser")
	e.Raw = "RareBrowser source"
	a.Observe(e)
	out := a.Finish()
	if len(out) != 3 {
		t.Fatal(out)
	}
	for _, f := range out {
		want, n := "403 source", 8
		if f.RuleID == "enumeration_404" {
			want = "404 source"
		}
		if f.RuleID == "rare_user_agent" {
			want, n = "RareBrowser source", 1
		}
		if len(f.Evidence) != n || f.EvidenceTruncated != (n == 8) {
			t.Fatalf("bad samples: %+v", f)
		}
		for _, sample := range f.Evidence {
			if sample.Raw != want {
				t.Fatalf("sample belongs to another aggregation: %+v", f)
			}
		}
	}
}

func TestHTMLDetectionNavigationAndRawSamples(t *testing.T) {
	r := Analyze([]string{"../examples/sample.log"}, Options{RetainUpstreamEvidence: true})
	// Repeated rule names across the three sources still need distinct anchors.
	sample := SourceAlert{Source: "hub", RuleID: "same-rule", Count: 2, Events: []EventRef{{File: "<source.log>", Line: 42}}, Evidence: []SourceEvidence{{File: "<source.log>", Line: 42, Raw: "<script>raw</script>", EvidenceTruncated: true}}, EvidenceTruncated: true, Metadata: map[string]string{"<key>": "<value>"}}
	r.UpstreamAlerts = []SourceAlert{sample}
	sample.Source = "AuraDFIR"
	r.AuraMatches = []SourceAlert{sample}
	sample.Source = "AuraDFIR/analysis"
	r.AuraAnalysis = []SourceAlert{sample}
	for _, lang := range []string{"ja", "en"} {
		var b bytes.Buffer
		if err := WriteReportWithLanguage(&b, r, "html", lang); err != nil {
			t.Fatal(err)
		}
		html := b.String()
		for _, id := range []string{"incident-list", "upstream-list"} {
			if strings.Count(html, `id="`+id+`"`) != 1 {
				t.Fatal("missing or duplicate table anchor", id)
			}
		}
		for _, f := range r.Findings {
			at := strings.Index(html, `<article id="`+f.ID+`">`)
			if at < 0 || !strings.Contains(html[:at], `href="#`+f.ID+`"`) {
				t.Fatal("missing incident link")
			}
			section := html[at : at+strings.Index(html[at:], "</article>")]
			if !strings.Contains(section, `href="#incident-list"`) {
				t.Fatal("missing incident return link")
			}
		}
		for i := 0; i < 3; i++ {
			id := fmt.Sprintf("upstream-%d", i)
			at := strings.Index(html, `<article id="`+id+`">`)
			if at < 0 || strings.Count(html, `id="`+id+`"`) != 1 || !strings.Contains(html[:at], `href="#`+id+`"`) {
				t.Fatal("missing source link", id)
			}
			section := html[at : at+strings.Index(html[at:], "</article>")]
			for _, want := range []string{`href="#upstream-list"`, "&lt;source.log&gt;:42", "&lt;script&gt;raw&lt;/script&gt;", "&lt;key&gt;</dt><dd>&lt;value&gt;", `class="warning"`} {
				if !strings.Contains(section, want) {
					t.Fatal("missing", want)
				}
			}
		}
		if strings.Contains(html, "<script>") {
			t.Fatal("unescaped raw log")
		}
	}
	var b bytes.Buffer
	if err := WriteReport(&b, Report{}, "html"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "<article") {
		t.Fatal("empty report has detail sections")
	}
}

func TestAnalyzeCapturesSourceLogsBeforeInputDisappears(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sample.log")
	raw := `192.0.2.1 - - [01/Nov/2026:00:00:00 +0000] "GET /.env HTTP/1.1" 404 42 "-" "RareBrowser"`
	if err := os.WriteFile(p, []byte(raw+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r := Analyze([]string{p}, Options{RetainUpstreamEvidence: true})
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if len(r.AuraMatches) == 0 || len(r.AuraAnalysis) == 0 {
		t.Fatal("expected source detections")
	}
	for _, alerts := range [][]SourceAlert{r.AuraMatches, r.AuraAnalysis} {
		for _, a := range alerts {
			if len(a.Evidence) != 1 || a.Evidence[0].Raw != raw {
				t.Fatal("source log was not retained", a)
			}
		}
	}
	var b bytes.Buffer
	if err := WriteReport(&b, r, "html"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "<pre>192.0.2.1") {
		t.Fatal("raw log was not rendered")
	}
}

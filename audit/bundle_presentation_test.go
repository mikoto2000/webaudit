package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	stdhtml "html"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode"
)

func TestCaseBriefKeepsFullEvidence(t *testing.T) {
	r := &InvestigationReport{}
	r.Metadata.Language = "en"
	route := "/" + strings.Repeat("長", 200) + "<script>evidence</script>"
	finding := Incident{ID: "WA-brief"}
	for i := 0; i < 4; i++ {
		finding.Evidence = append(finding.Evidence, Evidence{Event: Event{Raw: fmt.Sprintf("raw-evidence-%d", i), Status: ptr(200), Bytes: ptr(int64(0))}, Normalization: Normalized{Original: route}})
	}
	r.Analysis.Findings = []Incident{finding}
	r.FindingObservations = []FindingObservation{{ID: finding.ID, Requests: 4}}
	before, _ := json.Marshal(r.Analysis)
	var b bytes.Buffer
	if err := writeInvestigationHTML(&b, r); err != nil {
		t.Fatal(err)
	}
	page := b.String()
	article := strings.SplitN(page, `<article id="WA-brief">`, 2)[1]
	parts := strings.SplitN(article, `<details class="case-supporting">`, 2)
	if len(parts) != 2 {
		t.Fatal("missing expandable supporting evidence")
	}
	brief := parts[0]
	if !strings.Contains(brief, "Access records in this case: 4") || strings.Count(brief, "<tr><td>") != 3 {
		t.Fatal("brief must distinguish total case records from its three representative rows")
	}
	for _, label := range []string{"1. What was observed", "2. What is suspected", "3. What remains unverified", "4. What to check next"} {
		if !strings.Contains(brief, label) {
			t.Fatal("missing essential case guidance", label)
		}
	}
	if strings.Contains(brief, stdhtml.EscapeString(route)) || strings.Contains(brief, "raw-evidence-") || !strings.Contains(brief, "…") {
		t.Fatal("long routes and raw evidence should be retained in supporting details")
	}
	if !strings.Contains(parts[1], stdhtml.EscapeString(route)) || !strings.Contains(parts[1], "raw-evidence-3") || strings.Contains(page, "<script>evidence") {
		t.Fatal("full evidence was lost or rendered unsafely")
	}
	after, _ := json.Marshal(r.Analysis)
	if !bytes.Equal(before, after) {
		t.Fatal("brief presentation changed source evidence")
	}
}

func TestCaseActionLinksUseTargetIDs(t *testing.T) {
	r := &InvestigationReport{}
	r.Analysis.Findings = []Incident{{ID: "case-a"}}
	r.Detections = []BundleDetection{{ID: "source-a", Engine: "aura"}}
	r.Recommendations = []Recommendation{
		{ID: "rec-case", Type: "investigation", FindingIDs: []string{"case-a"}, Title: "Same title"},
		{ID: "rec-source", Type: "investigation", DetectionIDs: []string{"source-a"}, Title: "Same title"},
		{ID: "rec-other", Type: "investigation", FindingIDs: []string{"case-b"}, Title: "Same title"},
		{ID: "rec-control", Type: "preventive_review", FindingIDs: []string{"case-a"}},
	}
	v := buildReportHTMLView(r, reportTranslator{language: "en"})
	if len(v.Cases[0].Recommendations) != 1 || v.Cases[0].Recommendations[0].ID != "rec-case" {
		t.Fatal("case should link only to its investigation actions")
	}
	if len(v.Sources[0].Recommendations) != 1 || v.Sources[0].Recommendations[0].ID != "rec-source" {
		t.Fatal("independent detection should link only to its own investigation actions")
	}
	r.Recommendations = nil
	v = buildReportHTMLView(r, reportTranslator{language: "en"})
	if len(v.Cases[0].Recommendations) != 0 || len(v.Sources[0].Recommendations) != 0 {
		t.Fatal("missing recommendations must not create action links")
	}
}

func TestUnavailableRequestTargetDoesNotCreateShortcut(t *testing.T) {
	r := &InvestigationReport{}
	r.Metadata.Language = "en"
	r.Recommendations = []Recommendation{{ID: "rec-geo", Type: "investigation", DetectionIDs: []string{"geo-only"}}}
	var b bytes.Buffer
	if err := writeInvestigationHTML(&b, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), `data-secondary-case="geo-only"`) || strings.Contains(b.String(), "#request-geo-only") {
		t.Fatal("a request shortcut must not point to a target absent from the investigation plan")
	}
	if !strings.Contains(b.String(), "outside the request generator scope") {
		t.Fatal("explain when a recommendation cannot use the request generator")
	}
}

func TestCoverageSummariesSeparateDetectionAndCompleteness(t *testing.T) {
	r := &InvestigationReport{Coverage: []CoverageRow{
		{ID: "ASPECT-detected", HasDetections: true, Complete: true},
		{ID: "ASPECT-partial-hit", HasDetections: true, Complete: false},
		{ID: "ASPECT-unable", Complete: false},
		{ID: "ASPECT-not-supported", Complete: false},
		{ID: "ASPECT-no-match", Complete: true},
		{ID: "RULE-webaudit-test", HasDetections: true, Complete: false},
	}}
	v := buildReportHTMLView(r, reportTranslator{language: "en"})
	if len(v.DetectedAspects) != 2 || len(v.IncompleteAspects) != 3 {
		t.Fatalf("incorrect perspective summaries: detected=%d incomplete=%d", len(v.DetectedAspects), len(v.IncompleteAspects))
	}
	if v.DetectedAspects[1].ID != "ASPECT-partial-hit" || v.IncompleteAspects[0].ID != "ASPECT-partial-hit" {
		t.Fatal("a partial evaluation with detections must appear in both summaries")
	}
	if len(v.Coverage) != len(r.Coverage) || !v.CoverageIDs["RULE-webaudit-test"] || !v.CoverageIDs["ASPECT-no-match"] {
		t.Fatal("summaries lost detailed rule or no-match results")
	}
	r.Coverage = nil
	v = buildReportHTMLView(r, reportTranslator{language: "en"})
	if len(v.DetectedAspects) != 0 || len(v.IncompleteAspects) != 0 {
		t.Fatal("empty coverage produced summary results")
	}
}

func TestInvestigationHTMLChaptersNavigationAndSharedRecommendations(t *testing.T) {
	for _, lang := range []string{"ja", "en"} {
		t.Run(lang, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "report")
			r, err := GenerateBundle([]string{"../examples/sample.log"}, target, Options{}, BundleOptions{Language: lang, Title: "<script>title</script>"})
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(target, "report.html"))
			if err != nil {
				t.Fatal(err)
			}
			html := string(data)
			if !strings.Contains(html, `id="coverage-status-legend"`) || !strings.Contains(html, `href="#coverage-status-legend"`) {
				t.Fatal("coverage legend must remain linked from chapter 5")
			}
			rows := buildReportHTMLView(r, reportTranslator{language: lang}).RiskCoverage
			executive := executiveRisks(r)
			if len(rows) != len(executive) {
				t.Fatal("risk correspondence differs from the executive targets")
			}
			for i, row := range rows {
				if row.Risk.ID != executive[i].ID || !strings.Contains(html, `data-risk-ref="`+row.Risk.ID+`"`) {
					t.Fatal("executive risk missing from chapter 5")
				}
				if len(row.Perspectives) == 0 {
					t.Fatal("sample risk should have a recorded correspondence", row.Risk.ID)
				}
			}
			if !strings.Contains(html, `<details id="coverage-details">`) {
				t.Fatal("detailed coverage should be expandable")
			}
			chapterStart := strings.Index(html, `<h2 id="chapter-6">`)
			chapterEnd := strings.Index(html, `<h2 id="chapter-8">`)
			inventory := strings.Index(html, `<section id="appendix-coverage">`)
			if inventory < chapterEnd || strings.Contains(html[chapterStart:chapterEnd], `id="coverage-details"`) || strings.Contains(html[chapterStart:chapterEnd], `<tr id="coverage-`) {
				t.Fatal("the full evaluation inventory must remain outside chapter 5")
			}
			for _, risk := range executive {
				if !strings.Contains(html[chapterStart:chapterEnd], `data-risk-followup="`+risk.ID+`"`) {
					t.Fatal("follow-up work must remain linked to the displayed executive targets")
				}
			}
			if strings.Count(html, `<tr id="coverage-`) != len(r.Coverage) {
				t.Fatal("coverage rows were dropped or duplicated by summaries")
			}
			for i := 1; i <= 11; i++ {
				needsNavigation := i == 1 || i == 2 || i == 6 || i == 8 || i == 11
				if !strings.Contains(html, fmt.Sprintf(`id="chapter-%d"`, i)) || (needsNavigation && !strings.Contains(html, fmt.Sprintf(`href="#chapter-%d"`, i))) {
					t.Fatal("chapter missing", i)
				}
			}
			appendix := strings.Index(html, `<section id="appendix-assessment">`)
			if appendix < strings.Index(html, `<h2 id="chapter-11">`) || !strings.Contains(html, `href="#appendix-assessment"`) {
				t.Fatal("assessment definitions must be a linked appendix after the main chapters")
			}
			if strings.Contains(html, "<script>") || !strings.Contains(html, "&lt;script&gt;title&lt;/script&gt;") || !strings.Contains(html, "<meter") || !strings.Contains(html, "@media print") {
				t.Fatal("unsafe or missing visual/print output")
			}
			for _, appendixID := range []string{"appendix-methods", "appendix-statistics"} {
				if strings.Index(html, `<section id="`+appendixID+`">`) < strings.Index(html, `<section id="appendix-limitations">`) || !strings.Contains(html, `href="#`+appendixID+`"`) {
					t.Fatal("methods and whole-log statistics must be linked reference appendices")
				}
			}
			if strings.Contains(html, `<h2 id="chapter-3">`) || strings.Contains(html, `<h2 id="chapter-5">`) {
				t.Fatal("methods and whole-log statistics must not interrupt the main reading path")
			}
			if strings.Contains(html, `<h2 id="chapter-7">`) || !strings.Contains(html, `href="findings.csv"`) || !strings.Contains(html, `href="detections.csv"`) {
				t.Fatal("remove the duplicate list chapter while retaining full-data CSV access")
			}
			if strings.Contains(html, `<h2 id="chapter-9">`) || !strings.Contains(html, `<span id="chapter-9"></span>`) {
				t.Fatal("remove repeated overall assessment while preserving the overview reference")
			}
			scopeStart := strings.Index(html, `<h2 id="chapter-2">`)
			scopeEnd := strings.Index(html, `<h2 id="chapter-6">`)
			runLimits := strings.Index(html, `id="run-limitations"`)
			commonLimits := strings.Index(html, `<section id="appendix-limitations">`)
			if strings.Contains(html, `<h2 id="chapter-10">`) || runLimits < scopeStart || runLimits > scopeEnd || commonLimits < strings.Index(html, `<section id="appendix-coverage">`) {
				t.Fatal("runtime constraints belong in chapter 2 and common limits in appendix C")
			}
			if len(r.MaskingNotes) == 0 || !strings.Contains(html[commonLimits:], (reportTranslator{language: lang}).text(r.MaskingNotes[0])) || !strings.Contains(html[runLimits:scopeEnd], `href="diagnostics/parse-errors.csv"`) {
				t.Fatal("masking notes or run diagnostics were lost while redistributing limits")
			}
			for _, finding := range r.Analysis.Findings {
				if !strings.Contains(html, `<article id="`+finding.ID+`"`) {
					t.Fatal("removing the repeated list dropped case evidence")
				}
			}
			if lang == "ja" && !strings.Contains(html, "第5章 推奨対応") {
				t.Fatal("missing Japanese title")
			}
			if lang == "en" && !strings.Contains(html, "5. Recommended actions") {
				t.Fatal("missing English title")
			}
			if len(r.Recommendations) == 0 || r.Summary.TotalRequests != r.Statistics.TotalRequests {
				t.Fatal("missing common summary/recommendations")
			}
			ids := map[string]bool{}
			for _, m := range regexp.MustCompile(`id="([^"]+)"`).FindAllStringSubmatch(html, -1) {
				if ids[m[1]] {
					t.Fatal("duplicate anchor", m[1])
				}
				ids[m[1]] = true
			}
			for _, m := range regexp.MustCompile(`href="#([^"]+)"`).FindAllStringSubmatch(html, -1) {
				if !ids[m[1]] {
					t.Fatal("broken navigation", m[1])
				}
			}
			recommendations := bundleCSV(t, filepath.Join(target, "recommendations.csv"))
			if len(recommendations) != len(r.Recommendations) {
				t.Fatal("recommendation model differs from CSV")
			}
		})
	}
}
func TestBundleMasksSecretsWithoutChangingOriginalEvidence(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "access.log")
	raw := `192.0.2.1 - - [01/Nov/2026:00:00:00 +0000] "GET /.env?token=TOPSECRET HTTP/1.1" 404 0 "-" "Browser"`
	if err := os.WriteFile(input, []byte(raw+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "masked")
	r, err := GenerateBundle([]string{input}, target, Options{}, BundleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !r.MaskingEnabled {
		t.Fatal("masking not disclosed")
	}
	err = filepath.WalkDir(target, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), "TOPSECRET") {
			t.Fatal("secret exposed", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(input)
	if !strings.Contains(string(original), "TOPSECRET") {
		t.Fatal("original source modified")
	}
	clear := filepath.Join(dir, "sensitive")
	_, err = GenerateBundle([]string{input}, clear, Options{}, BundleOptions{IncludeSensitiveEvidence: true})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(clear, "suspicious-requests.csv"))
	if !strings.Contains(string(data), "TOPSECRET") {
		t.Fatal("explicit sensitive export not respected")
	}
}

func TestBundleEscapesControlCharactersEvenWithSensitiveEvidence(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "access.log")
	raw := `{"remote_addr":"192.0.2.1","time_iso8601":"2026-11-01T00:00:00Z","request":"GET /.env HTTP/1.1","status":404,"body_bytes_sent":0,"http_user_agent":"Browser\u001b[31m\u202e"}`
	if err := os.WriteFile(input, []byte(raw+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "report")
	_, err := GenerateBundle([]string{input}, target, Options{}, BundleOptions{IncludeSensitiveEvidence: true})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(target, "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(string(data), "\u001b\u202e") {
		t.Fatal("active control character in rendered report")
	}
	if !strings.Contains(string(data), `\u001B`) {
		t.Fatal("control character representation missing")
	}
}

func TestInvestigationHTMLCatalogCoverage(t *testing.T) {
	visible := regexp.MustCompile(`(?s)<style>.*?</style>|<pre(?: [^>]*)?>.*?</pre>|{{.*?}}|<[^>]*>`).ReplaceAllString(investigationHTML, "")
	if strings.IndexFunc(visible, unicode.IsLetter) >= 0 {
		t.Fatal("unlocalized static template text", visible)
	}
	for _, match := range regexp.MustCompile(`{{t ("(?:[^"\\]|\\.)*")}}`).FindAllStringSubmatch(investigationHTML, -1) {
		var key string
		if err := json.Unmarshal([]byte(match[1]), &key); err != nil || reportJapanese[key] == "" {
			t.Fatal("missing Japanese template key", match[1])
		}
	}
	for _, aspect := range bundleAspects() {
		if reportJapanese[aspect.Name] == "" {
			t.Fatal("missing perspective name", aspect.Name)
		}
	}
}

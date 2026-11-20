package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

func languageReport(t *testing.T) Report {
	t.Helper()
	g := testGeo(t, 64)
	r := Analyze([]string{"../examples/sample.log"}, Options{GeoIP: g})
	r.Partial = true
	r.Warnings = append(r.Warnings, "Missing status in 2 parsed requests reduces related detection coverage", `C:\logs\access.log:5: invalid status`)
	r.Findings[0].Reasons = append(r.Findings[0].Reasons, "24 observations in overlapping five-minute event-time window; diversity bounded at 64")
	r.Findings[0].Evidence[0].Event.Raw = `<payload>Summary 日本語 https://example.test/unknown</payload>`
	r.Findings[0].Evidence[0].Normalization.Original = "/Summary/日本語?unknown=high"
	return r
}

func TestHTMLLanguages(t *testing.T) {
	r := languageReport(t)
	before, _ := json.Marshal(r)
	for _, language := range []string{"", "ja", "en"} {
		t.Run("language="+language, func(t *testing.T) {
			var b bytes.Buffer
			if err := WriteReportWithLanguage(&b, r, "html", language); err != nil {
				t.Fatal(err)
			}
			s := b.String()
			want := []string{`lang="ja"`, "概要", "成否不明", "部分解析:", "攻撃・検出の種類", "GeoIP / ASN による調査の参考情報", "不明な理由", "重複する5分間", "2件の要求でHTTPステータスが欠落", `C:\logs\access.log:5: HTTPステータスが不正です`}
			absent := []string{"Access logs show requests", "Why the outcome is uncertain", "Missing status in 2", "observations in overlapping"}
			if language == "en" {
				want = []string{`lang="en"`, "Summary", "Unknown outcome", "Partial analysis:", "Why the outcome is uncertain", "Access logs show requests", "Historical response", "GeoIP / ASN investigation context", "Missing status in 2", "observations in overlapping"}
				absent = []string{"概要", "不明な理由", "成否不明", "この事案の時刻", "重複する5分間"}
			}
			for _, value := range append(want, "&lt;payload&gt;Summary 日本語 https://example.test/unknown&lt;/payload&gt;", "/Summary/日本語?unknown=high", "WA-sqli", "192.0.2.20", "ISC License") {
				if !strings.Contains(s, value) {
					t.Errorf("missing %q", value)
				}
			}
			for _, value := range absent {
				if strings.Contains(s, value) {
					t.Errorf("wrong language: %q", value)
				}
			}
			if strings.Contains(s, "<payload>") || strings.Contains(s, `<script`) {
				t.Fatal("unescaped evidence or script")
			}
		})
	}
	after, _ := json.Marshal(r)
	if !bytes.Equal(before, after) {
		t.Fatal("localization mutated the report")
	}
}

func TestHTMLLanguageIsolation(t *testing.T) {
	for i := 0; i < 12; i++ {
		language := []string{"ja", "en"}[i%2]
		t.Run(fmt.Sprintf("%s-%d", language, i), func(t *testing.T) {
			t.Parallel()
			var b bytes.Buffer
			if err := WriteReportWithLanguage(&b, Report{}, "html", language); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(b.String(), `lang="`+language+`"`) || strings.Contains(b.String(), "概要") != (language == "ja") {
				t.Fatal("language leaked across renders")
			}
		})
	}
}

func TestHTMLCatalogCoverage(t *testing.T) {
	visible := regexp.MustCompile(`(?s)<style>.*?</style>|<pre(?: [^>]*)?>.*?</pre>|{{.*?}}|<[^>]*>`).ReplaceAllString(htmlSource, "")
	if strings.IndexFunc(visible, unicode.IsLetter) >= 0 {
		t.Errorf("unlocalized static template text: %s", visible)
	}
	for _, match := range regexp.MustCompile(`{{t ("(?:[^"\\]|\\.)*")}}`).FindAllStringSubmatch(htmlSource, -1) {
		key, err := strconv.Unquote(match[1])
		if err != nil || reportJapanese[key] == "" {
			t.Errorf("missing template translation: %s", match[1])
		}
	}
	var categories []string
	for _, r := range Rules() {
		categories = append(categories, r.Category)
		if reportJapanese[r.Description] == "" || reportJapanese[r.Category] == "" {
			t.Errorf("missing rule translation: %s", r.ID)
		}
	}
	categories = append(categories, "auth", "rate", "WS-size", "future-category")
	for _, g := range investigationFor(categories) {
		for _, source := range append([]string{g.WhyUnknown, g.SuccessEvidence, g.FailureEvidence}, g.WhereToCheck...) {
			translated := reportEnglish[source]
			if translated == "" || strings.IndexFunc(translated, func(r rune) bool { return unicode.Is(unicode.Han, r) }) >= 0 {
				t.Errorf("missing English investigation text: %s", source)
			}
		}
	}
	// Catch new built-in warnings that have not been added to the HTML catalog.
	tr := reportTranslator{language: "ja"}
	for _, name := range []string{"analysis.go", "aura_behavior.go", "input.go", "incidents.go", "upstream.go", "geo_analysis.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			fn := ""
			switch f := call.Fun.(type) {
			case *ast.SelectorExpr:
				fn = f.Sel.Name
			case *ast.Ident:
				fn = f.Name
			}
			if fn != "warn" && fn != "warning" && fn != "uniqueAppend" {
				return true
			}
			for _, arg := range call.Args {
				literal, ok := arg.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}
				value, _ := strconv.Unquote(literal.Value)
				if strings.HasPrefix(tr.diagnostic(value), "診断情報（原文）:") {
					t.Errorf("missing built-in warning translation in %s: %s", name, value)
				}
			}
			return true
		})
	}
}

func TestDiagnosticTranslation(t *testing.T) {
	tr := reportTranslator{language: "ja"}
	for _, tc := range []struct{ source, want string }{
		{`GeoIP country database "C:\db.mmdb": bad metadata; automatic database ignored`, `GeoIP 国 DB "C:\db.mmdb"を利用できない`},
		{"GeoIP asn lookup failed: bad metadata", "GeoIP ASNの検索に失敗"},
		{`directory C:\logs: Access denied`, `ディレクトリ C:\logsの読み込みエラー`},
		{`C:\logs\a.log:3: duplicate JSON field host`, `C:\logs\a.log:3: 重複したJSONフィールド: host`},
		{"Managed GeoIP unavailable; analysis continues without automatic GeoIP: bad manifest", "管理GeoIPを利用できないため"},
		{`open C:\logs: Access denied`, `診断情報（原文）: open C:\logs: Access denied`},
	} {
		if got := tr.diagnostic(tc.source); !strings.Contains(got, tc.want) {
			t.Errorf("%s: %s", tc.source, got)
		}
		if got := (reportTranslator{language: "en"}).diagnostic(tc.source); got != tc.source {
			t.Errorf("English diagnostic changed: %s", got)
		}
	}
	var ja, implicit bytes.Buffer
	if err := WriteReportWithLanguage(&ja, Report{}, "html", "ja"); err != nil {
		t.Fatal(err)
	}
	if err := WriteReport(&implicit, Report{}, "html"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ja.Bytes(), implicit.Bytes()) {
		t.Fatal("default writer is not Japanese")
	}
}

func TestLanguageNonHTMLAndInvalid(t *testing.T) {
	r := languageReport(t)
	for _, format := range []string{"json", "csv", "summary"} {
		var ja, en bytes.Buffer
		if err := WriteReportWithLanguage(&ja, r, format, "ja"); err != nil {
			t.Fatal(err)
		}
		if err := WriteReportWithLanguage(&en, r, format, "en"); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ja.Bytes(), en.Bytes()) {
			t.Fatalf("%s changed with language", format)
		}
	}
	var b bytes.Buffer
	if err := WriteReportWithLanguage(&b, r, "html", "fr"); err == nil || b.Len() != 0 {
		t.Fatal("invalid language accepted or partial output written")
	}
}

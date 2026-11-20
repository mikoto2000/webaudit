package audit

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestInvestigationCoverage(t *testing.T) {
	var categories []string
	for _, r := range Rules() {
		categories = append(categories, r.Category)
	}
	// Behavioral detections also need guidance, including the WS- categories
	// emitted by behaviorRule (which only removes the WB- prefix).
	for _, id := range []string{"WB-404", "WB-auth", "WB-login", "WB-rate", "WB-burst", "WB-paths", "WB-sensitive", "WB-ua", "WB-multi", "WS-url-size", "WS-size", "WS-ip", "WS-errors", "WS-hour"} {
		categories = append(categories, behaviorRule(id, "").Category)
	}
	fallback := guidanceFor("future-category")
	for _, category := range categories {
		g := guidanceFor(category)
		if reflect.DeepEqual(g, fallback) {
			t.Errorf("category %s has only generic guidance", category)
		}
		if g.WhyUnknown == "" || len(g.WhereToCheck) == 0 || g.SuccessEvidence == "" || g.FailureEvidence == "" {
			t.Errorf("incomplete guidance for %s: %+v", category, g)
		}
	}
}

func TestInvestigationMultipleCategoriesAndFallback(t *testing.T) {
	categories := []string{"xss", "sqli", "xss", "future-category"}
	original := append([]string(nil), categories...)
	got := investigationFor(categories)
	if !reflect.DeepEqual(categories, original) || len(got) != 3 {
		t.Fatalf("mutated input or duplicate guidance: %+v / %v", got, categories)
	}
	if got[0].Category != "future-category" || !strings.Contains(got[1].WhereToCheck[1], "DB") || !strings.Contains(got[2].SuccessEvidence, "スクリプト") {
		t.Fatalf("missing category-specific guidance: %+v", got)
	}
	if g := investigationFor(nil); len(g) != 1 || g[0].Category != "unknown" || g[0].FailureEvidence == "" {
		t.Fatalf("missing fallback: %+v", g)
	}
}

func TestInvestigationWithUnknownTimezone(t *testing.T) {
	f := Incident{TimezoneUnknown: true, Categories: []string{"sqli", "command_injection"}}
	o := infer(&f)
	if o.Verdict != "unknown" || len(o.Investigation) != 2 || !strings.Contains(strings.Join(o.Missing, " "), "timezone") {
		t.Fatalf("timezone path lost guidance or uncertainty: %+v", o)
	}
}

func TestInvestigationReports(t *testing.T) {
	f := Incident{Categories: []string{"sqli", "xss", "<script>"}}
	f.Outcome = infer(&f)
	r := Report{Findings: []Incident{f}}
	for _, format := range []string{"html", "summary", "json", "csv"} {
		t.Run(format, func(t *testing.T) {
			var b bytes.Buffer
			if err := WriteReport(&b, r, format); err != nil {
				t.Fatal(err)
			}
			switch format {
			case "html", "summary":
				for _, text := range []string{"不明な理由", "確認する場所", "何が見つかれば判断できるか", "DB", "スクリプト", "成否不明", "失敗"} {
					if !strings.Contains(b.String(), text) {
						t.Errorf("%s omitted %s", format, text)
					}
				}
				if format == "html" && (strings.Contains(b.String(), "<script>") || !strings.Contains(b.String(), "&lt;script&gt;")) {
					t.Fatal("category was not HTML escaped")
				}
			case "json":
				var decoded Report
				if err := json.Unmarshal(b.Bytes(), &decoded); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(decoded.Findings[0].Outcome.Investigation, f.Outcome.Investigation) {
					t.Fatal("JSON lost structured guidance")
				}
			case "csv":
				rows, err := csv.NewReader(&b).ReadAll()
				if err != nil {
					t.Fatal(err)
				}
				var decoded Incident
				if err := json.Unmarshal([]byte(rows[2][8]), &decoded); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(decoded.Outcome.Investigation, f.Outcome.Investigation) {
					t.Fatal("CSV lost structured guidance")
				}
			}
		})
	}
}

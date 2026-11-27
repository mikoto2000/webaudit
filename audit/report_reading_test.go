package audit

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestExecutiveOutcomeReviewOrder(t *testing.T) {
	counts := map[string]int{"confirmed_failure": 2, "likely_failed": 4, "unknown": 3, "possible_success": 1, "confirmed_success": 0}
	rows := executiveOutcomeCounts(counts)
	var got []string
	for _, row := range rows {
		got = append(got, row.Label)
		if row.Count != int64(counts[row.Label]) {
			t.Fatal("reordering changed outcome counts")
		}
	}
	want := []string{"confirmed_success", "possible_success", "unknown", "likely_failed", "confirmed_failure"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("outcome order %v, want %v", got, want)
	}
}

func TestExecutiveQuickReadMatchesResponse(t *testing.T) {
	for _, tc := range []struct {
		level, ja, en string
	}{
		{"priority", "以降の02〜04に沿って、優先して担当者に追加確認", "review the priority cases first"},
		{"planned", "担当者と確認の予定", "Plan a review"},
		{"hold", "読み込めなかったログ", "unreadable logs"},
		{"monitor", "記録と監視を続けて", "continue logging and monitoring"},
	} {
		for _, lang := range []string{"ja", "en"} {
			t.Run(tc.level+"/"+lang, func(t *testing.T) {
				r := InvestigationReport{}
				r.Metadata.Language = lang
				r.DecisionSupport.ResponseLevel = tc.level
				var b bytes.Buffer
				if err := renderExecutiveReport(&b, &r); err != nil {
					t.Fatal(err)
				}
				page := b.String()
				start := strings.Index(page, `<section aria-labelledby="quick-read">`)
				if start < 0 {
					t.Fatal("missing plain-language summary")
				}
				quick := strings.SplitN(page[start:], "</section>", 2)[0]
				want, unknown := tc.ja, "何が起きたか判断できません"
				if lang == "en" {
					want, unknown = tc.en, "what happened cannot be assessed"
				}
				for _, text := range []string{want, unknown, `href="#next-actions"`} {
					if !strings.Contains(quick, text) {
						t.Errorf("quick summary missing %q", text)
					}
				}
				if strings.Contains(quick, "No suspicious candidates") || strings.Contains(quick, "不審な候補は見つかりませんでした") {
					t.Error("zero parsed observations must not be presented as a no-hit analysis")
				}
			})
		}
	}
}

func TestExecutiveQuickRisksMatchVisibleDetails(t *testing.T) {
	for _, lang := range []string{"ja", "en"} {
		t.Run(lang, func(t *testing.T) {
			r := InvestigationReport{}
			r.Metadata.Language = lang
			r.Summary.ParsedLines = 1
			// Repeated risks and a low-priority risk beyond the 10-row bound
			// must not create extra types or links to missing detail rows.
			for i := 0; i < 10; i++ {
				id := "risk-" + strings.Repeat("x", i+1)
				title := "Information exposure"
				if i == 0 {
					title = `<script>untrusted</script>`
				}
				r.DecisionSupport.Risks = append(r.DecisionSupport.Risks, DecisionRisk{ID: id, Title: title, Priority: "high"})
			}
			r.DecisionSupport.Risks = append(r.DecisionSupport.Risks, DecisionRisk{ID: "omitted-risk", Title: "Omitted type", Priority: "low"})
			var b bytes.Buffer
			if err := renderExecutiveReport(&b, &r); err != nil {
				t.Fatal(err)
			}
			page := b.String()
			parts := strings.SplitN(page, `<ul id="quick-risk-list">`, 2)
			if len(parts) != 2 {
				t.Fatal("missing risk list")
			}
			list := strings.SplitN(parts[1], "</ul>", 2)[0]
			if strings.Count(list, "<li>") != 2 || strings.Contains(list, "Omitted type") || strings.Contains(list, "<script>") {
				t.Fatalf("risk summary failed grouping, bounds or escaping: %s", list)
			}
			for _, id := range []string{"risk-x", "risk-xx"} {
				if !strings.Contains(list, `href="#`+id+`"`) || !strings.Contains(page, `<tr id="`+id+`"`) {
					t.Fatalf("summary link does not match section 02: %s", id)
				}
			}
			if len(r.DecisionSupport.Risks) != 11 {
				t.Fatal("summary changed the underlying risk model")
			}
		})
	}
}

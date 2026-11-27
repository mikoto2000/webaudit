package audit

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestEscalationCriteriaFollowRiskProfile(t *testing.T) {
	for _, lang := range []string{"ja", "en"} {
		seen := map[string]bool{}
		for _, categories := range [][]string{{"sensitive_file"}, {"login"}, {"sqli"}, {"large_response"}, {"traffic_spike"}} {
			profile := profileFor(categories, lang)
			criteria := profileEscalation(profile.key, lang)
			if criteria == "" || seen[criteria] {
				t.Fatalf("%s: missing or shared criteria for %s", lang, profile.key)
			}
			seen[criteria] = true
		}
		if profileEscalation(profileFor([]string{"unknown"}, lang).key, lang) != "" {
			t.Fatal("unclassified activity should use common criteria")
		}
		// A request matching several categories retains the existing profile
		// precedence, rather than adding criteria for unrelated risk profiles.
		profile := profileFor([]string{"sqli", "login", "sensitive_file"}, lang)
		if profile.key != "resource" {
			t.Fatal("risk profile precedence changed")
		}
	}
}

func TestExecutiveEscalationGroupsPreserveTargets(t *testing.T) {
	d := DecisionSupport{CommonEscalation: "common", Risks: []DecisionRisk{
		{ID: "r1", CaseID: "a", Title: "Files", Escalation: "file evidence"},
		{ID: "r2", CaseID: "b", Title: "Files", Escalation: "file evidence"},
		{ID: "r3", CaseID: "c", Title: "Processing", Escalation: "processing evidence"},
		{ID: "r4", CaseID: "d", Title: "General", Escalation: "common"},
		{ID: "r5", CaseID: "e", Title: "Empty"},
	}}
	groups := executiveEscalationGroups(d)
	if len(groups) != 2 || len(groups[0].Targets) != 2 || groups[0].Targets[1].CaseID != "b" || groups[1].Targets[0].CaseID != "c" {
		t.Fatalf("incorrect grouping or lost references: %+v", groups)
	}
	if len(d.Risks) != 5 {
		t.Fatal("presentation grouping changed underlying risks")
	}
	if len(executiveEscalationGroups(DecisionSupport{})) != 0 {
		t.Fatal("no candidates must not produce individual criteria")
	}
}

func TestEscalationBundleOutputsAgree(t *testing.T) {
	for _, lang := range []string{"ja", "en"} {
		t.Run(lang, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "report")
			r, err := GenerateBundle([]string{"../examples/sample.log"}, dir, Options{}, BundleOptions{Language: lang})
			if err != nil {
				t.Fatal(err)
			}
			d := r.DecisionSupport
			if d.CommonEscalation == "" || d.CommonDefer == "" || d.Version != "webaudit/response-rules-2" {
				t.Fatal("missing common guidance or rules version")
			}
			csvByCase := map[string]map[string]string{}
			for _, row := range bundleCSV(t, filepath.Join(dir, "risk-register.csv")) {
				csvByCase[row["case_id"]] = row
			}
			var standalone DecisionSupport
			if err := json.Unmarshal(audienceRead(t, dir, "data/decision-support.json"), &standalone); err != nil {
				t.Fatal(err)
			}
			if standalone.CommonEscalation != d.CommonEscalation || len(standalone.Risks) != len(d.Risks) {
				t.Fatal("shared model mismatch")
			}
			for _, risk := range d.Risks {
				want := profileEscalation(risk.Profile, lang)
				if want == "" {
					want = d.CommonEscalation
				}
				row := csvByCase[risk.CaseID]
				if risk.Escalation != want || row["escalation"] != want || row["if_deferred"] != d.CommonDefer {
					t.Fatalf("criteria diverged for %s", risk.CaseID)
				}
			}
			page := string(audienceRead(t, dir, "executive-summary.html"))
			section := strings.SplitN(page, "05 ", 2)[1]
			if strings.Count(section, d.CommonEscalation) != 1 || strings.Count(section, d.CommonDefer) != 1 {
				t.Fatal("common guidance should appear once in section 05")
			}
			if !strings.Contains(section, audienceText(lang, "04の追加調査の結果を受け取ってから", "Use this chapter after receiving the results")) {
				t.Fatal("section 05 must explain when to use it")
			}
			// Use the actual bounded view: grouped conditions must not drop
			// visible references or link to omitted section 02 rows.
			view := d
			view.Risks = executiveRisks(r)
			for _, group := range executiveEscalationGroups(view) {
				if strings.Count(section, group.Condition) != 1 {
					t.Fatal("specific criteria were duplicated or omitted")
				}
				for _, risk := range group.Targets {
					if !strings.Contains(section, `href="#`+risk.ID+`"`) || !strings.Contains(page, `id="`+risk.ID+`"`) {
						t.Fatal("missing target reference")
					}
				}
			}
			before, _ := json.Marshal(r.Analysis)
			var rendered bytes.Buffer
			if err := renderExecutiveReport(&rendered, r); err != nil {
				t.Fatal(err)
			}
			after, _ := json.Marshal(r.Analysis)
			if !bytes.Equal(before, after) {
				t.Fatal("rendering changed detection or outcome data")
			}
		})
	}
}

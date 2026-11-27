package audit

import (
	"reflect"
	"testing"
)

func TestRiskCoverageUsesCaseAndEngineReferences(t *testing.T) {
	r := &InvestigationReport{}
	r.Analysis.Findings = []Incident{{ID: "case-native", Outcome: Outcome{Missing: []string{"historical response content"}}}}
	r.DecisionSupport.Actions = []DecisionAction{
		{CaseID: "case-native", Materials: []string{"application records"}},
		{CaseID: "source-detection", Materials: []string{"source rule evidence"}},
	}
	r.DecisionSupport.Risks = []DecisionRisk{
		{ID: "risk-native", CaseID: "case-native", Kind: "finding", Title: "Same title", Priority: "high"},
		{ID: "risk-fallback", CaseID: "case-fallback", Kind: "finding", Title: "Same title", Priority: "high"},
		{ID: "risk-source", CaseID: "source-detection", Kind: "independent_detection", Title: "Same title"},
		{ID: "risk-missing", CaseID: "missing-detection", Kind: "independent_detection", Title: "Same title"},
	}
	r.Detections = []BundleDetection{
		{ID: "source-detection", Engine: "aura", RuleID: "shared-name"},
		{ID: "missing-detection", Engine: "hub", RuleID: "shared-name"},
	}
	coverage := []CoverageRow{
		{ID: "ASPECT-native", HasDetections: true, FindingIDs: []string{"case-native"}},
		{ID: "ASPECT-unrelated", Name: "Same title", HasDetections: true, FindingIDs: []string{"other-case"}},
		{ID: "RULE-webaudit-fallback", Engines: []string{"webaudit"}, RuleIDs: []string{"fallback"}, FindingIDs: []string{"case-fallback"}},
		{ID: "RULE-webaudit-same", Engines: []string{"webaudit"}, RuleIDs: []string{"shared-name"}},
		{ID: "RULE-aura-same", Engines: []string{"aura"}, RuleIDs: []string{"shared-name"}},
	}
	rows := riskCoverageRows(r, coverage)
	if len(rows) != 4 {
		t.Fatal("a missing correspondence must not drop its executive risk")
	}
	want := []string{"ASPECT-native", "RULE-webaudit-fallback", "RULE-aura-same"}
	for i, id := range want {
		if len(rows[i].Perspectives) != 1 || rows[i].Perspectives[0].ID != id {
			t.Fatalf("incorrect correspondence for risk %d: %+v", i, rows[i])
		}
	}
	if rows[2].Engine != "aura" || rows[3].Engine != "hub" || len(rows[3].Perspectives) != 0 {
		t.Fatal("independent engines were conflated or missing correspondence was invented")
	}
	if !reflect.DeepEqual(rows[0].Missing, []string{"historical response content"}) || !reflect.DeepEqual(rows[0].Materials, []string{"application records"}) {
		t.Fatal("native follow-up records must come from this target's evidence and action")
	}
	if len(rows[2].Missing) != 0 || !reflect.DeepEqual(rows[2].Materials, []string{"source rule evidence"}) {
		t.Fatal("independent target inherited another case's missing evidence or records")
	}
	if len(riskCoverageRows(&InvestigationReport{}, coverage)) != 0 {
		t.Fatal("no executive risks should produce no risk correspondence rows")
	}
	for i := 0; i < 20; i++ {
		r.DecisionSupport.Risks = append(r.DecisionSupport.Risks, DecisionRisk{ID: "extra", Priority: "low"})
	}
	rows = riskCoverageRows(r, nil)
	executive := executiveRisks(r)
	if len(rows) != 10 {
		t.Fatal("risk correspondence must share the executive display limit")
	}
	for i, row := range rows {
		if !reflect.DeepEqual(row.Risk, executive[i]) || len(row.Perspectives) != 0 {
			t.Fatal("risk order diverged or omitted coverage rows were linked")
		}
	}
}

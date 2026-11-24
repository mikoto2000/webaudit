package audit

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"reflect"
	"sort"
	"strconv"
)

//go:embed investigation.html
var investigationHTML string

type reportCaseView struct {
	Finding    Incident
	Metrics    FindingObservation
	Assessment CaseAssessment
	Rules      []AnalysisRule
	Samples    []caseSampleView
}
type caseSampleView struct {
	Evidence  Evidence
	Reference EvidenceReference
}
type sourceReportView struct {
	Detection BundleDetection
	Source    SourceAlert
	Rule      AnalysisRule
	Samples   []sourceSampleView
}
type sourceSampleView struct {
	Sample    SourceEvidence
	Reference EvidenceReference
}
type chartBar struct {
	Label string
	Count int64
}
type reportChart struct {
	Title     string
	Rows      []chartBar
	Maximum   int64
	TotalRows int
	Annex     string
}
type reportHTMLView struct {
	R                                                                   *InvestigationReport
	Cases                                                               []reportCaseView
	Sources                                                             []sourceReportView
	Coverage                                                            []CoverageRow
	Rules                                                               []AnalysisRule
	Charts                                                              []reportChart
	Timeline                                                            []TimelineRow
	TimelineMax                                                         int64
	CaseIDs, CoverageIDs, RuleIDs, SourceIDs                            map[string]bool
	TruncatedCases, TruncatedSources, TruncatedCoverage, TruncatedRules bool
}

func reportRuleAnchor(engine, id string) string { return "rule-" + bundleID("", engine+"|"+id) }
func buildReportHTMLView(r *InvestigationReport, tr reportTranslator) reportHTMLView {
	v := reportHTMLView{R: r, CaseIDs: map[string]bool{}, SourceIDs: map[string]bool{}, CoverageIDs: map[string]bool{}, RuleIDs: map[string]bool{}, TimelineMax: 1}
	metrics := map[string]FindingObservation{}
	for _, m := range r.FindingObservations {
		metrics[m.ID] = m
	}
	assessments := map[string]CaseAssessment{}
	for _, a := range r.Assessments {
		assessments[a.FindingID] = a
	}
	for _, f := range r.Analysis.Findings {
		if len(v.Cases) >= 100 {
			v.TruncatedCases = true
			break
		}
		item := reportCaseView{Finding: f, Metrics: metrics[f.ID], Assessment: assessments[f.ID]}
		for _, rule := range r.AnalysisRules {
			if rule.Engine != "webaudit" {
				continue
			}
			for _, matched := range f.Rules {
				if matched.ID == rule.ID {
					item.Rules = append(item.Rules, rule)
				}
			}
		}
		for i, e := range f.Evidence {
			ref := EvidenceReference{}
			if i < len(item.Assessment.EvidenceRefs) {
				ref = item.Assessment.EvidenceRefs[i]
			}
			item.Samples = append(item.Samples, caseSampleView{e, ref})
		}
		v.Cases = append(v.Cases, item)
		v.CaseIDs[f.ID] = true
	}
	for _, d := range r.Detections {
		if d.Engine == "webaudit" || d.Engine == "geoip" {
			continue
		}
		if len(v.Sources) >= 100 {
			v.TruncatedSources = true
			break
		}
		item := sourceReportView{Detection: d}
		if source := sourceAlertFor(r, d); source != nil {
			item.Source = *source
		}
		for _, rule := range r.AnalysisRules {
			if rule.Engine == d.Engine && rule.ID == d.RuleID {
				item.Rule = rule
				break
			}
		}
		for _, sample := range item.Source.Evidence {
			ref := EvidenceReference{}
			for _, candidate := range d.EvidenceRefs {
				if candidate.File == sample.File && candidate.Line == sample.Line {
					ref = candidate
					break
				}
			}
			if ref.FileID == "" {
				ref = evidenceReference(r, sample.File, sample.Line)
			}
			item.Samples = append(item.Samples, sourceSampleView{sample, ref})
		}
		v.Sources = append(v.Sources, item)
		v.SourceIDs[d.ID] = true
	}
	for _, row := range r.Coverage {
		if len(v.Coverage) >= 1000 {
			v.TruncatedCoverage = true
			break
		}
		v.Coverage = append(v.Coverage, row)
		v.CoverageIDs[row.ID] = true
	}
	for _, rule := range r.AnalysisRules {
		if len(v.Rules) >= 1000 {
			v.TruncatedRules = true
			break
		}
		v.Rules = append(v.Rules, rule)
		v.RuleIDs[reportRuleAnchor(rule.Engine, rule.ID)] = true
	}
	for _, row := range r.Statistics.Timeline {
		if row.Requests > v.TimelineMax {
			v.TimelineMax = row.Requests
		}
	}
	v.Timeline = r.Statistics.Timeline
	if len(v.Timeline) > 120 {
		v.Timeline = v.Timeline[:120]
	}
	for _, spec := range []struct{ dim, title, annex string }{{"method", "HTTP method counts", "method"}, {"status", "HTTP status counts", "status"}, {"ip", "Source IP ranking", "ip"}, {"uri", "URI path ranking", "uri"}, {"host", "Target host counts", "host"}, {"user_agent", "User-Agent counts", "user-agent"}, {"status_class", "HTTP status class counts", "status-class"}, {"country", "Country request counts", "country"}, {"asn", "ASN request counts", "asn"}} {
		if (spec.dim == "country" || spec.dim == "asn") && !r.Statistics.GeoIPEnabled {
			continue
		}
		chart := reportChart{Title: spec.title, Annex: "statistics/" + spec.annex + "-summary.csv", Maximum: 1, TotalRows: len(r.Statistics.Dimensions[spec.dim])}
		for _, row := range r.Statistics.Dimensions[spec.dim] {
			if len(chart.Rows) >= 20 {
				break
			}
			label := tr.text("unknown")
			if row.Value != nil {
				label = *row.Value
			}
			if row.Other {
				label = tr.text("Other retained-limit observations")
			}
			chart.Rows = append(chart.Rows, chartBar{label, row.Requests})
			if row.Requests > chart.Maximum {
				chart.Maximum = row.Requests
			}
		}
		v.Charts = append(v.Charts, chart)
	}
	countChart := func(title string, values map[string]int64, annex string) {
		chart := reportChart{Title: title, Maximum: 1, Annex: annex, TotalRows: len(values)}
		for key, n := range values {
			chart.Rows = append(chart.Rows, chartBar{tr.text(key), n})
			if n > chart.Maximum {
				chart.Maximum = n
			}
		}
		sort.Slice(chart.Rows, func(i, j int) bool {
			if chart.Rows[i].Count != chart.Rows[j].Count {
				return chart.Rows[i].Count > chart.Rows[j].Count
			}
			return chart.Rows[i].Label < chart.Rows[j].Label
		})
		if len(chart.Rows) > 30 {
			chart.Rows = chart.Rows[:30]
		}
		v.Charts = append(v.Charts, chart)
	}
	countChart("Detection counts by engine and category", r.Statistics.AttackDetections, "analysis-coverage.csv")
	severities, outcomes := map[string]int64{}, map[string]int64{}
	for key, n := range r.Analysis.Severities {
		severities[key] = int64(n)
	}
	for key, n := range r.Analysis.Outcomes {
		outcomes[key] = int64(n)
	}
	countChart("Severity counts", severities, "findings.csv")
	countChart("Outcome counts", outcomes, "findings.csv")
	return v
}
func writeInvestigationHTML(w io.Writer, r *InvestigationReport) error {
	tr := reportTranslator{language: r.Metadata.Language}
	v := buildReportHTMLView(r, tr)
	numeric := func(value any) string {
		if value == nil {
			return tr.text("unknown")
		}
		rv := reflect.ValueOf(value)
		for rv.Kind() == reflect.Pointer {
			if rv.IsNil() {
				return tr.text("unknown")
			}
			rv = rv.Elem()
		}
		if rv.Kind() == reflect.Float64 {
			return strconv.FormatFloat(rv.Float(), 'g', 6, 64)
		}
		return fmt.Sprint(rv.Interface())
	}
	functions := template.FuncMap{"t": tr.text, "outcome": tr.outcome, "diagnostic": tr.diagnostic, "lang": func() string { return r.Metadata.Language }, "n": numeric, "dt": func(value any) string { return numeric(value) }, "specified": func(value string) string {
		if value == "" {
			return tr.text("Not specified")
		}
		return value
	}, "caseVisible": func(id string) bool { return v.CaseIDs[id] }, "sourceVisible": func(id string) bool { return v.SourceIDs[id] }, "coverageVisible": func(id string) bool { return v.CoverageIDs[id] }, "ruleAnchor": reportRuleAnchor, "ruleVisible": func(engine, id string) bool { return v.RuleIDs[reportRuleAnchor(engine, id)] }, "meanBytes": func(m FindingObservation) *float64 {
		if m.BytesCount == 0 {
			return nil
		}
		return ptr(m.BytesSum / float64(m.BytesCount))
	}, "percent": func(value *float64) string {
		if value == nil {
			return tr.text("unknown")
		}
		return strconv.FormatFloat(*value, 'f', 2, 64) + "%"
	}, "title": func() string {
		if r.Metadata.Title != "" {
			return r.Metadata.Title
		}
		return tr.text("Access log investigation report")
	}}
	parsed, err := template.New("investigation").Funcs(functions).Parse(investigationHTML)
	if err != nil {
		return err
	}
	return parsed.Execute(w, v)
}

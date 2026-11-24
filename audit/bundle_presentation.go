package audit

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type InvestigationSummary struct {
	InputFiles         int              `json:"input_files"`
	TotalLines         int64            `json:"total_lines"`
	ParsedLines        int64            `json:"parsed_lines"`
	UnparsedLines      int64            `json:"unparsed_lines"`
	ExcludedLines      int64            `json:"excluded_lines"`
	TotalRequests      int64            `json:"total_requests"`
	UniqueIPs          int64            `json:"unique_ips"`
	SuspiciousRequests int64            `json:"suspicious_requests"`
	SuspiciousIPs      int64            `json:"suspicious_ips"`
	SuspiciousPercent  *float64         `json:"suspicious_percent"`
	Detections         int64            `json:"detections"`
	DetectionsByEngine map[string]int64 `json:"detections_by_engine"`
	Findings           int              `json:"findings"`
	PriorityFindings   int              `json:"priority_findings"`
	SeverityCounts     map[string]int   `json:"severity_counts"`
	OutcomeCounts      map[string]int   `json:"outcome_counts"`
	CountQuality       string           `json:"count_quality"`
}
type CaseAssessment struct {
	EvidenceRefs        []EvidenceReference `json:"evidence_refs"`
	FindingID           string              `json:"finding_id"`
	DetectionConfidence string              `json:"detection_confidence"`
	Priority            string              `json:"priority"`
	Facts               []string            `json:"facts"`
	Inferences          []string            `json:"inferences"`
	Unknowns            []string            `json:"unknowns"`
	BenignAlternatives  []string            `json:"benign_alternatives"`
	ConditionalImpacts  []string            `json:"conditional_impacts"`
	RelatedFindingIDs   []string            `json:"related_finding_ids"`
	RelatedIPs          []string            `json:"related_ips"`
	CoverageIDs         []string            `json:"coverage_ids"`
}
type Recommendation struct {
	ID              string     `json:"id"`
	Type            string     `json:"type"`
	Title           string     `json:"title"`
	Reason          string     `json:"reason"`
	FindingIDs      []string   `json:"finding_ids"`
	DetectionIDs    []string   `json:"detection_ids"`
	Priority        string     `json:"priority"`
	WhereToCheck    []string   `json:"where_to_check"`
	Method          string     `json:"method"`
	SuccessEvidence string     `json:"success_evidence"`
	FailureEvidence string     `json:"failure_evidence"`
	First           *time.Time `json:"first"`
	Last            *time.Time `json:"last"`
	IP              string     `json:"source_ip"`
	Host            *string    `json:"host"`
	URIs            []string   `json:"uri_samples"`
}

func investigationPriority(f Incident) string {
	if f.Outcome.Verdict == "possible_success" || f.Severity == "critical" || f.Severity == "high" {
		return "high"
	}
	if f.Severity == "medium" {
		return "medium"
	}
	return "low"
}
func conditionalImpact(category string) string {
	switch category {
	case "sqli", "nosqli", "ldap_injection", "xpath_injection":
		return "If an applicable injection vulnerability exists, unauthorized data access, modification or authentication bypass may be possible. Vulnerability and impact are unverified."
	case "command_injection", "deserialization", "log4shell", "spring4shell", "struts_ognl", "shellshock":
		return "If vulnerable code handles the request, unauthorized code execution may be possible. Execution and compromise are unverified."
	case "xss":
		return "If the input is rendered unsafely, browser script execution may be possible. Response content and browser execution are unverified."
	case "lfi_traversal", "rfi", "sensitive_file":
		return "If sensitive resources are exposed or file inclusion is vulnerable, confidential file disclosure or code loading may be possible. Returned content is unverified."
	case "ssrf":
		return "If server-side fetching is vulnerable, internal service access or unintended outbound connections may be possible. Server-side activity is unverified."
	case "auth", "login", "access_bypass":
		return "If authentication or access controls are vulnerable, unauthorized account or resource access may be possible. Authentication results are unverified."
	case "rate", "burst", "WS-hour", "WS-ip", "WS-errors", "WS-size", "WS-url-size":
		return "Traffic or response anomalies may affect availability or indicate unusual processing, but authorized activity and normal routing are alternatives. Impact is unverified."
	default:
		return "Observed probes alone do not establish an exploitable vulnerability, attacker intent or actual impact."
	}
}
func prepareInvestigationReport(r *InvestigationReport, max int) {
	r.Summary = InvestigationSummary{InputFiles: len(r.Inventory), TotalRequests: r.Statistics.TotalRequests, UniqueIPs: r.Statistics.UniqueIPs, SuspiciousRequests: r.Evidence.SuspiciousRequests, SuspiciousIPs: r.Statistics.SuspiciousIPs, SuspiciousPercent: r.Statistics.SuspiciousPercent, Findings: len(r.Analysis.Findings), DetectionsByEngine: map[string]int64{}, SeverityCounts: r.Analysis.Severities, OutcomeCounts: r.Analysis.Outcomes, CountQuality: r.CountQuality}
	for _, in := range r.Inventory {
		r.Summary.TotalLines += in.TotalLines
		r.Summary.ParsedLines += in.Parsed
		r.Summary.UnparsedLines += in.Unparsed
		r.Summary.ExcludedLines += in.Excluded
	}
	for _, row := range r.Coverage {
		if strings.HasPrefix(row.ID, "RULE-") && len(row.Engines) == 1 && row.Engines[0] != "geoip" && row.Detections != nil {
			r.Summary.DetectionsByEngine[row.Engines[0]] += *row.Detections
		}
	}
	for _, n := range r.Summary.DetectionsByEngine {
		r.Summary.Detections += n
	}
	tr := reportTranslator{language: r.Metadata.Language}
	translate := func(values []string) []string {
		out := make([]string, len(values))
		for i, v := range values {
			out[i] = tr.text(v)
		}
		return out
	}
	metrics := map[string]FindingObservation{}
	for _, m := range r.FindingObservations {
		metrics[m.ID] = m
	}
	add := func(rec Recommendation) {
		if len(r.Recommendations) >= max {
			r.RecommendationsTruncated = true
			return
		}
		r.Recommendations = append(r.Recommendations, rec)
	}
	for _, f := range r.Analysis.Findings {
		priority := investigationPriority(f)
		if priority == "high" {
			r.Summary.PriorityFindings++
		}
		assessment := CaseAssessment{FindingID: f.ID, DetectionConfidence: "unknown", Priority: priority, Facts: []string{"Counts, status codes and source references describe observed log records, not verified server-side execution."}, Inferences: append([]string(nil), f.Reasons...), Unknowns: append([]string(nil), f.Outcome.Missing...), BenignAlternatives: []string{"Authorized testing, legitimate traffic, shared addresses and common error routing may explain some matches. Validate application context."}}
		for _, rule := range f.Rules {
			uniqueAppend(&assessment.Inferences, rule.Description)
		}
		for _, category := range f.Categories {
			uniqueAppend(&assessment.ConditionalImpacts, conditionalImpact(category))
		}
		for _, row := range r.Coverage {
			for _, id := range row.FindingIDs {
				if id == f.ID {
					assessment.CoverageIDs = append(assessment.CoverageIDs, row.ID)
					break
				}
			}
		}
		if r.Analysis.GeoIP != nil {
			for _, hint := range r.Analysis.GeoIP.Correlations {
				matches := false
				for _, id := range hint.IncidentIDs {
					matches = matches || id == f.ID
				}
				if matches {
					for _, id := range hint.IncidentIDs {
						if id != f.ID {
							uniqueAppend(&assessment.RelatedFindingIDs, id)
						}
					}
					for _, ip := range hint.IPs {
						if ip != f.IP {
							uniqueAppend(&assessment.RelatedIPs, ip)
						}
					}
				}
			}
		}
		for _, evidence := range f.Evidence {
			assessment.EvidenceRefs = append(assessment.EvidenceRefs, evidenceReference(r, evidence.Event.File, evidence.Event.Line))
		}
		r.Assessments = append(r.Assessments, assessment)
		guides := f.Outcome.Investigation
		if len(guides) == 0 {
			guides = investigationFor(f.Categories)
		}
		for _, guide := range guides {
			rec := Recommendation{ID: bundleID("REC-", f.ID+"\x00"+guide.Category), Type: "investigation", Title: tr.text("Collect corroborating evidence") + ": " + tr.text(guide.Category), Reason: tr.text(guide.WhyUnknown), FindingIDs: []string{f.ID}, Priority: priority, WhereToCheck: translate(guide.WhereToCheck), Method: tr.text("Correlate the recorded interval, host, URI and request identifiers; source IP alone is not verified identity."), SuccessEvidence: tr.text(guide.SuccessEvidence), FailureEvidence: tr.text(guide.FailureEvidence), IP: f.IP, Host: f.Host, URIs: metrics[f.ID].URIs}
			if !f.TimezoneUnknown {
				rec.First = ptr(f.First)
				rec.Last = ptr(f.Last)
			}
			add(rec)
		}
	}
	for i := range r.Detections {
		d := &r.Detections[i]
		if source := sourceAlertFor(r, *d); source != nil {
			for _, ref := range source.Events {
				if len(d.EvidenceRefs) >= 8 {
					break
				}
				d.EvidenceRefs = append(d.EvidenceRefs, evidenceReference(r, ref.File, ref.Line))
			}
		}
	}
	for _, d := range r.Detections {
		if d.Engine == "webaudit" {
			continue
		}
		add(Recommendation{ID: bundleID("REC-", d.ID), Type: "investigation", Title: tr.text("Review independent source detection"), Reason: tr.text(d.Reason), DetectionIDs: []string{d.ID}, Priority: "unassessed", WhereToCheck: []string{tr.text("Original source references and the source rule conditions"), tr.text("Application and server records for the recorded group and interval")}, Method: tr.text("Validate whether the rule applies to the target system; group membership is not proof that every request is malicious."), SuccessEvidence: tr.text("Corroborating application, host or response evidence is required to confirm success."), FailureEvidence: tr.text("Contemporaneous records showing rejection before the affected operation can support failure for the verified requests."), First: d.First, Last: d.Last, IP: d.IP, Host: d.Host})
	}
	if r.RecommendationsTruncated {
		r.Complete = false
		if r.Status != "failed" {
			r.Status = "partial"
		}
		r.Analysis.Partial = true
		r.Analysis.warn("Recommendation limit reached; recommendations are incomplete")
	}
	r.MaskingEnabled = !r.Metadata.IncludeSensitiveEvidence
	r.MaskingNotes = []string{"Deterministic masking covers common query credentials, Authorization and Cookie values; it is not a guarantee that all personal or secret data is removed.", "Original files are unchanged. File identifiers, original hashes and line numbers retain source traceability.", "IP addresses and investigator metadata are not anonymized; review sensitive evidence before sharing."}
}

var secretQuery = regexp.MustCompile(`(?i)((?:[?&;]|%3f|%26)(?:access_token|api[_-]?key|token|password|passwd|secret|session(?:id|_id)?|authorization|cookie)(?:=|%3d))([^&\s"'<>]+)`)
var secretPair = regexp.MustCompile(`(?i)(\b(?:access_token|api[_-]?key|token|password|passwd|secret|session(?:id|_id)?)=)([^&\s"'<>]+)`)
var secretHeader = regexp.MustCompile(`(?i)((?:cookie|set-cookie|authorization|proxy-authorization)\s*:\s*)([^"\r\n]*)`)
var secretJSON = regexp.MustCompile(`(?i)("(?:http_)?(?:authorization|cookie|set_cookie|access_token|api_key|password|token|session_id)"\s*:\s*)("(?:[^"\\]|\\.)*"|[^,}\s]+)`)
var secretBearer = regexp.MustCompile(`(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+`)

func maskReportString(s string) string {
	s = secretJSON.ReplaceAllString(s, `${1}"[REDACTED]"`)
	s = secretQuery.ReplaceAllString(s, `${1}[REDACTED]`)
	s = secretPair.ReplaceAllString(s, `${1}[REDACTED]`)
	s = secretHeader.ReplaceAllString(s, `${1}[REDACTED]`)
	return secretBearer.ReplaceAllString(s, `${1} [REDACTED]`)
}
func maskTree(value any) any {
	switch v := value.(type) {
	case string:
		return maskReportString(v)
	case []any:
		for i, item := range v {
			v[i] = maskTree(item)
		}
		return v
	case map[string]any:
		for key, item := range v {
			if key == "pattern" || key == "filter" || key == "condition" || key == "conditions" {
				continue
			}
			v[key] = maskTree(item)
		}
		return v
	}
	return value
}
func maskJSON(data []byte) ([]byte, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return json.Marshal(maskTree(value))
}
func maskCommonReport(r *InvestigationReport) error {
	if r.Metadata.IncludeSensitiveEvidence {
		return nil
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	data, err = maskJSON(data)
	if err != nil {
		return err
	}
	var masked InvestigationReport
	if err = json.Unmarshal(data, &masked); err != nil {
		return err
	}
	*r = masked
	return nil
}
func maskCSVValue(value, header string) string {
	if header == "condition" || header == "conditions" || header == "filter" {
		return value
	}
	if strings.HasSuffix(header, "_json") {
		if masked, err := maskJSON([]byte(value)); err == nil {
			return string(masked)
		}
	}
	return maskReportString(value)
}
func writeRecommendations(b *bundleWriter, r *InvestigationReport) error {
	return b.csv("recommendations.csv", []string{"recommendation_id", "type", "title", "reason", "finding_ids", "detection_ids", "priority", "where_to_check", "method", "success_evidence", "failure_evidence", "first", "last", "source_ip", "host", "uri_samples"}, func(write func(...string) error) error {
		for _, rec := range r.Recommendations {
			if err := write(rec.ID, rec.Type, rec.Title, rec.Reason, strings.Join(rec.FindingIDs, ";"), strings.Join(rec.DetectionIDs, ";"), rec.Priority, strings.Join(rec.WhereToCheck, ";"), rec.Method, rec.SuccessEvidence, rec.FailureEvidence, bundleTime(rec.First), bundleTime(rec.Last), rec.IP, val(rec.Host), strings.Join(rec.URIs, ";")); err != nil {
				return err
			}
		}
		return nil
	})
}

type EvidenceReference struct {
	RequestID string `json:"request_id"`
	FileID    string `json:"source_file_id"`
	File      string `json:"source_file"`
	Line      int64  `json:"source_line"`
}

func evidenceReference(r *InvestigationReport, file string, line int64) EvidenceReference {
	fileID := ""
	for _, in := range r.Inventory {
		if in.Path == file {
			fileID = in.ID
			break
		}
	}
	return EvidenceReference{RequestID: bundleID("REQ-", fileID+"\x00"+strconv.FormatInt(line, 10)), FileID: fileID, File: file, Line: line}
}
func sourceAlertFor(r *InvestigationReport, d BundleDetection) *SourceAlert {
	if d.SourceIndex == nil {
		return nil
	}
	var rows []SourceAlert
	switch d.Engine {
	case "hub":
		rows = r.Analysis.UpstreamAlerts
	case "aura":
		rows = r.Analysis.AuraMatches
	case "aura-analysis":
		rows = r.Analysis.AuraAnalysis
	}
	if *d.SourceIndex < 0 || *d.SourceIndex >= len(rows) {
		return nil
	}
	return &rows[*d.SourceIndex]
}

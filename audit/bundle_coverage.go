package audit

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type AnalysisRule struct {
	ID          string   `json:"id"`
	Engine      string   `json:"engine"`
	Kind        string   `json:"kind"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Required    []string `json:"required_fields"`
	Condition   string   `json:"condition"`
	Supported   bool     `json:"supported"`
	Enabled     bool     `json:"enabled"`
}
type CoverageRow struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	RuleIDs           []string `json:"rule_ids"`
	Engines           []string `json:"engines"`
	Status            string   `json:"status"`
	Evaluation        string   `json:"evaluation"`
	Complete          bool     `json:"complete"`
	HasDetections     bool     `json:"has_detections"`
	EligibleRequests  *int64   `json:"eligible_requests"`
	DetectedRequests  *int64   `json:"detected_requests"`
	Detections        *int64   `json:"detections"`
	MatchedCandidates *int64   `json:"matched_candidates"`
	FindingIDs        []string `json:"finding_ids"`
	Conditions        []string `json:"conditions"`
	Limitations       []string `json:"limitations"`
	CountQuality      string   `json:"count_quality"`
}
type ruleObservation struct{ eligible, matched, detections int64 }
type aspectDefinition struct {
	ID, Name string
	Rules    []string
	Partial  bool
}

func bundleAspects() []aspectDefinition {
	specs := []struct {
		id, name, rules string
		partial         bool
	}{
		{"sqli", "SQL injection", "WA-sqli", false}, {"nosqli", "NoSQL injection", "WA-nosqli", false}, {"xss", "Cross-site scripting", "WA-xss", false},
		{"command_injection", "OS command injection", "WA-command_injection", false}, {"rce", "Remote code execution", "WA-command_injection,WA-deserialization,WA-struts_ognl", true},
		{"traversal", "Directory traversal", "WA-lfi_traversal", true}, {"lfi", "Local file inclusion", "WA-lfi_traversal", true}, {"rfi", "Remote file inclusion", "WA-rfi", false},
		{"ssrf", "Server-side request forgery", "WA-ssrf", false}, {"ssti", "Server-side template injection", "WA-ssti", false}, {"ldap_injection", "LDAP injection", "WA-ldap_injection", false},
		{"xpath_injection", "XPath injection", "WA-xpath_injection", false}, {"xxe", "XML external entity injection", "WA-xxe", false}, {"deserialization", "Deserialization attacks", "WA-deserialization", false},
		{"crlf_injection", "CRLF injection", "WA-crlf_injection", false}, {"cve_probe", "Known vulnerability probes", "WA-cve_probe", true}, {"log4shell", "Log4Shell", "WA-log4shell", false},
		{"spring4shell", "Spring4Shell", "WA-spring4shell", false}, {"shellshock", "Shellshock", "WA-shellshock", false}, {"struts_ognl", "Struts attacks", "WA-struts_ognl", false},
		{"webshell", "WebShell-related access", "WA-webshell", false}, {"sensitive_file", "Sensitive file access", "WA-sensitive_file", false}, {"admin_probing", "Administrative interface probing", "WB-paths", true},
		{"recon_probe", "Directory and file probing", "WA-recon_probe,WB-paths,WB-sensitive", true}, {"brute_force", "Brute-force indicators", "WB-auth,WB-login", false},
		{"method", "Unusual HTTP methods", "WA-method", false}, {"unusual_protocol", "Unusual HTTP protocols", "WA-protocol", false}, {"scanner", "Suspicious User-Agent", "WA-scanner,WB-ua", true},
		{"rate", "High request rate", "WB-rate,WB-burst", false}, {"errors4xx", "Unusual 4xx responses", "WB-404,WB-auth,WS-errors", true}, {"errors5xx", "Unusual 5xx responses", "WS-errors", true},
		{"response_size", "Unusual response size", "WS-url-size,WS-size,WS-ip", true}, {"follow_up", "Suspicious access following probes", "WB-multi", true},
		{"multi_ip", "Similar activity from multiple IPs", "geoip-similarity", true}, {"ip_reputation", "IP reputation", "", false}, {"request_body", "Attacks in request bodies", "", false},
		{"open_redirect", "Open redirect", "WA-open_redirect", false}, {"access_bypass", "Access bypass", "WA-access_bypass", false}, {"null_byte", "Null byte injection", "WA-null_byte", false},
		{"iis_aspnet", "IIS and ASP.NET probes", "WA-iis_aspnet", false}, {"hourly_anomaly", "Hourly traffic anomaly", "WS-hour", false},
	}
	out := make([]aspectDefinition, 0, len(specs))
	for _, s := range specs {
		a := aspectDefinition{ID: s.id, Name: s.name, Partial: s.partial}
		if s.rules != "" {
			a.Rules = strings.Split(s.rules, ",")
		}
		out = append(out, a)
	}
	return out
}
func analysisRules() []AnalysisRule {
	var out []AnalysisRule
	for _, r := range Rules() {
		required := append([]string(nil), r.Required...)
		out = append(out, AnalysisRule{ID: r.ID, Engine: "webaudit", Kind: "signature", Category: r.Category, Description: r.Description, Required: required, Condition: r.Field + ": " + r.Pattern, Supported: true, Enabled: true})
	}
	behavior := []struct{ id, desc, required, condition string }{
		{"WB-404", "Concentrated HTTP 404 responses", "ip,time,status", "at least 20 HTTP 404 observations"},
		{"WB-auth", "Concentrated HTTP 401/403 responses", "ip,time,status", "at least 20 HTTP 401/403 observations"},
		{"WB-login", "Repeated login endpoint requests", "ip,time,target,method", "at least 20 POST requests to known login endpoints"},
		{"WB-rate", "High request rate", "ip,time", "at least 600 requests"},
		{"WB-burst", "Leaky bucket burst", "ip,time", "capacity 300; leak 1 request/second; ordered input required"},
		{"WB-paths", "Diverse URL probing with errors", "ip,time,target,status", "at least 40 paths and 10 HTTP 401/403/404 observations"},
		{"WB-sensitive", "Distinct sensitive resource probes", "ip,time,target", "at least 5 distinct sensitive paths"},
		{"WB-ua", "User-Agent rotation during probing", "ip,time,target,status,user_agent", "at least 5 UAs, 10 paths and 10 HTTP 401/403/404 observations"},
		{"WB-multi", "Multiple techniques in one window", "ip,time,target", "at least 2 signature categories and 8 observations; no verified attack progression"},
		{"WS-ip", "IP request/byte volume outlier", "ip,time", "at least 20 peers; median/MAD with effect floors +100 and 5x requests, or +1MiB and 10x bytes"},
		{"WS-errors", "IP HTTP-error-rate outlier", "ip,time,status", "at least 20 peers with 20 known-status requests each; +0.5 rate and 3x effect floors"},
		{"WS-url-size", "Same URL/status response-size outlier", "ip,time,target,status,bytes", "at least 20 prior samples; +4096 bytes and 5x median; robust MAD; ring of 128"},
		{"WS-size", "Response-size outlier", "ip,time,status,bytes", "at least 20 prior samples; +1MiB and 10x median; robust MAD; ring of 128"},
		{"WS-hour", "Hourly traffic outlier", "ip,time", "at least 20 hourly bins including observed-span zeros; +100 requests and 5x median; bounded span"},
	}
	for _, r := range behavior {
		condition := r.condition
		if strings.HasPrefix(r.id, "WB-") {
			condition += "; two overlapping five-minute partitions offset by 150s; diversity capped at 64"
		}
		out = append(out, AnalysisRule{ID: r.id, Engine: "webaudit", Kind: "aggregate", Category: r.id, Description: r.desc, Required: strings.Split(r.required, ","), Condition: condition, Supported: true, Enabled: true})
	}
	for _, r := range sourceRules {
		required := []string{"ip", "time", "target"}
		for field, token := range map[string]string{"status": "http_status", "method": "http_verb", "user_agent": "http_user_agent", "protocol": "http_version", "referer": "http_referer", "host": "target_fqdn"} {
			if strings.Contains(r.Filter+" "+r.Group+" "+r.Distinct, token) {
				required = append(required, field)
			}
		}
		sort.Strings(required)
		condition := fmt.Sprintf("%s; capacity=%d; cache_size=%d; leakspeed=%s; blackhole=%s; groupby=%s; distinct=%s", r.Filter, r.Capacity, r.CacheSize, r.Leak, r.Blackhole, r.Group, r.Distinct)
		out = append(out, AnalysisRule{ID: r.ID, Engine: "hub", Kind: r.Type, Description: r.Description, Required: required, Condition: condition, Supported: r.Supported, Enabled: r.Supported})
	}
	for _, r := range auraSource.Signatures {
		out = append(out, AnalysisRule{ID: r.ID, Engine: "aura", Kind: "signature", Category: r.ID, Description: r.Description, Required: []string{"target"}, Condition: r.Pattern, Supported: true, Enabled: true})
	}
	out = append(out, AnalysisRule{ID: "scanner_ua", Engine: "aura", Kind: "signature", Description: "Source scanner User-Agent match", Required: []string{"user_agent"}, Condition: strings.Join(auraSource.ScannerUAs, " | "), Supported: true, Enabled: true}, AnalysisRule{ID: "dangerous_method", Engine: "aura", Kind: "signature", Description: "Source dangerous HTTP method", Required: []string{"method"}, Condition: strings.Join(auraSource.Methods, " | "), Supported: true, Enabled: true})
	for _, r := range []struct{ id, fields, condition string }{{"brute_force", "ip,time,status", "at least 20 HTTP 401/403 requests in one fixed five-minute interval; case-wide auth count"}, {"enumeration_404", "ip,time,status", "at least 50 HTTP 404 observations per peer, case-wide"}, {"exfil_bytes", "ip,time,bytes", "at least 5 peers; bytes above mean+3SD and above 10MiB; not proof of exfiltration"}, {"rare_user_agent", "time,user_agent", "case-wide UA count at most 5; bottom 25 UAs; excludes empty and '-'"}, {"traffic_spike", "time", "at least 6-hour observed span; hourly z-score greater than 3; includes bounded zero-hour baseline"}} {
		out = append(out, AnalysisRule{ID: r.id, Engine: "aura-analysis", Kind: "aggregate", Description: r.id, Required: strings.Split(r.fields, ","), Condition: r.condition, Supported: true, Enabled: true})
	}
	out = append(out, AnalysisRule{ID: "geoip-similarity", Engine: "geoip", Kind: "context", Description: "Multi-IP similarity within one ASN", Required: []string{"ip", "time", "target"}, Condition: "known shared ASN + path + host when known + category + fixed five-minute UTC interval; contextual hint only", Supported: true, Enabled: true})
	sort.Slice(out, func(i, j int) bool {
		if out[i].Engine != out[j].Engine {
			return out[i].Engine < out[j].Engine
		}
		return out[i].ID < out[j].ID
	})
	return out
}
func ruleKey(engine, id string) string { return engine + "|" + id }
func requestEligible(e Event, fields []string) bool {
	for _, field := range fields {
		ok := true
		switch field {
		case "ip":
			ok = e.IP != ""
		case "time":
			ok = !e.TimezoneUnknown
		case "target":
			ok = e.Target != ""
		case "method":
			ok = e.Method != nil
		case "protocol":
			ok = e.Protocol != nil
		case "status":
			ok = e.Status != nil
		case "bytes":
			ok = e.Bytes != nil
		case "user_agent":
			ok = e.UA != nil
		case "referer":
			ok = e.Referer != nil
		case "host":
			ok = e.Host != nil
		}
		if !ok {
			return false
		}
	}
	return true
}
func (c *bundleCapture) ruleHit(engine, id string) {
	if c == nil {
		return
	}
	key := ruleKey(engine, id)
	if c.observations == nil {
		c.observations = map[string]*ruleObservation{}
	}
	if c.observations[key] == nil {
		c.observations[key] = &ruleObservation{}
	}
	c.observations[key].matched++
	c.observations[key].detections++
}
func (c *bundleCapture) observeDetection(e Event, hits []Rule, n Normalized) {
	if c == nil {
		return
	}
	if c.observations == nil {
		c.observations = map[string]*ruleObservation{}
	}
	if c.aspectObservations == nil {
		c.aspectObservations = map[string]*ruleObservation{}
	}
	matched := map[string]bool{}
	for _, h := range hits {
		c.ruleHit("webaudit", h.ID)
		matched[h.ID] = true
	}
	eligible := map[string]bool{}
	for _, rule := range c.rules {
		if !rule.Supported {
			continue
		}
		key := ruleKey(rule.Engine, rule.ID)
		if c.observations[key] == nil {
			c.observations[key] = &ruleObservation{}
		}
		if requestEligible(e, rule.Required) {
			c.observations[key].eligible++
			if rule.Engine == "webaudit" {
				eligible[rule.ID] = true
			}
		}
	}
	for _, aspect := range bundleAspects() {
		key := aspect.ID
		if c.aspectObservations[key] == nil {
			c.aspectObservations[key] = &ruleObservation{}
		}
		applicable, hit := false, false
		detectionCount := int64(0)
		for _, id := range aspect.Rules {
			applicable = applicable || eligible[id]
			hit = hit || matched[id]
			if matched[id] {
				detectionCount++
			}
		}
		if applicable {
			c.aspectObservations[key].eligible++
		}
		if hit {
			c.aspectObservations[key].matched++
			c.aspectObservations[key].detections += detectionCount
		}
	}
}
func (c *bundleCapture) observeSignals(a *Analysis, signals []Signal) {
	if c == nil {
		return
	}
	c.signals = append([]Signal(nil), signals...)
	c.ready = map[string]bool{"WS-ip": len(a.ips) >= 20, "WS-errors": false, "WS-size": len(a.global.values) > 20, "WS-url-size": false, "WS-hour": false}
	peers := 0
	for _, p := range a.ips {
		if p.statusN >= 20 {
			peers++
		}
	}
	c.ready["WS-errors"] = peers >= 20
	for _, b := range a.urls {
		if len(b.values) > 20 {
			c.ready["WS-url-size"] = true
		}
	}
	var first, last int64
	seenHour := false
	for h := range a.hours {
		if !seenHour || h < first {
			first = h
		}
		if !seenHour || h > last {
			last = h
		}
		seenHour = true
	}
	c.ready["WS-hour"] = len(a.hours) > 0 && last-first >= 19 && last-first < int64(a.o.MaxKeys)
}
func coverageStatus(row *CoverageRow, supported bool, partial bool, ready bool) {
	row.CountQuality = "exact"
	row.Complete = supported && !partial && ready
	if !supported {
		row.Status = "unsupported"
		row.Evaluation = "not_supported"
		row.Complete = false
		row.EligibleRequests = nil
		row.DetectedRequests = nil
		row.Detections = nil
		row.CountQuality = "unavailable"
		return
	}
	if !ready || row.EligibleRequests == nil || *row.EligibleRequests == 0 {
		row.Status = "unable"
		row.Evaluation = "unable"
		row.Complete = false
		row.CountQuality = "unavailable"
		return
	}
	if partial {
		row.Status = "partial"
		row.Evaluation = "partial"
		row.Complete = false
		row.CountQuality = "lower_bound"
		return
	}
	row.Evaluation = "evaluated"
	if row.HasDetections {
		row.Status = "detected"
	} else {
		row.Status = "no_detection"
	}
}
func buildCoverage(r *InvestigationReport, c *bundleCapture) {
	r.AnalysisRules = c.rules
	detections := map[string]int64{}
	for _, s := range c.signals {
		detections[ruleKey("webaudit", s.Rule.ID)]++
	}
	for _, pair := range []struct {
		engine string
		alerts []SourceAlert
	}{{"hub", r.Analysis.UpstreamAlerts}, {"aura", r.Analysis.AuraMatches}, {"aura-analysis", r.Analysis.AuraAnalysis}} {
		for _, a := range pair.alerts {
			detections[ruleKey(pair.engine, a.RuleID)]++
		}
	}
	if r.Analysis.GeoIP != nil {
		detections[ruleKey("geoip", "geoip-similarity")] = int64(len(r.Analysis.GeoIP.Correlations))
	}
	ruleRows := map[string]CoverageRow{}
	for _, rule := range c.rules {
		key := ruleKey(rule.Engine, rule.ID)
		ob := c.observations[key]
		if ob == nil {
			ob = &ruleObservation{}
		}
		count := detections[key]
		var requestCount *int64
		if rule.Kind == "signature" && rule.Engine == "webaudit" {
			count = ob.matched
			requestCount = ptr(ob.matched)
		}
		row := CoverageRow{ID: "RULE-" + rule.Engine + "-" + rule.ID, Name: rule.Description, Description: rule.Description, RuleIDs: []string{rule.ID}, Engines: []string{rule.Engine}, EligibleRequests: ptr(ob.eligible), DetectedRequests: requestCount, Detections: ptr(count), MatchedCandidates: ptr(ob.matched), HasDetections: count > 0, Conditions: []string{rule.Condition}}
		for _, f := range r.Analysis.Findings {
			for _, h := range f.Rules {
				if rule.Engine == "webaudit" && h.ID == rule.ID {
					uniqueAppend(&row.FindingIDs, f.ID)
				}
			}
		}
		ready := true
		if known, ok := c.ready[rule.ID]; ok {
			ready = known
			if !ready {
				row.Limitations = append(row.Limitations, "Insufficient baseline observations or peers for statistical evaluation")
			}
		}
		partial := !r.Complete || ob.eligible < r.Analysis.Parsed-r.Analysis.Duplicates
		if rule.Engine == "geoip" && r.Analysis.GeoIP != nil {
			partial = partial || r.Analysis.GeoIP.Truncated || r.Analysis.GeoIP.CorrelationsTruncated
		}
		if rule.Engine == "geoip" && r.Analysis.GeoIP == nil {
			row.Status = "not_performed"
			row.Evaluation = "not_performed"
			row.CountQuality = "unavailable"
			row.EligibleRequests = nil
			row.Detections = nil
			row.Limitations = append(row.Limitations, "GeoIP database not configured")
		} else {
			coverageStatus(&row, rule.Supported, partial, ready)
		}
		if ob.eligible < r.Analysis.Parsed-r.Analysis.Duplicates {
			row.Limitations = append(row.Limitations, "Some observations lack required fields or a known timezone")
		}
		if requestCount == nil {
			row.Limitations = append(row.Limitations, "Distinct detected request count is unavailable until full evidence association; matched_candidates are filter/signature candidates, not confirmed attacks")
		}
		r.Coverage = append(r.Coverage, row)
		ruleRows[key] = row
	}
	for _, aspect := range bundleAspects() {
		ob := c.aspectObservations[aspect.ID]
		if ob == nil {
			ob = &ruleObservation{}
		}
		row := CoverageRow{ID: "ASPECT-" + aspect.ID, Name: aspect.Name, Description: aspect.Name, RuleIDs: aspect.Rules, Engines: []string{"webaudit"}, EligibleRequests: ptr(ob.eligible), DetectedRequests: ptr(ob.matched), Detections: ptr(ob.detections), HasDetections: ob.matched > 0}
		partial := !r.Complete || aspect.Partial || ob.eligible < r.Analysis.Parsed-r.Analysis.Duplicates
		supported := len(aspect.Rules) > 0
		ready := true
		for _, id := range aspect.Rules {
			engine := "webaudit"
			if id == "geoip-similarity" {
				engine = "geoip"
			}
			rr := ruleRows[ruleKey(engine, id)]
			row.HasDetections = row.HasDetections || rr.HasDetections
			for _, f := range rr.FindingIDs {
				uniqueAppend(&row.FindingIDs, f)
			}
			row.Conditions = append(row.Conditions, rr.Conditions...)
			if strings.HasPrefix(id, "WB-") || strings.HasPrefix(id, "WS-") || id == "geoip-similarity" {
				row.DetectedRequests = nil
				row.Detections = nil
				partial = true
				row.EligibleRequests = rr.EligibleRequests
				if rr.Evaluation == "unable" {
					ready = false
				}
			}
		}
		if aspect.Partial {
			row.Limitations = append(row.Limitations, "Related or shared rules cover only part of this perspective; separate labels do not imply independent detections")
		}
		coverageStatus(&row, supported, partial, ready)
		if aspect.ID == "multi_ip" && r.Analysis.GeoIP == nil {
			row.Status = "not_performed"
			row.Evaluation = "not_performed"
			row.EligibleRequests = nil
			row.DetectedRequests = nil
			row.Detections = nil
			row.Complete = false
			row.CountQuality = "unavailable"
		}
		r.Coverage = append(r.Coverage, row)
	}
	sort.Slice(r.Coverage, func(i, j int) bool { return r.Coverage[i].ID < r.Coverage[j].ID })
}
func writeCoverage(b *bundleWriter, r *InvestigationReport) error {
	if err := b.csv("analysis-rules.csv", []string{"rule_id", "engine", "kind", "category", "description", "supported", "enabled", "required_fields", "conditions"}, func(write func(...string) error) error {
		for _, rule := range r.AnalysisRules {
			if err := write(rule.ID, rule.Engine, rule.Kind, rule.Category, rule.Description, strconv.FormatBool(rule.Supported), strconv.FormatBool(rule.Enabled), strings.Join(rule.Required, ";"), rule.Condition); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	number := func(v *int64) string {
		if v == nil {
			return ""
		}
		return strconv.FormatInt(*v, 10)
	}
	return b.csv("analysis-coverage.csv", []string{"coverage_id", "name", "description", "rule_ids", "engines", "status", "evaluation", "complete", "has_detections", "eligible_requests", "detected_requests", "detections", "matched_candidates", "finding_ids", "conditions", "limitations", "count_quality"}, func(write func(...string) error) error {
		for _, row := range r.Coverage {
			if err := write(row.ID, row.Name, row.Description, strings.Join(row.RuleIDs, ";"), strings.Join(row.Engines, ";"), row.Status, row.Evaluation, strconv.FormatBool(row.Complete), strconv.FormatBool(row.HasDetections), number(row.EligibleRequests), number(row.DetectedRequests), number(row.Detections), number(row.MatchedCandidates), strings.Join(row.FindingIDs, ";"), strings.Join(row.Conditions, ";"), strings.Join(row.Limitations, ";"), row.CountQuality); err != nil {
				return err
			}
		}
		return nil
	})
}

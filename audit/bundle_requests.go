package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type RequestHit struct {
	RuleID    string `json:"rule_id"`
	Category  string `json:"category"`
	Severity  string `json:"severity"`
	Reason    string `json:"reason"`
	FindingID string `json:"finding_id"`
}
type RequestSnapshot struct {
	ID               string       `json:"request_id"`
	FileID           string       `json:"source_file_id"`
	Event            Event        `json:"event"`
	Normalization    Normalized   `json:"normalization"`
	Hits             []RequestHit `json:"hits"`
	SourceDetections []string     `json:"source_detections"`
	GeoIP            *GeoIPInfo   `json:"geoip"`
}
type BundleDetection struct {
	ID                  string     `json:"id"`
	Engine              string     `json:"engine"`
	RuleID              string     `json:"rule_id"`
	Kind                string     `json:"kind"`
	Category            string     `json:"category"`
	Severity            string     `json:"severity"`
	DetectionConfidence string     `json:"detection_confidence"`
	Reason              string     `json:"reason"`
	Condition           string     `json:"condition"`
	First               *time.Time `json:"first"`
	Last                *time.Time `json:"last"`
	IP                  string     `json:"source_ip"`
	Host                *string    `json:"host"`
	FindingIDs          []string   `json:"finding_ids"`
	RequestCount        int64      `json:"request_count"`
	RelatedRequestCount int64      `json:"related_request_count"`
	CountQuality        string     `json:"count_quality"`
	signal              *Signal
	source              *SourceAlert
}
type FindingObservation struct {
	ID              string           `json:"finding_id"`
	DirectRequests  int64            `json:"direct_requests"`
	RelatedRequests int64            `json:"related_requests"`
	StatusCounts    map[string]int64 `json:"status_counts"`
	Methods         map[string]int64 `json:"methods"`
	URIs            []string         `json:"uri_samples"`
	URIsTruncated   bool             `json:"uri_samples_truncated"`
	BytesCount      int64            `json:"bytes_count"`
	BytesSum        float64          `json:"bytes_sum"`
	BytesMin        *int64           `json:"bytes_min"`
	BytesMax        *int64           `json:"bytes_max"`
}
type EvidenceSummary struct {
	SuspiciousRequests  int64    `json:"suspicious_requests"`
	RelatedRequests     int64    `json:"related_requests"`
	DirectDetections    int64    `json:"signature_detections"`
	AggregateDetections int64    `json:"aggregate_detections"`
	SpoolBytes          int64    `json:"spool_bytes"`
	Reasons             []string `json:"incomplete_reasons"`
}

type requestSpool struct {
	file        *os.File
	path        string
	limit, used int64
	truncated   bool
	err         error
}

func newRequestSpool(dir string, limit int64) (*requestSpool, error) {
	f, err := os.CreateTemp(dir, ".requests-")
	if err != nil {
		return nil, err
	}
	return &requestSpool{file: f, path: f.Name(), limit: limit}, nil
}
func (s *requestSpool) write(r RequestSnapshot) {
	if s == nil || s.truncated || s.err != nil {
		return
	}
	data, err := json.Marshal(r)
	if err != nil {
		s.err = err
		return
	}
	if int64(len(data)+1) > s.limit-s.used {
		s.truncated = true
		return
	}
	data = append(data, '\n')
	n, err := s.file.Write(data)
	s.used += int64(n)
	s.err = err
}
func (s *requestSpool) close() error {
	if s == nil {
		return nil
	}
	if s.file != nil {
		err := s.file.Close()
		s.file = nil
		if s.err == nil {
			s.err = err
		}
	}
	return s.err
}
func (s *requestSpool) remove() {
	if s == nil {
		return
	}
	_ = s.close()
	_ = os.Remove(s.path)
}
func (s *requestSpool) scan(consume func(RequestSnapshot) error) error {
	if err := s.close(); err != nil {
		return err
	}
	f, err := os.Open(s.path)
	if err != nil {
		return err
	}
	defer f.Close()
	d := json.NewDecoder(bufio.NewReader(f))
	for {
		var r RequestSnapshot
		err := d.Decode(&r)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err = consume(r); err != nil {
			return err
		}
	}
}
func (c *bundleCapture) requestID(e Event) string {
	return bundleID("REQ-", c.inputs[e.File].ID+"\x00"+strconv.FormatInt(e.Line, 10))
}
func (c *bundleCapture) candidate(id string) {
	if c != nil {
		uniqueAppend(&c.pendingSources, id)
	}
}
func (c *bundleCapture) writeRequest(e Event, hits []Rule, n Normalized, correlator *Correlator) {
	if c == nil || c.spool == nil {
		return
	}
	r := RequestSnapshot{ID: c.requestID(e), FileID: c.inputs[e.File].ID, Event: e, Normalization: n, SourceDetections: append([]string(nil), c.pendingSources...)}
	for _, h := range hits {
		hit := RequestHit{RuleID: h.ID, Category: h.Category, Severity: h.Severity, Reason: h.Description}
		if f := correlator.items[incidentKey(e, family(h))]; f != nil {
			hit.FindingID = f.ID
		}
		r.Hits = append(r.Hits, hit)
	}
	if c.o.GeoIP != nil {
		g := c.o.GeoIP.Lookup(e.IP)
		r.GeoIP = &g
	}
	c.spool.write(r)
}
func (c *bundleCapture) bucketID(key string, e Event) string {
	if c == nil {
		return ""
	}
	return bundleID("DET-", "hub\x00"+key+"\x00"+c.requestID(e))
}
func (c *bundleCapture) sourceID(source, key string) string {
	if c == nil {
		return ""
	}
	return bundleID("DET-", source+"\x00"+key)
}
func sourceDetectionID(a SourceAlert, index int) string {
	if a.ID != "" {
		return a.ID
	}
	return bundleID("DET-", fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%d", a.Source, a.RuleID, a.IP, a.Group, bundleTime(a.First), a.bundleMatchKey, index))
}
func bundleDetections(r *InvestigationReport, c *bundleCapture) []BundleDetection {
	var out []BundleDetection
	for i, s := range c.signals {
		copySignal := s
		d := BundleDetection{ID: bundleID("DET-", fmt.Sprintf("webaudit\x00%s\x00%d\x00%s\x00%s", s.Rule.ID, i, s.Start.Format(time.RFC3339Nano), s.End.Format(time.RFC3339Nano))), Engine: "webaudit", RuleID: s.Rule.ID, Kind: "related", Category: s.Rule.Category, Severity: s.Rule.Severity, DetectionConfidence: "unknown", Reason: s.Reason, First: ptr(s.Start), Last: ptr(s.End), IP: s.Event.IP, Host: s.Event.Host, signal: &copySignal, CountQuality: r.CountQuality}
		if s.Rule.ID == "WS-size" || s.Rule.ID == "WS-url-size" {
			d.Kind = "direct"
		}
		for _, f := range r.Analysis.Findings {
			if f.ID == incidentID(s.Event, family(s.Rule)) {
				d.FindingIDs = []string{f.ID}
				break
			}
		}
		for _, rule := range c.rules {
			if rule.Engine == "webaudit" && rule.ID == d.RuleID {
				d.Condition = rule.Condition
				break
			}
		}
		out = append(out, d)
	}
	for _, set := range []struct {
		engine string
		alerts []SourceAlert
	}{{"hub", r.Analysis.UpstreamAlerts}, {"aura", r.Analysis.AuraMatches}, {"aura-analysis", r.Analysis.AuraAnalysis}} {
		for i, a := range set.alerts {
			copyAlert := a
			d := BundleDetection{ID: sourceDetectionID(a, i), Engine: set.engine, RuleID: a.RuleID, Kind: "direct", Severity: "unknown", DetectionConfidence: "unknown", Reason: a.RuleID, First: a.First, Last: a.Last, IP: a.IP, source: &copyAlert, CountQuality: r.CountQuality}
			if set.engine == "aura-analysis" {
				d.Kind = "related"
			}
			for _, rule := range c.rules {
				if rule.Engine == d.Engine && rule.ID == d.RuleID {
					d.Condition = rule.Condition
					d.Category = rule.Category
					d.Reason = rule.Description
					break
				}
			}
			out = append(out, d)
		}
	}
	return out
}
func detectionRelated(d *BundleDetection, r RequestSnapshot) bool {
	e := r.Event
	if d.signal != nil {
		s := d.signal
		if e.TimezoneUnknown || e.Time.Before(s.Start) || e.Time.After(s.End) {
			return false
		}
		if d.RuleID == "WS-hour" {
			return e.Time.Unix()/3600 == s.Event.Time.Unix()/3600
		}
		return e.IP == s.Event.IP && val(e.Host) == val(s.Event.Host)
	}
	if d.source == nil || e.TimezoneUnknown || e.LogType != "http_access-log" {
		return false
	}
	a := d.source
	switch a.RuleID {
	case "brute_force":
		return e.IP == a.IP && (val(e.Status) == 401 || val(e.Status) == 403)
	case "enumeration_404":
		return e.IP == a.IP && val(e.Status) == 404
	case "exfil_bytes":
		return e.IP == a.IP
	case "rare_user_agent":
		return digest(sourceUA(e)) == a.bundleMatchKey
	case "traffic_spike":
		return a.First != nil && e.Time.Truncate(time.Hour).Equal(a.First.Truncate(time.Hour))
	}
	return false
}

var requestHeaders = []string{"request_id", "finding_ids", "detection_ids", "timestamp", "source_ip", "country_code", "asn", "as_organization", "host", "method", "protocol", "request_uri", "normalized_uri", "status_code", "response_bytes", "request_duration", "referer", "user_agent", "attack_categories", "rule_ids", "detection_engines", "severity", "detection_confidence", "detection_reason", "source_file_id", "source_file", "source_line", "relation", "direct_detection_ids", "related_detection_ids", "normalization_steps", "raw_log", "count_quality"}

func requestCSV(r RequestSnapshot, direct, related []*BundleDetection, quality string) []string {
	var findingIDs, ids, ruleIDs, categories, engines, reasons, directIDs, relatedIDs []string
	severity := "unknown"
	all := append(append([]*BundleDetection(nil), direct...), related...)
	for _, d := range all {
		uniqueAppend(&ids, d.ID)
		uniqueAppend(&ruleIDs, d.RuleID)
		uniqueAppend(&engines, d.Engine)
		if d.Category != "" {
			uniqueAppend(&categories, d.Category)
		}
		uniqueAppend(&reasons, d.Reason)
		for _, id := range d.FindingIDs {
			uniqueAppend(&findingIDs, id)
		}
		if severity == "unknown" || weight(d.Severity) > weight(severity) {
			severity = d.Severity
		}
	}
	for _, d := range direct {
		directIDs = append(directIDs, d.ID)
	}
	for _, d := range related {
		relatedIDs = append(relatedIDs, d.ID)
	}
	country, asn, org := "", "", ""
	if r.GeoIP != nil {
		country = val(r.GeoIP.CountryCode)
		org = val(r.GeoIP.ASNOrganization)
		if r.GeoIP.ASN != nil {
			asn = strconv.FormatUint(uint64(*r.GeoIP.ASN), 10)
		}
	}
	status, size := "", ""
	if r.Event.Status != nil {
		status = strconv.Itoa(*r.Event.Status)
	}
	if r.Event.Bytes != nil {
		size = strconv.FormatInt(*r.Event.Bytes, 10)
	}
	timestamp := ""
	if !r.Event.TimezoneUnknown {
		timestamp = r.Event.Time.Format(time.RFC3339Nano)
	}
	normalized := r.Event.Target
	if len(r.Normalization.Variants) > 0 {
		normalized = r.Normalization.Variants[len(r.Normalization.Variants)-1]
	}
	relation := "related"
	if len(direct) > 0 {
		relation = "direct"
		if len(related) > 0 {
			relation = "direct_and_related"
		}
	}
	return []string{r.ID, strings.Join(findingIDs, ";"), strings.Join(ids, ";"), timestamp, r.Event.IP, country, asn, org, val(r.Event.Host), val(r.Event.Method), val(r.Event.Protocol), r.Event.Target, normalized, status, size, "", val(r.Event.Referer), val(r.Event.UA), strings.Join(categories, ";"), strings.Join(ruleIDs, ";"), strings.Join(engines, ";"), severity, "unknown", strings.Join(reasons, ";"), r.FileID, r.Event.File, strconv.FormatInt(r.Event.Line, 10), relation, strings.Join(directIDs, ";"), strings.Join(relatedIDs, ";"), strings.Join(r.Normalization.Steps, ";"), r.Event.Raw, quality}
}
func directRequestDetections(r RequestSnapshot) []BundleDetection {
	out := make([]BundleDetection, 0, len(r.Hits))
	for _, h := range r.Hits {
		d := BundleDetection{ID: bundleID("DET-", "webaudit\x00"+h.RuleID+"\x00"+r.ID), Engine: "webaudit", RuleID: h.RuleID, Kind: "direct", Category: h.Category, Severity: h.Severity, DetectionConfidence: "unknown", Reason: h.Reason, IP: r.Event.IP, Host: r.Event.Host, RequestCount: 1, CountQuality: "exact"}
		if !r.Event.TimezoneUnknown {
			d.First = ptr(r.Event.Time)
			d.Last = ptr(r.Event.Time)
		}
		if h.FindingID != "" {
			d.FindingIDs = []string{h.FindingID}
		}
		out = append(out, d)
	}
	return out
}

type detectionInterval struct {
	index              int
	start, end, maxEnd int64
	left, right        *detectionInterval
}
type evidenceIndex struct {
	sources map[string]int
	points  map[string][]int
	scopes  map[string]*detectionInterval
}

func pointKey(file string, line int64) string {
	return digest(file + "\x00" + strconv.FormatInt(line, 10))
}
func hostScope(ip string, host *string) string { return "host:" + digest(ip+"\x00"+val(host)) }
func newEvidenceIndex(groups []BundleDetection) *evidenceIndex {
	index := &evidenceIndex{sources: map[string]int{}, points: map[string][]int{}, scopes: map[string]*detectionInterval{}}
	buckets := map[string][]*detectionInterval{}
	for i, d := range groups {
		if d.Engine == "hub" || d.Engine == "aura" {
			index.sources[d.ID] = i
			continue
		}
		if d.Kind == "direct" && d.signal != nil {
			key := pointKey(d.signal.Event.File, d.signal.Event.Line)
			index.points[key] = append(index.points[key], i)
			continue
		}
		scope := ""
		if d.signal != nil {
			scope = hostScope(d.signal.Event.IP, d.signal.Event.Host)
			if d.RuleID == "WS-hour" {
				scope = "ws-hour:" + strconv.FormatInt(d.signal.Event.Time.Unix()/3600, 10)
			}
		}
		if d.source != nil {
			a := d.source
			switch a.RuleID {
			case "rare_user_agent":
				scope = "ua:" + a.bundleMatchKey
			case "traffic_spike":
				if a.First != nil {
					scope = "aura-hour:" + strconv.FormatInt(a.First.Truncate(time.Hour).Unix(), 10)
				}
			default:
				scope = "ip:" + a.IP
			}
		}
		if scope == "" {
			continue
		}
		start, end := int64(math.MinInt64), int64(math.MaxInt64)
		if d.First != nil {
			start = d.First.Unix()
		}
		if d.Last != nil {
			end = d.Last.Unix()
		}
		buckets[scope] = append(buckets[scope], &detectionInterval{index: i, start: start, end: end, maxEnd: end})
	}
	var tree func([]*detectionInterval) *detectionInterval
	tree = func(nodes []*detectionInterval) *detectionInterval {
		if len(nodes) == 0 {
			return nil
		}
		mid := len(nodes) / 2
		n := nodes[mid]
		n.left = tree(nodes[:mid])
		n.right = tree(nodes[mid+1:])
		for _, child := range []*detectionInterval{n.left, n.right} {
			if child != nil && child.maxEnd > n.maxEnd {
				n.maxEnd = child.maxEnd
			}
		}
		return n
	}
	for scope, nodes := range buckets {
		sort.Slice(nodes, func(i, j int) bool {
			if nodes[i].start != nodes[j].start {
				return nodes[i].start < nodes[j].start
			}
			return nodes[i].index < nodes[j].index
		})
		index.scopes[scope] = tree(nodes)
	}
	return index
}
func (n *detectionInterval) query(second int64, visit func(int)) {
	if n == nil || n.maxEnd < second {
		return
	}
	n.left.query(second, visit)
	if n.start <= second {
		if n.end >= second {
			visit(n.index)
		}
		n.right.query(second, visit)
	}
}
func matchingDetections(r RequestSnapshot, groups []BundleDetection, index *evidenceIndex) ([]BundleDetection, []*BundleDetection, []*BundleDetection) {
	directValues := directRequestDetections(r)
	var direct, related []*BundleDetection
	for i := range directValues {
		direct = append(direct, &directValues[i])
	}
	for _, id := range r.SourceDetections {
		if i, ok := index.sources[id]; ok {
			direct = append(direct, &groups[i])
		}
	}
	for _, i := range index.points[pointKey(r.Event.File, r.Event.Line)] {
		direct = append(direct, &groups[i])
	}
	seen := map[int]bool{}
	visit := func(i int) {
		if seen[i] {
			return
		}
		seen[i] = true
		d := &groups[i]
		if detectionRelated(d, r) {
			related = append(related, d)
		}
	}
	if !r.Event.TimezoneUnknown {
		for _, scope := range []string{hostScope(r.Event.IP, r.Event.Host), "ip:" + r.Event.IP, "ua:" + digest(sourceUA(r.Event)), "ws-hour:" + strconv.FormatInt(r.Event.Time.Unix()/3600, 10), "aura-hour:" + strconv.FormatInt(r.Event.Time.Truncate(time.Hour).Unix(), 10)} {
			index.scopes[scope].query(r.Event.Time.Unix(), visit)
		}
	}
	return directValues, direct, related
}
func writeDetectionRow(write func(...string) error, d BundleDetection) error {
	return write(d.ID, d.Engine, d.RuleID, d.Kind, d.Category, d.Severity, d.DetectionConfidence, d.Reason, d.Condition, bundleTime(d.First), bundleTime(d.Last), d.IP, val(d.Host), strings.Join(d.FindingIDs, ";"), strconv.FormatInt(d.RequestCount, 10), strconv.FormatInt(d.RelatedRequestCount, 10), d.CountQuality)
}
func exportRequestEvidence(b *bundleWriter, r *InvestigationReport, c *bundleCapture) error {
	if err := c.spool.close(); err != nil {
		return err
	}
	r.EvidenceComplete = r.Complete && !c.spool.truncated
	for _, signal := range c.signals {
		if signal.Event.EvidenceTruncated {
			r.EvidenceComplete = false
			uniqueAppend(&r.Evidence.Reasons, "Delayed-detection source fields were compacted; complete association cannot be guaranteed")
		}
	}

	r.Evidence.SpoolBytes = c.spool.used
	if c.spool.truncated {
		r.Evidence.Reasons = append(r.Evidence.Reasons, "Private request spool byte limit reached; full request export is incomplete")
	}
	if !r.Complete {
		r.Evidence.Reasons = append(r.Evidence.Reasons, "Analysis or original-file provenance is incomplete")
	}
	if !r.EvidenceComplete {
		r.Complete = false
		r.Status = "partial"
		r.CountQuality = "lower_bound"
		r.Analysis.Partial = true
		for _, reason := range r.Evidence.Reasons {
			r.Analysis.warn(reason)
		}
	}
	groups := bundleDetections(r, c)
	index := newEvidenceIndex(groups)
	metrics := map[string]*FindingObservation{}
	for _, f := range r.Analysis.Findings {
		metrics[f.ID] = &FindingObservation{ID: f.ID, StatusCounts: map[string]int64{}, Methods: map[string]int64{}}
	}
	coverageCounts := map[string]int64{}
	coverageRelated := map[string]int64{}
	// First pass produces suspicious observations and exact bounded group/finding counters.
	err := b.csv("suspicious-requests.csv", requestHeaders, func(write func(...string) error) error {
		return c.spool.scan(func(snapshot RequestSnapshot) error {
			_, direct, related := matchingDetections(snapshot, groups, index)
			if len(direct) > 0 {
				r.Evidence.SuspiciousRequests++
				if err := write(requestCSV(snapshot, direct, related, r.CountQuality)...); err != nil {
					return err
				}
			}
			if len(related) > 0 {
				r.Evidence.RelatedRequests++
			}
			seenRules := map[string]bool{}
			seenRelatedRules := map[string]bool{}
			seenFindings := map[string]int{}
			for _, set := range []struct {
				rows []*BundleDetection
				flag int
			}{{direct, 1}, {related, 2}} {
				for _, d := range set.rows {
					if set.flag == 1 {
						d.RequestCount++
						if strings.HasPrefix(d.ID, "DET-") && d.Engine == "webaudit" && d.signal == nil {
							r.Evidence.DirectDetections++
						}
					} else {
						d.RelatedRequestCount++
					}
					key := ruleKey(d.Engine, d.RuleID)
					if set.flag == 1 && !seenRules[key] {
						coverageCounts[key]++
						seenRules[key] = true
					}
					if set.flag == 2 && !seenRelatedRules[key] {
						coverageRelated[key]++
						seenRelatedRules[key] = true
					}
					for _, id := range d.FindingIDs {
						seenFindings[id] |= set.flag
					}
				}
			}
			for id, flags := range seenFindings {
				m := metrics[id]
				if m == nil {
					continue
				}
				if flags&1 != 0 {
					m.DirectRequests++
				}
				if flags&2 != 0 {
					m.RelatedRequests++
				}
				status := "unknown"
				if snapshot.Event.Status != nil {
					status = strconv.Itoa(*snapshot.Event.Status)
				}
				m.StatusCounts[status]++
				method := val(snapshot.Event.Method)
				if method == "" {
					method = "unknown"
				}
				method, methodCut := clipped(method, 128)
				if len(m.Methods) >= 64 && m.Methods[method] == 0 {
					method = "(other)"
					m.URIsTruncated = true
				}
				if methodCut {
					m.URIsTruncated = true
				}
				m.Methods[method]++
				uri, uriCut := clipped(snapshot.Event.Target, 1024)
				if uriCut {
					m.URIsTruncated = true
				}
				knownURI := false
				for _, v := range m.URIs {
					if v == uri {
						knownURI = true
						break
					}
				}
				if !knownURI {
					if len(m.URIs) < 8 {
						m.URIs = append(m.URIs, uri)
					} else {
						m.URIsTruncated = true
					}
				}
				if snapshot.Event.Bytes != nil {
					v := *snapshot.Event.Bytes
					m.BytesCount++
					m.BytesSum += float64(v)
					if m.BytesMin == nil || v < *m.BytesMin {
						m.BytesMin = ptr(v)
					}
					if m.BytesMax == nil || v > *m.BytesMax {
						m.BytesMax = ptr(v)
					}
				}
			}
			return nil
		})
	})
	if err != nil {
		return err
	}
	// A related observation may also be directly detected; relation IDs make the overlap explicit.
	if err = b.csv("related-requests.csv", requestHeaders, func(write func(...string) error) error {
		return c.spool.scan(func(snapshot RequestSnapshot) error {
			_, direct, related := matchingDetections(snapshot, groups, index)
			if len(related) == 0 {
				return nil
			}
			return write(requestCSV(snapshot, direct, related, r.CountQuality)...)
		})
	}); err != nil {
		return err
	}
	if err = b.csv("detections.csv", []string{"detection_id", "engine", "rule_id", "relation", "category", "severity", "detection_confidence", "reason", "condition", "first", "last", "source_ip", "host", "finding_ids", "direct_request_count", "related_request_count", "count_quality"}, func(write func(...string) error) error {
		if err := c.spool.scan(func(snapshot RequestSnapshot) error {
			for _, d := range directRequestDetections(snapshot) {
				if err := writeDetectionRow(write, d); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
		for _, d := range groups {
			if err := writeDetectionRow(write, d); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	r.Detections = groups
	r.Evidence.AggregateDetections = int64(len(groups))
	for _, f := range r.Analysis.Findings {
		r.FindingObservations = append(r.FindingObservations, *metrics[f.ID])
	}
	for i := range r.Coverage {
		row := &r.Coverage[i]
		if strings.HasPrefix(row.ID, "RULE-") && len(row.Engines) == 1 && len(row.RuleIDs) == 1 && row.Status != "unsupported" && row.Engines[0] != "geoip" {
			count := coverageCounts[ruleKey(row.Engines[0], row.RuleIDs[0])]
			row.DetectedRequests = ptr(count)
			related := coverageRelated[ruleKey(row.Engines[0], row.RuleIDs[0])]
			row.RelatedRequests = ptr(related)
			row.Limitations = filterAssociationLimitation(row.Limitations)
			if !r.EvidenceComplete {
				row.CountQuality = "lower_bound"
				row.Complete = false
				if row.Status == "no_detection" || row.Status == "detected" {
					row.Status = "partial"
					row.Evaluation = "partial"
				}
			}
		}
	}
	return b.csv("findings.csv", []string{"finding_id", "source_ip", "host", "first", "last", "categories", "rule_ids", "direct_requests", "related_requests", "severity", "detection_confidence", "attack_score", "outcome", "outcome_confidence", "count_quality", "details_json"}, func(write func(...string) error) error {
		for _, f := range r.Analysis.Findings {
			m := metrics[f.ID]
			ids := []string{}
			for _, rule := range f.Rules {
				ids = append(ids, rule.ID)
			}
			details, err := json.Marshal(struct {
				Incident     Incident            `json:"incident"`
				Observations *FindingObservation `json:"observations"`
			}{f, m})
			if err != nil {
				return err
			}
			first, last := "", ""
			if !f.TimezoneUnknown {
				first = f.First.Format(time.RFC3339Nano)
				last = f.Last.Format(time.RFC3339Nano)
			}
			if err := write(f.ID, f.IP, val(f.Host), first, last, strings.Join(f.Categories, ";"), strings.Join(ids, ";"), strconv.FormatInt(m.DirectRequests, 10), strconv.FormatInt(m.RelatedRequests, 10), f.Severity, "unknown", strconv.Itoa(f.Score), f.Outcome.Verdict, strconv.FormatFloat(f.Outcome.Confidence, 'g', -1, 64), r.CountQuality, string(details)); err != nil {
				return err
			}
		}
		return nil
	})
}
func filterAssociationLimitation(in []string) []string {
	var out []string
	for _, s := range in {
		if !strings.HasPrefix(s, "Distinct detected request count is unavailable") {
			out = append(out, s)
		}
	}
	return out
}

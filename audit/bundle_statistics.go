package audit

import (
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type NumericSummary struct {
	Count      int64    `json:"count"`
	Missing    int64    `json:"missing"`
	Invalid    int64    `json:"invalid"`
	Sum        *float64 `json:"sum"`
	SumQuality string   `json:"sum_quality"`
	Min        *float64 `json:"min"`
	Max        *float64 `json:"max"`
	Mean       *float64 `json:"mean"`
	Unit       string   `json:"unit"`
}

func (n *NumericSummary) add(v *float64) {
	if v == nil {
		n.Missing++
		return
	}
	n.Count++
	if n.Count == 1 {
		n.Sum = ptr(*v)
		n.SumQuality = "finite"
	} else if n.Sum != nil {
		sum := *n.Sum + *v
		if math.IsInf(sum, 0) || math.IsNaN(sum) {
			n.Sum = nil
			n.SumQuality = "overflow"
		} else {
			n.Sum = &sum
		}
	}
	if n.Min == nil || *v < *n.Min {
		n.Min = ptr(*v)
	}
	if n.Max == nil || *v > *n.Max {
		n.Max = ptr(*v)
	}
	n.Mean = nil
	if n.Sum != nil {
		n.Mean = ptr(*n.Sum / float64(n.Count))
	}
}

type StatisticsRow struct {
	Key                string  `json:"key"`
	Value              *string `json:"value"`
	Name               *string `json:"name"`
	Organization       *string `json:"organization"`
	Requests           int64   `json:"requests"`
	SuspiciousRequests int64   `json:"suspicious_requests"`
	RequestPercent     float64 `json:"request_percent"`
	SuspiciousPercent  float64 `json:"suspicious_within_group_percent"`
	UniqueIPs          *int64  `json:"unique_ips"`
	UniqueIPQuality    string  `json:"unique_ip_quality"`
	Other              bool    `json:"other"`
	LabelTruncated     bool    `json:"label_truncated"`
	CountQuality       string  `json:"count_quality"`
}
type TimelineRow struct {
	Time               time.Time `json:"time"`
	Requests           int64     `json:"requests"`
	SuspiciousRequests int64     `json:"suspicious_requests"`
	Errors4xx          int64     `json:"errors_4xx"`
	Errors5xx          int64     `json:"errors_5xx"`
}
type RequestStatistics struct {
	Population                string                     `json:"population"`
	TotalRequests             int64                      `json:"total_requests"`
	UniqueIPs                 int64                      `json:"unique_ips"`
	UniqueIPQuality           string                     `json:"unique_ip_quality"`
	SuspiciousIPs             int64                      `json:"suspicious_ips"`
	SuspiciousCountQuality    string                     `json:"suspicious_count_quality"`
	SuspiciousPercent         *float64                   `json:"suspicious_percent"`
	Dimensions                map[string][]StatisticsRow `json:"dimensions"`
	Timeline                  []TimelineRow              `json:"timeline"`
	TimelineResolutionSeconds int64                      `json:"timeline_resolution_seconds"`
	UnknownTimeRequests       int64                      `json:"unknown_time_requests"`
	OmittedTimelineRequests   int64                      `json:"omitted_timeline_requests"`
	ResponseBytes             NumericSummary             `json:"response_bytes"`
	RequestDuration           NumericSummary             `json:"request_duration"`
	GeoIPEnabled              bool                       `json:"geoip_enabled"`
	GeoLookupStatuses         map[string]int64           `json:"geo_lookup_statuses"`
	AttackDetections          map[string]int64           `json:"attack_detections"`
	Truncated                 bool                       `json:"truncated"`
	Notes                     []string                   `json:"notes"`
}
type statisticsRecorder struct {
	max                                 int
	geo                                 bool
	total, unknownTime, omittedTimeline int64
	tables                              map[string]map[string]*StatisticsRow
	other                               map[string]*StatisticsRow
	bins                                map[int64]*TimelineRow
	resolution                          int64
	first, last                         *time.Time
	bytes, duration                     NumericSummary
	pairs                               map[string]bool
	geoStatuses                         map[string]int64
	truncated                           bool
}

func newStatisticsRecorder(max int, geo bool) *statisticsRecorder {
	return &statisticsRecorder{max: max, geo: geo, tables: map[string]map[string]*StatisticsRow{}, other: map[string]*StatisticsRow{}, bins: map[int64]*TimelineRow{}, resolution: 60, pairs: map[string]bool{}, geoStatuses: map[string]int64{}, bytes: NumericSummary{Unit: "bytes", SumQuality: "unavailable"}, duration: NumericSummary{Unit: "seconds", SumQuality: "unavailable"}}
}
func (s *statisticsRecorder) dimensions(r RequestSnapshot) map[string]*string {
	e := r.Event
	status, class := "", ""
	var statusP, classP *string
	if e.Status != nil {
		status = strconv.Itoa(*e.Status)
		class = strconv.Itoa(*e.Status/100) + "xx"
		statusP = &status
		classP = &class
	}
	out := map[string]*string{"method": e.Method, "protocol": e.Protocol, "status": statusP, "status_class": classP, "ip": ptr(e.IP), "host": e.Host, "uri": ptr(e.Path), "user_agent": e.UA, "log_type": ptr(e.LogType)}
	if s.geo {
		var country, asn *string
		if r.GeoIP != nil {
			country = r.GeoIP.CountryCode
			if r.GeoIP.ASN != nil {
				asn = ptr(strconv.FormatUint(uint64(*r.GeoIP.ASN), 10))
			}
		}
		out["country"] = country
		out["asn"] = asn
	}
	return out
}
func dimensionKey(value *string) string {
	if value == nil {
		return "missing"
	}
	return bundleID("VALUE-", *value)
}
func (s *statisticsRecorder) row(dim string, value *string, admit bool) *StatisticsRow {
	key := dimensionKey(value)
	table := s.tables[dim]
	if table == nil {
		if !admit {
			return s.other[dim]
		}
		table = map[string]*StatisticsRow{}
		s.tables[dim] = table
	}
	if row := table[key]; row != nil {
		return row
	}
	if !admit {
		return s.other[dim]
	}
	if len(table) >= s.max {
		s.truncated = true
		if s.other[dim] == nil {
			s.other[dim] = &StatisticsRow{Key: "other", Other: true, CountQuality: "exact", UniqueIPQuality: "unavailable"}
		}
		return s.other[dim]
	}
	row := &StatisticsRow{Key: key, CountQuality: "exact", UniqueIPQuality: "unavailable"}
	if value != nil {
		limit := 1024
		if dim == "user_agent" {
			limit = 512
		}
		if dim == "host" {
			limit = 255
		}
		if dim == "method" || dim == "protocol" {
			limit = 128
		}
		v, cut := clipped(*value, limit)
		row.Value = &v
		row.LabelTruncated = cut
		s.truncated = s.truncated || cut
	}
	if dim == "country" || dim == "asn" {
		row.UniqueIPs = ptr(int64(0))
		row.UniqueIPQuality = "exact"
	}
	table[key] = row
	return row
}
func floorBin(second, width int64) int64 {
	q := second / width
	if second < 0 && second%width != 0 {
		q--
	}
	key := q * width
	minimum := time.Date(0, time.January, 1, 0, 0, 0, 0, time.UTC).Unix()
	if key < minimum {
		return minimum
	}
	return key
}
func (s *statisticsRecorder) coarsen() {
	next := s.resolution * 10
	switch s.resolution {
	case 60:
		next = 3600
	case 3600:
		next = 86400
	case 86400:
		next = 604800
	case 604800:
		next = 2592000
	case 2592000:
		next = 31536000
	}
	bins := map[int64]*TimelineRow{}
	for _, row := range s.bins {
		key := floorBin(row.Time.Unix(), next)
		if bins[key] == nil {
			bins[key] = &TimelineRow{Time: time.Unix(key, 0).UTC()}
		}
		b := bins[key]
		b.Requests += row.Requests
		b.SuspiciousRequests += row.SuspiciousRequests
		b.Errors4xx += row.Errors4xx
		b.Errors5xx += row.Errors5xx
	}
	s.bins = bins
	s.resolution = next
}
func (s *statisticsRecorder) observe(r RequestSnapshot) {
	s.total++
	e := r.Event
	for dim, value := range s.dimensions(r) {
		row := s.row(dim, value, true)
		row.Requests++
		if s.geo && (dim == "country" || dim == "asn") && r.GeoIP != nil {
			pair := dim + "|" + row.Key + "|" + e.IP
			if !s.pairs[pair] {
				if len(s.pairs) < s.max {
					s.pairs[pair] = true
					if row.UniqueIPs != nil {
						*row.UniqueIPs++
					}
				} else {
					row.UniqueIPQuality = "lower_bound"
					s.truncated = true
				}
			}
			if dim == "country" && !row.Other {
				if r.GeoIP.CountryName != nil {
					name, cut := clipped(*r.GeoIP.CountryName, 255)
					row.Name = &name
					row.LabelTruncated = row.LabelTruncated || cut
					s.truncated = s.truncated || cut
				}
			}
			if dim == "asn" && !row.Other {
				if r.GeoIP.ASNOrganization != nil {
					org, cut := clipped(*r.GeoIP.ASNOrganization, 255)
					row.Organization = &org
					row.LabelTruncated = row.LabelTruncated || cut
					s.truncated = s.truncated || cut
				}
			}
		}
	}
	if s.geo && r.GeoIP != nil {
		s.geoStatuses["country:"+r.GeoIP.CountryStatus]++
		s.geoStatuses["asn:"+r.GeoIP.ASNStatus]++
	}
	if e.Bytes == nil {
		s.bytes.add(nil)
	} else {
		s.bytes.add(ptr(float64(*e.Bytes)))
	}
	s.duration.add(r.Duration)
	if r.InvalidDuration {
		s.duration.Invalid++
	}
	if e.TimezoneUnknown {
		s.unknownTime++
		return
	}
	if s.first == nil || e.Time.Before(*s.first) {
		s.first = ptr(e.Time)
	}
	if s.last == nil || e.Time.After(*s.last) {
		s.last = ptr(e.Time)
	}
	key := floorBin(e.Time.Unix(), s.resolution)
	for s.bins[key] == nil && len(s.bins) >= s.max && s.resolution < 1<<40 {
		s.coarsen()
		key = floorBin(e.Time.Unix(), s.resolution)
	}
	if s.bins[key] == nil {
		if len(s.bins) >= s.max {
			s.omittedTimeline++
			s.truncated = true
			return
		}
		s.bins[key] = &TimelineRow{Time: time.Unix(key, 0).UTC()}
	}
	row := s.bins[key]
	row.Requests++
	if e.Status != nil && *e.Status >= 400 && *e.Status < 500 {
		row.Errors4xx++
	}
	if e.Status != nil && *e.Status >= 500 && *e.Status < 600 {
		row.Errors5xx++
	}
}
func (s *statisticsRecorder) finalizeTimeline() {
	if s.first == nil || s.last == nil {
		return
	}
	span := s.last.Sub(*s.first)
	if span > 60*24*time.Hour {
		for s.resolution < 86400 {
			s.coarsen()
		}
	} else if span > 2*24*time.Hour {
		for s.resolution < 3600 {
			s.coarsen()
		}
	}
}
func (s *statisticsRecorder) suspicious(r RequestSnapshot) {
	if s == nil {
		return
	}
	for dim, value := range s.dimensions(r) {
		if row := s.row(dim, value, false); row != nil {
			row.SuspiciousRequests++
		}
	}
	if !r.Event.TimezoneUnknown {
		if row := s.bins[floorBin(r.Event.Time.Unix(), s.resolution)]; row != nil {
			row.SuspiciousRequests++
		}
	}
}
func (s *statisticsRecorder) model(r *InvestigationReport) RequestStatistics {
	out := RequestStatistics{Population: "successfully parsed, non-deduplicated source observations; source records are not verified unique network transactions", TotalRequests: s.total, UniqueIPQuality: "exact", SuspiciousCountQuality: "exact", Dimensions: map[string][]StatisticsRow{}, TimelineResolutionSeconds: s.resolution, UnknownTimeRequests: s.unknownTime, OmittedTimelineRequests: s.omittedTimeline, ResponseBytes: s.bytes, RequestDuration: s.duration, GeoIPEnabled: s.geo, GeoLookupStatuses: s.geoStatuses, AttackDetections: map[string]int64{}, Truncated: s.truncated, Notes: []string{"No observations in a time bin do not establish missing logs or downtime", "Response byte sums and means use floating-point arithmetic; rounding is possible", "Counts across perspectives, rules and engines overlap and must not be summed as unique requests"}}
	if !r.EvidenceComplete {
		out.SuspiciousCountQuality = "lower_bound"
	}
	if s.total > 0 {
		out.SuspiciousPercent = ptr(float64(r.Evidence.SuspiciousRequests) * 100 / float64(s.total))
	}
	for dim, table := range s.tables {
		for _, row := range table {
			copyRow := *row
			if s.total > 0 {
				copyRow.RequestPercent = float64(row.Requests) * 100 / float64(s.total)
			}
			if row.Requests > 0 {
				copyRow.SuspiciousPercent = float64(row.SuspiciousRequests) * 100 / float64(row.Requests)
			}
			out.Dimensions[dim] = append(out.Dimensions[dim], copyRow)
		}
		if row := s.other[dim]; row != nil {
			copyRow := *row
			if s.total > 0 {
				copyRow.RequestPercent = float64(row.Requests) * 100 / float64(s.total)
			}
			if row.Requests > 0 {
				copyRow.SuspiciousPercent = float64(row.SuspiciousRequests) * 100 / float64(row.Requests)
			}
			out.Dimensions[dim] = append(out.Dimensions[dim], copyRow)
		}
		sort.Slice(out.Dimensions[dim], func(i, j int) bool {
			a, b := out.Dimensions[dim][i], out.Dimensions[dim][j]
			if a.Requests != b.Requests {
				return a.Requests > b.Requests
			}
			return a.Key < b.Key
		})
	}
	for _, row := range out.Dimensions["ip"] {
		if !row.Other && row.Value != nil {
			out.UniqueIPs++
			if row.SuspiciousRequests > 0 {
				out.SuspiciousIPs++
			}
		}
		if row.Other {
			out.UniqueIPQuality = "lower_bound"
		}
	}
	for _, row := range s.bins {
		out.Timeline = append(out.Timeline, *row)
	}
	sort.Slice(out.Timeline, func(i, j int) bool { return out.Timeline[i].Time.Before(out.Timeline[j].Time) })
	for _, row := range r.Coverage {
		if !strings.HasPrefix(row.ID, "RULE-") || len(row.Engines) != 1 || len(row.RuleIDs) != 1 || row.Detections == nil {
			continue
		}
		category := "unclassified"
		for _, rule := range r.AnalysisRules {
			if rule.Engine == row.Engines[0] && rule.ID == row.RuleIDs[0] {
				if rule.Category != "" {
					category = rule.Category
				}
				break
			}
		}
		out.AttackDetections[row.Engines[0]+":"+category] += *row.Detections
	}
	return out
}
func (c *bundleCapture) duration(e Event) (*float64, bool) {
	var text string
	present := false
	if c.durationRegex != nil {
		fields := fieldsFrom(c.durationRegex, e.Raw)
		if fields != nil {
			text, present = fields["duration_seconds"]
		}
	} else if c.o.LogRegex == "" {
		payload, _, err := unwrapSyslog(e.Raw)
		if err == nil && strings.HasPrefix(strings.TrimSpace(payload), "{") {
			if obj, err := uniqueObject(payload); err == nil {
				if raw, ok := obj["request_time"]; ok && string(raw) != "null" {
					present = true
					if json.Unmarshal(raw, &text) != nil {
						text = string(raw)
					}
				}
			}
		}
	}
	if !present {
		return nil, false
	}
	value, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsInf(value, 0) || math.IsNaN(value) || value < 0 {
		return nil, true
	}
	return &value, false
}
func (c *bundleCapture) initStatistics() {
	geo := c.o.GeoIP != nil && len(c.o.GeoIP.Metadata()) > 0
	c.stats = newStatisticsRecorder(c.o.MaxKeys, geo)
	if c.o.LogRegex != "" {
		if rx, err := regexp.Compile(c.o.LogRegex); err == nil && rx.SubexpIndex("duration_seconds") >= 0 {
			c.durationRegex = rx
		}
	}
}
func writeStatistics(b *bundleWriter, r *InvestigationReport) error {
	for _, table := range []struct{ dim, name string }{{"status", "status"}, {"status_class", "status-class"}, {"method", "method"}, {"ip", "ip"}, {"host", "host"}, {"uri", "uri"}, {"user_agent", "user-agent"}, {"country", "country"}, {"asn", "asn"}, {"log_type", "log-type"}, {"protocol", "protocol"}} {
		if err := b.csv("statistics/"+table.name+"-summary.csv", []string{"key", "value", "name", "organization", "missing", "other", "requests", "suspicious_requests", "request_percent", "suspicious_within_group_percent", "unique_ips", "unique_ip_quality", "label_truncated", "count_quality"}, func(write func(...string) error) error {
			for _, row := range r.Statistics.Dimensions[table.dim] {
				ips := ""
				if row.UniqueIPs != nil {
					ips = strconv.FormatInt(*row.UniqueIPs, 10)
				}
				if err := write(row.Key, val(row.Value), val(row.Name), val(row.Organization), strconv.FormatBool(row.Value == nil && !row.Other), strconv.FormatBool(row.Other), strconv.FormatInt(row.Requests, 10), strconv.FormatInt(row.SuspiciousRequests, 10), strconv.FormatFloat(row.RequestPercent, 'f', 6, 64), strconv.FormatFloat(row.SuspiciousPercent, 'f', 6, 64), ips, row.UniqueIPQuality, strconv.FormatBool(row.LabelTruncated), row.CountQuality); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	number := func(v *float64) string {
		if v == nil {
			return ""
		}
		return strconv.FormatFloat(*v, 'g', -1, 64)
	}
	if err := b.csv("statistics/numeric-summary.csv", []string{"metric", "unit", "count", "missing", "invalid", "sum", "sum_quality", "minimum", "maximum", "mean"}, func(write func(...string) error) error {
		for _, metric := range []struct {
			name string
			data NumericSummary
		}{{"response_bytes", r.Statistics.ResponseBytes}, {"request_duration", r.Statistics.RequestDuration}} {
			n := metric.data
			if err := write(metric.name, n.Unit, strconv.FormatInt(n.Count, 10), strconv.FormatInt(n.Missing, 10), strconv.FormatInt(n.Invalid, 10), number(n.Sum), n.SumQuality, number(n.Min), number(n.Max), number(n.Mean)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return b.csv("statistics/timeline.csv", []string{"time_utc", "resolution_seconds", "requests", "suspicious_requests", "4xx", "5xx", "suspicious_count_quality"}, func(write func(...string) error) error {
		for _, row := range r.Statistics.Timeline {
			if err := write(row.Time.Format(time.RFC3339), strconv.FormatInt(r.Statistics.TimelineResolutionSeconds, 10), strconv.FormatInt(row.Requests, 10), strconv.FormatInt(row.SuspiciousRequests, 10), strconv.FormatInt(row.Errors4xx, 10), strconv.FormatInt(row.Errors5xx, 10), r.Statistics.SuspiciousCountQuality); err != nil {
				return err
			}
		}
		return nil
	})
}

package audit

import (
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Aura's case-wide aggregations are kept separate from WebAudit's windows and MAD.
// These reproduce the single-shard aggregation definitions, within the key budget.
type auraPeer struct {
	Samples, AuthSamples, NotFoundSamples []SourceEvidence
	Count, Auth, NotFound                 int64
	Bytes                                 float64
	First, Last                           time.Time
	Worst                                 int64
	NotFoundFirst, NotFoundLast           time.Time
}
type auraUA struct {
	Key     string
	Samples []SourceEvidence
	Value   string
	Count   int64
}
type auraAnalysis struct {
	evidence    *upstreamEvidence
	hourSamples map[int64][]SourceEvidence
	o           Options
	peers       map[string]*auraPeer
	windows     map[string]int64
	uas         map[string]*auraUA
	hours       map[int64]int64
	warnings    []string
}

func newAuraAnalysis(o Options) *auraAnalysis {
	return &auraAnalysis{o: o.defaults(), hourSamples: map[int64][]SourceEvidence{}, peers: map[string]*auraPeer{}, windows: map[string]int64{}, uas: map[string]*auraUA{}, hours: map[int64]int64{}}
}

// All four tables share a budget; only new entries need admission.
func (a *auraAnalysis) allowKey() bool {
	if len(a.peers)+len(a.windows)+len(a.uas)+len(a.hours) >= a.o.MaxKeys {
		uniqueAppend(&a.warnings, "Aura aggregation limit reached; source aggregations are incomplete")
		return false
	}
	return true
}
func (a *auraAnalysis) Observe(e Event) {
	if e.TimezoneUnknown || e.LogType != "http_access-log" {
		return
	}
	p := a.peers[e.IP]
	if p == nil && a.allowKey() {
		p = &auraPeer{First: e.Time, Last: e.Time}
		a.peers[strings.Clone(e.IP)] = p
	}
	if p != nil {
		p.Count++
		a.evidence.add(&p.Samples, e)
		p.Bytes += float64(val(e.Bytes))
		if e.Time.Before(p.First) {
			p.First = e.Time
		}
		if e.Time.After(p.Last) {
			p.Last = e.Time
		}
		if val(e.Status) == 404 {
			if p.NotFound == 0 || e.Time.Before(p.NotFoundFirst) {
				p.NotFoundFirst = e.Time
			}
			if p.NotFound == 0 || e.Time.After(p.NotFoundLast) {
				p.NotFoundLast = e.Time
			}
			p.NotFound++
			a.evidence.add(&p.NotFoundSamples, e)
		}
		if val(e.Status) == 401 || val(e.Status) == 403 {
			p.Auth++
			a.evidence.add(&p.AuthSamples, e)
			key := e.IP + "/" + strconv.FormatInt(e.Time.Truncate(5*time.Minute).Unix(), 10)
			count, exists := a.windows[key]
			if exists || a.allowKey() {
				a.windows[key] = count + 1
				if a.windows[key] > p.Worst {
					p.Worst = a.windows[key]
				}
			}
		}
	}
	{
		ua := sourceUA(e)
		key := digest(ua)
		v := a.uas[key]
		if v == nil && a.allowKey() {
			value, cut := clipped(ua, 512)
			if cut {
				uniqueAppend(&a.warnings, "Aura User-Agent samples truncated; source references remain authoritative")
			}
			v = &auraUA{Value: value, Key: key}
			a.uas[key] = v
		}
		if v != nil {
			v.Count++
			a.evidence.add(&v.Samples, e)
		}
	}
	hour := e.Time.Truncate(time.Hour).Unix()
	if count, exists := a.hours[hour]; exists || a.allowKey() {
		a.hours[hour] = count + 1
		if a.evidence != nil {
			samples := a.hourSamples[hour]
			a.evidence.add(&samples, e)
			a.hourSamples[hour] = samples
		}
	}
}
func (a *auraAnalysis) Finish() []SourceAlert {
	var out []SourceAlert
	add := func(rule, ip, group string, n int64, first, last *time.Time, samples []SourceEvidence) {
		alert := SourceAlert{Source: "AuraDFIR/analysis", RuleID: rule, IP: ip, Group: group, Count: n, First: first, Last: last}
		a.evidence.attach(&alert, samples)
		out = append(out, alert)
	}
	peers := make([]string, 0, len(a.peers))
	for ip := range a.peers {
		peers = append(peers, ip)
	}
	top := func(count func(*auraPeer) int64, n int) []string {
		copyIPs := append([]string(nil), peers...)
		sort.Slice(copyIPs, func(i, j int) bool {
			x, y := count(a.peers[copyIPs[i]]), count(a.peers[copyIPs[j]])
			if x != y {
				return x > y
			}
			return copyIPs[i] < copyIPs[j]
		})
		if len(copyIPs) > n {
			copyIPs = copyIPs[:n]
		}
		return copyIPs
	}
	for _, ip := range top(func(p *auraPeer) int64 { return p.Auth }, 200) {
		p := a.peers[ip]
		if p.Worst >= 20 {
			add("brute_force", ip, ip, p.Auth, nil, nil, p.AuthSamples)
		}
	}
	for _, ip := range top(func(p *auraPeer) int64 { return p.NotFound }, 200) {
		p := a.peers[ip]
		if p.NotFound >= 50 {
			add("enumeration_404", ip, ip, p.NotFound, ptr(p.NotFoundFirst), ptr(p.NotFoundLast), p.NotFoundSamples)
		}
	}
	totals := top(func(p *auraPeer) int64 { return p.Count }, 500)
	if len(totals) >= 5 {
		mean := 0.0
		for _, ip := range totals {
			mean += a.peers[ip].Bytes
		}
		mean /= float64(len(totals))
		variance := 0.0
		for _, ip := range totals {
			d := a.peers[ip].Bytes - mean
			variance += d * d
		}
		sd := math.Sqrt(variance / float64(len(totals)))
		for _, ip := range totals {
			p := a.peers[ip]
			if sd > 0 && p.Bytes > 10*1024*1024 && p.Bytes > mean+3*sd {
				add("exfil_bytes", ip, ip, p.Count, nil, nil, p.Samples)
			}
		}
	}
	uas := make([]*auraUA, 0, len(a.uas))
	for _, v := range a.uas {
		uas = append(uas, v)
	}
	sort.Slice(uas, func(i, j int) bool {
		if uas[i].Count != uas[j].Count {
			return uas[i].Count < uas[j].Count
		}
		return uas[i].Value < uas[j].Value
	})
	if len(uas) > 25 {
		uas = uas[:25]
	}
	for _, ua := range uas {
		if ua.Count <= 5 && ua.Value != "" && ua.Value != "-" {
			add("rare_user_agent", "", ua.Value, ua.Count, nil, nil, ua.Samples)
			out[len(out)-1].bundleMatchKey = ua.Key
		}
	}
	if len(a.hours) > 0 {
		var lo, hi int64
		first := true
		sum, squares := 0.0, 0.0
		for h, n := range a.hours {
			if first || h < lo {
				lo = h
			}
			if first || h > hi {
				hi = h
			}
			first = false
			sum += float64(n)
			squares += float64(n) * float64(n)
		}
		n := float64((hi-lo)/3600 + 1)
		if n >= 6 {
			mean := sum / n
			sd := math.Sqrt(math.Max(0, squares/n-mean*mean))
			keys := make([]int64, 0, len(a.hours))
			for h := range a.hours {
				keys = append(keys, h)
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
			if sd > 0 {
				for _, h := range keys {
					count := a.hours[h]
					if (float64(count)-mean)/sd > 3 {
						t := time.Unix(h, 0).UTC()
						add("traffic_spike", "", t.Format(time.RFC3339), count, &t, nil, a.hourSamples[h])
					}
				}
			}
		}
	}
	if len(out) > a.o.MaxFindings {
		uniqueAppend(&a.warnings, "Aura finding limit reached; source aggregations are incomplete")
		out = out[:a.o.MaxFindings]
	}
	return out
}

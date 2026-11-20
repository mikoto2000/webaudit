package audit

import (
	"net/netip"
	"sort"
	"strconv"
)

type GeoPeer struct {
	IP       string    `json:"ip"`
	Info     GeoIPInfo `json:"info"`
	Requests int64     `json:"requests"`
}
type GeoGroup struct {
	IPCount           int      `json:"ip_count"`
	SuspiciousIPCount int      `json:"suspicious_ip_count"`
	Key               string   `json:"key"`
	Name              string   `json:"name"`
	Requests          int64    `json:"requests"`
	Incidents         int      `json:"incidents"`
	IPs               []string `json:"ips"`
	Categories        []string `json:"categories"`
	MultiIP           bool     `json:"multiple_suspicious_ips"`
}
type GeoIPReport struct {
	Enabled               bool             `json:"enabled"`
	Correlations          []GeoCorrelation `json:"correlations"`
	CorrelationsTruncated bool             `json:"correlations_truncated"`
	Databases             []GeoDatabase    `json:"databases"`
	Peers                 []GeoPeer        `json:"peers"`
	Countries             []GeoGroup       `json:"countries"`
	ASNs                  []GeoGroup       `json:"asns"`
	Truncated             bool             `json:"truncated"`
	Context               string           `json:"context"`
}
type geoAnalysis struct {
	g         *GeoIP
	max       int
	peers     map[string]*GeoPeer
	truncated bool
}

func (a *geoAnalysis) observe(ip string) {
	if a == nil {
		return
	}
	if parsed, err := netip.ParseAddr(ip); err == nil {
		ip = parsed.Unmap().String()
	}
	if p := a.peers[ip]; p != nil {
		p.Requests++
		if p.Info.Classification == "public" {
			a.g.peerHits++
		}
		return
	}
	if len(a.peers) >= a.max {
		a.truncated = true
		a.g.skipped++
		return
	}
	a.peers[ip] = &GeoPeer{IP: ip, Info: a.g.Lookup(ip), Requests: 1}
}
func (a *geoAnalysis) finish(r *Report) {
	if a == nil {
		return
	}
	out := &GeoIPReport{Enabled: true, Databases: a.g.Metadata(), Truncated: a.truncated, Context: "Investigation context only: shared country or ASN does not establish a shared actor, an attack, or attack success. Counts cover retained parsed peers and WebAudit incidents; upstream alerts are separate. IP/category samples are limited to 64 per group; counts may be lower bounds when truncated."}
	countries, asns := map[string]*GeoGroup{}, map[string]*GeoGroup{}
	group := func(m map[string]*GeoGroup, key, name, ip string, requests int64, incident *Incident) {
		row := m[key]
		if row == nil {
			row = &GeoGroup{Key: key, Name: name}
			m[key] = row
		}
		row.Requests += requests
		if incident != nil {
			row.Incidents++
			for _, cat := range incident.Categories {
				if len(row.Categories) < 64 {
					uniqueAppend(&row.Categories, cat)
				}
			}
		}
		if len(row.IPs) < 64 {
			uniqueAppend(&row.IPs, ip)
		}
	}
	keys := make([]string, 0, len(a.peers))
	for ip := range a.peers {
		keys = append(keys, ip)
	}
	sort.Strings(keys)
	for _, ip := range keys {
		p := a.peers[ip]
		out.Peers = append(out.Peers, *p)
		ck, cn, ak, an := geoKeys(p.Info)
		group(countries, ck, cn, ip, p.Requests, nil)
		group(asns, ak, an, ip, p.Requests, nil)
	}
	suspicious := map[string]map[string]bool{}
	for i := range r.Findings {
		f := &r.Findings[i]
		x := a.g.Lookup(f.IP)
		f.GeoIP = &x
		ck, cn, ak, an := geoKeys(x)
		group(countries, ck, cn, f.IP, 0, f)
		group(asns, ak, an, f.IP, 0, f)
		if ak != "unknown" {
			if suspicious[ak] == nil {
				suspicious[ak] = map[string]bool{}
			}
			// We only need two distinct IPs to establish a multi-IP investigation hint.
			ip := f.IP
			if parsed, err := netip.ParseAddr(ip); err == nil {
				ip = parsed.Unmap().String()
			}
			if len(suspicious[ak]) < 2 {
				suspicious[ak][ip] = true
			}
		}
	}
	for k, v := range asns {
		v.MultiIP = len(suspicious[k]) >= 2
	}
	sorted := func(m map[string]*GeoGroup) []GeoGroup {
		out := make([]GeoGroup, 0, len(m))
		for _, v := range m {
			sort.Strings(v.IPs)
			sort.Strings(v.Categories)
			out = append(out, *v)
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Requests != out[j].Requests {
				return out[i].Requests > out[j].Requests
			}
			return out[i].Key < out[j].Key
		})
		return out
	}
	out.Countries = sorted(countries)
	out.ASNs = sorted(asns)
	populateGeoCounts(out, r.Findings)
	out.Correlations, out.CorrelationsTruncated = geoSimilarities(r.Findings, a.max)
	r.GeoIP = out
	if a.truncated {
		r.warn("GeoIP peer limit reached; request/country/ASN counts are lower bounds")
		r.Partial = true
	}
	for _, w := range a.g.warnings {
		r.warn(w)
	}
	for _, w := range a.g.lookupWarnings {
		r.warn(w)
		r.Partial = true
	}
}
func geoKeys(x GeoIPInfo) (ck, cn, ak, an string) {
	ck, cn, ak, an = "unknown", "unknown", "unknown", "unknown"
	if x.CountryCode != nil {
		ck = *x.CountryCode
	}
	if x.CountryName != nil {
		cn = *x.CountryName
	}
	if x.ASN != nil {
		ak = strconv.FormatUint(uint64(*x.ASN), 10)
	}
	if x.ASNOrganization != nil {
		an = *x.ASNOrganization
	}
	return
}

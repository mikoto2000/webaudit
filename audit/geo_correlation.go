package audit

import (
	"net/netip"
	"sort"
	"strconv"
	"time"
)

func canonicalIP(ip string) string {
	if parsed, e := netip.ParseAddr(ip); e == nil {
		return parsed.Unmap().String()
	}
	return ip
}

// Distinct counts refer to retained peers/incidents, not the 64-item display
// samples. Memory is bounded by the existing peer and incident budgets.
func populateGeoCounts(out *GeoIPReport, findings []Incident) {
	all, susp := map[string]map[string]bool{}, map[string]map[string]bool{}
	add := func(ip string, x GeoIPInfo, suspicious bool) {
		ck, _, ak, _ := geoKeys(x)
		for _, key := range []string{"country/" + ck, "asn/" + ak} {
			if all[key] == nil {
				all[key] = map[string]bool{}
			}
			all[key][canonicalIP(ip)] = true
			if suspicious {
				if susp[key] == nil {
					susp[key] = map[string]bool{}
				}
				susp[key][canonicalIP(ip)] = true
			}
		}
	}
	for _, p := range out.Peers {
		add(p.IP, p.Info, false)
	}
	for _, f := range findings {
		if f.GeoIP != nil {
			add(f.IP, *f.GeoIP, true)
		}
	}
	for i := range out.Countries {
		g := &out.Countries[i]
		g.IPCount = len(all["country/"+g.Key])
		g.SuspiciousIPCount = len(susp["country/"+g.Key])
	}
	for i := range out.ASNs {
		g := &out.ASNs[i]
		g.IPCount = len(all["asn/"+g.Key])
		g.SuspiciousIPCount = len(susp["asn/"+g.Key])
		g.MultiIP = g.Key != "unknown" && g.SuspiciousIPCount >= 2
	}
}

type GeoCorrelation struct {
	ASN              string    `json:"asn"`
	TargetHost       *string   `json:"target_host"`
	Path             string    `json:"path"`
	Category         string    `json:"category"`
	WindowStart      time.Time `json:"window_start"`
	WindowEnd        time.Time `json:"window_end"`
	IPCount          int       `json:"ip_count"`
	IPs              []string  `json:"ips"`
	IncidentIDs      []string  `json:"incident_ids"`
	Basis            string    `json:"basis"`
	SamplesTruncated bool      `json:"samples_truncated"`
}
type geoCandidate struct {
	row GeoCorrelation
	ips map[string]bool
}

func geoSimilarities(findings []Incident, max int) ([]GeoCorrelation, bool) {
	candidates := map[string]*geoCandidate{}
	truncated := false
	for _, f := range findings {
		if f.GeoIP == nil || f.GeoIP.ASN == nil || f.TimezoneUnknown || len(f.Evidence) == 0 {
			continue
		}
		e := f.Evidence[0].Event
		if e.Path == "" || e.EvidenceTruncated || e.RequestMalformed {
			continue
		}
		start := f.First.UTC().Truncate(5 * time.Minute)
		end := start.Add(5 * time.Minute)
		if !f.Last.Before(end) {
			continue
		}
		asn := strconv.FormatUint(uint64(*f.GeoIP.ASN), 10)
		for _, cat := range f.Categories {
			key := digest(asn + "\x00" + val(f.Host) + "\x00" + e.Path + "\x00" + cat + "\x00" + start.Format(time.RFC3339))
			c := candidates[key]
			if c == nil {
				if len(candidates) >= max {
					truncated = true
					continue
				}
				c = &geoCandidate{ips: map[string]bool{}, row: GeoCorrelation{ASN: asn, TargetHost: f.Host, Path: e.Path, Category: cat, WindowStart: start, WindowEnd: end, Basis: "Same known ASN, exact recorded path, target host when available, technique category and five-minute UTC interval. Unknown hosts are not verified as the same target. This is an investigation hint, not shared-actor or attack-success evidence."}}
				candidates[key] = c
			}
			c.ips[canonicalIP(f.IP)] = true
			if len(c.row.IncidentIDs) < 64 {
				uniqueAppend(&c.row.IncidentIDs, f.ID)
			} else {
				c.row.SamplesTruncated = true
			}
		}
	}
	out := make([]GeoCorrelation, 0)
	for _, c := range candidates {
		if len(c.ips) < 2 {
			continue
		}
		c.row.IPCount = len(c.ips)
		for ip := range c.ips {
			c.row.IPs = append(c.row.IPs, ip)
		}
		sort.Strings(c.row.IPs)
		if len(c.row.IPs) > 64 {
			c.row.IPs = c.row.IPs[:64]
			c.row.SamplesTruncated = true
		}
		sort.Strings(c.row.IncidentIDs)
		out = append(out, c.row)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.ASN != b.ASN {
			return a.ASN < b.ASN
		}
		if !a.WindowStart.Equal(b.WindowStart) {
			return a.WindowStart.Before(b.WindowStart)
		}
		if val(a.TargetHost) != val(b.TargetHost) {
			return val(a.TargetHost) < val(b.TargetHost)
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Category < b.Category
	})
	return out, truncated
}

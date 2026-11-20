package audit

import (
	"container/list"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// GeoIPInfo is context only. It is never consumed by detection or outcome scoring.
// Nil fields mean unknown, including a miss or a database not being configured.
type GeoIPInfo struct {
	Status          string  `json:"status"`
	CountryStatus   string  `json:"country_status"`
	ASNStatus       string  `json:"asn_status"`
	Classification  string  `json:"classification"`
	CountryCode     *string `json:"country_code"`
	CountryName     *string `json:"country_name"`
	ASN             *uint32 `json:"asn"`
	ASNOrganization *string `json:"asn_organization"`
}
type GeoDatabase struct {
	Version       *string    `json:"version"`
	DownloadedAt  *time.Time `json:"downloaded_at"`
	BuildTime     *time.Time `json:"build_time"`
	SourceURL     *string    `json:"source_url"`
	Generation    *string    `json:"generation"`
	LastCheckedAt *time.Time `json:"last_checked_at"`
	Role          string     `json:"role"`
	File          string     `json:"file"`
	Provider      string     `json:"provider"`
	Type          string     `json:"type"`
	UpdatedAt     *string    `json:"updated_at"`
	License       string     `json:"license"`
}
type geoCacheEntry struct {
	ip   netip.Addr
	info GeoIPInfo
}

// GeoIP is scoped to one analysis, used sequentially, and owns its DB handles.
// The LRU caches both hits and misses, with at most capacity entries.
type GeoIP struct {
	country, asn                   *maxminddb.Reader
	metadata                       []GeoDatabase
	warnings                       []string
	capacity                       int
	cache                          *list.List
	entries                        map[netip.Addr]*list.Element
	lookups                        uint64
	calls, hits, peerHits, skipped uint64
}

// OpenGeoIP opens explicitly selected files first. dir is the executable's geoip
// directory, never the current working directory. No DB is a valid disabled state.
func OpenGeoIP(country, asn, dir string, capacity int) (*GeoIP, error) {
	if capacity <= 0 {
		capacity = 4096
	}
	g := &GeoIP{capacity: capacity, cache: list.New(), entries: map[netip.Addr]*list.Element{}}
	for _, s := range []struct {
		role, path string
		dst        **maxminddb.Reader
	}{{"country", country, &g.country}, {"asn", asn, &g.asn}} {
		path := s.path
		if path == "" && dir != "" {
			fixed := filepath.Join(dir, s.role+".mmdb")
			if _, err := os.Stat(fixed); !os.IsNotExist(err) {
				path = fixed
			} else {
				matches, _ := filepath.Glob(filepath.Join(dir, "dbip-"+s.role+"-lite-*.mmdb"))
				sort.Strings(matches)
				if len(matches) > 0 {
					path = matches[len(matches)-1]
				}
			}
		}
		if path == "" {
			continue
		}
		db, err := maxminddb.Open(path)
		if err == nil {
			err = db.Verify()
			if err == nil {
				kind := strings.ToLower(db.Metadata.DatabaseType)
				if (s.role == "country" && strings.Contains(kind, "asn") && !strings.Contains(kind, "country")) || (s.role == "asn" && (strings.Contains(kind, "country") || strings.Contains(kind, "city")) && !strings.Contains(kind, "asn")) {
					err = fmt.Errorf("wrong database type %q for %s", db.Metadata.DatabaseType, s.role)
				}
			}
		}
		if err != nil {
			if db != nil {
				db.Close()
			}
			msg := fmt.Sprintf("GeoIP %s database %q: %v", s.role, path, err)
			if s.path != "" {
				g.Close()
				return nil, fmt.Errorf("%s", msg)
			}
			g.warnings = append(g.warnings, msg+"; automatic database ignored")
			continue
		}
		*s.dst = db
		m := GeoDatabase{Role: s.role, File: path, Provider: "unknown", Type: db.Metadata.DatabaseType, License: "unknown (see database provider terms)"}
		if db.Metadata.BuildEpoch > 0 {
			build := time.Unix(int64(db.Metadata.BuildEpoch), 0).UTC()
			m.BuildTime = &build
			v := build.Format("2006-01-02")
			m.UpdatedAt = &v
		}
		if strings.HasPrefix(strings.ToLower(m.Type), "dbip-") {
			m.Provider = "DB-IP"
			if strings.Contains(strings.ToLower(m.Type), "lite") {
				m.License = "CC BY 4.0; IP Geolocation by DB-IP (https://db-ip.com)"
			}
		}
		g.metadata = append(g.metadata, m)
	}
	if g.country == nil && g.asn == nil && len(g.warnings) == 0 {
		return nil, nil
	}
	return g, nil
}
func (g *GeoIP) Close() {
	if g == nil {
		return
	}
	if g.country != nil {
		g.country.Close()
	}
	if g.asn != nil {
		g.asn.Close()
	}
}
func (g *GeoIP) Metadata() []GeoDatabase { return append([]GeoDatabase(nil), g.metadata...) }

var reservedNetworks = func() []netip.Prefix {
	var out []netip.Prefix
	// Conservative special-purpose exclusions (including documentation, benchmark,
	// protocol assignment, NAT64/transition and future-use ranges). No DNS resolution.
	for _, s := range []string{"0.0.0.0/8", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func classifyIP(ip netip.Addr) string {
	if !ip.IsValid() || ip.Zone() != "" {
		return "invalid"
	}
	if ip.IsUnspecified() {
		return "unspecified"
	}
	if ip.IsLoopback() {
		return "loopback"
	}
	if ip.IsPrivate() {
		return "private"
	}
	if ip.IsLinkLocalUnicast() {
		return "link_local"
	}
	if ip.IsMulticast() {
		return "multicast"
	}
	if netip.MustParsePrefix("100.64.0.0/10").Contains(ip) {
		return "shared"
	}
	for _, p := range reservedNetworks {
		if p.Contains(ip) {
			return "reserved"
		}
	}
	if !ip.IsGlobalUnicast() || (ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip)) {
		return "reserved"
	}
	return "public"
}
func (g *GeoIP) Lookup(address string) GeoIPInfo {
	ip, err := netip.ParseAddr(address)
	if err == nil {
		ip = ip.Unmap()
	}
	x := GeoIPInfo{Classification: classifyIP(ip), Status: "db_not_installed", CountryStatus: "db_not_installed", ASNStatus: "db_not_installed"}
	if x.Classification == "invalid" {
		x.Status = "invalid_ip"
	} else if x.Classification != "public" {
		x.Status = "non_public"
	}
	if x.Classification != "public" {
		x.CountryStatus = "not_queried"
		x.ASNStatus = "not_queried"
	}
	if x.Classification != "public" || g == nil {
		return x
	}
	g.calls++
	if e := g.entries[ip]; e != nil {
		g.hits++
		g.cache.MoveToFront(e)
		return e.Value.(geoCacheEntry).info
	}
	if g.country != nil {
		x.CountryStatus = "not_found"
		var r struct {
			Country struct {
				Code  *string           `maxminddb:"iso_code"`
				Names map[string]string `maxminddb:"names"`
			} `maxminddb:"country"`
		}
		g.lookups++
		if err := g.country.Lookup(ip).Decode(&r); err != nil {
			x.CountryStatus = "read_error"
			g.lookupError("country", err)
		} else {
			x.CountryCode = nonempty(r.Country.Code)
			if x.CountryCode != nil || len(r.Country.Names) > 0 {
				x.CountryStatus = "found"
			}
			if v := r.Country.Names["en"]; v != "" {
				x.CountryName = ptr(v)
			}
		}
	}
	if g.asn != nil {
		x.ASNStatus = "not_found"
		var r struct {
			Number       *uint32 `maxminddb:"autonomous_system_number"`
			Organization *string `maxminddb:"autonomous_system_organization"`
		}
		g.lookups++
		if err := g.asn.Lookup(ip).Decode(&r); err != nil {
			x.ASNStatus = "read_error"
			g.lookupError("asn", err)
		} else {
			x.ASN = r.Number
			if x.ASN != nil || nonempty(r.Organization) != nil {
				x.ASNStatus = "found"
			}
			x.ASNOrganization = nonempty(r.Organization)
		}
	}
	if x.CountryStatus == "read_error" || x.ASNStatus == "read_error" {
		x.Status = "read_error"
	} else if x.CountryStatus == "found" || x.ASNStatus == "found" {
		x.Status = "found"
	} else if g.country != nil || g.asn != nil {
		x.Status = "not_found"
	}
	if g.cache.Len() >= g.capacity {
		e := g.cache.Back()
		delete(g.entries, e.Value.(geoCacheEntry).ip)
		g.cache.Remove(e)
	}
	g.entries[ip] = g.cache.PushFront(geoCacheEntry{ip, x})
	return x
}
func nonempty(p *string) *string {
	if p != nil && *p == "" {
		return nil
	}
	return p
}
func (g *GeoIP) lookupError(role string, err error) {
	// Bound error retention independently from IP cardinality.
	if len(g.warnings) < 10 {
		uniqueAppend(&g.warnings, fmt.Sprintf("GeoIP %s lookup failed: %v", role, err))
	}
}

type GeoMetrics struct {
	PublicLookupCalls uint64  `json:"public_lookup_calls"`
	LRUHits           uint64  `json:"lru_hits"`
	PeerCacheHits     uint64  `json:"peer_cache_hits"`
	ReaderLookups     uint64  `json:"reader_lookups"`
	CachedIPs         int     `json:"cached_ips"`
	UntrackedRequests uint64  `json:"untracked_requests"`
	CacheHitRate      float64 `json:"cache_hit_rate"`
}

// Metrics counts real MMDB calls and both bounded cache layers; no clock or I/O.
func (g *GeoIP) Metrics() GeoMetrics {
	if g == nil {
		return GeoMetrics{}
	}
	m := GeoMetrics{PublicLookupCalls: g.calls, LRUHits: g.hits, PeerCacheHits: g.peerHits, ReaderLookups: g.lookups, CachedIPs: len(g.entries), UntrackedRequests: g.skipped}
	if n := g.calls + g.peerHits; n > 0 {
		m.CacheHitRate = float64(g.hits+g.peerHits) / float64(n)
	}
	return m
}

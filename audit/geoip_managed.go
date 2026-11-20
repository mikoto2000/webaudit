package audit

import (
	"errors"
	"fmt"
	"path/filepath"
	"webaudit/internal/geoipdb"
)

// OpenManagedGeoIP opens one verified managed snapshot, retaining legacy discovery
// only when no managed manifest exists. Explicit files always take precedence.
func OpenManagedGeoIP(country, asn, dir, legacyDir string, capacity int) (*GeoIP, []string, error) {
	if dir == "" || (country != "" && asn != "") {
		return openDiscoveredGeoIP(country, asn, legacyDir, capacity)
	}
	var g *GeoIP
	err := geoipdb.WithCurrent(dir, func(meta *geoipdb.Metadata) error {
		c, a := country, asn
		for _, d := range meta.Current.Databases {
			if d.Role == "country" && c == "" {
				c = filepath.Join(dir, filepath.FromSlash(d.File))
			}
			if d.Role == "asn" && a == "" {
				a = filepath.Join(dir, filepath.FromSlash(d.File))
			}
		}
		var e error
		g, e = OpenGeoIP(c, a, "", capacity)
		if e != nil {
			return e
		}
		g.applyManagedMetadata(meta, country, asn)
		return nil
	})
	if errors.Is(err, geoipdb.ErrNotInstalled) {
		return openDiscoveredGeoIP(country, asn, legacyDir, capacity)
	}
	if err != nil {
		if g != nil {
			g.Close()
		}
		explicit, e := OpenGeoIP(country, asn, "", capacity)
		return explicit, []string{fmt.Sprintf("Managed GeoIP unavailable; analysis continues without automatic GeoIP: %v", err)}, e
	}
	return g, nil, nil
}

// Discovery failures disable only the unavailable optional databases. Return
// startup diagnostics separately even when another database remains usable.
func openDiscoveredGeoIP(country, asn, dir string, capacity int) (*GeoIP, []string, error) {
	g, err := OpenGeoIP(country, asn, dir, capacity)
	if g == nil {
		return nil, nil, err
	}
	warnings := g.warnings
	g.warnings = nil
	if g.country == nil && g.asn == nil {
		g.Close()
		g = nil
	}
	return g, warnings, err
}

func (g *GeoIP) applyManagedMetadata(meta *geoipdb.Metadata, country, asn string) {
	for i := range g.metadata {
		m := &g.metadata[i]
		if (m.Role == "country" && country != "") || (m.Role == "asn" && asn != "") {
			continue
		}
		for _, d := range meta.Current.Databases {
			if d.Role == m.Role {
				m.Version = ptr(d.Version)
				m.DownloadedAt = ptr(d.DownloadedAt)
				m.SourceURL = ptr(d.URL)
				m.Generation = ptr(meta.Current.ID)
				m.LastCheckedAt = ptr(meta.CheckedAt)
			}
		}
	}
}

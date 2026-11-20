package audit

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeoIPDistinctCountsBeyondSamples(t *testing.T) {
	g := testGeo(t, 128)
	a := &geoAnalysis{g: g, max: 128, peers: map[string]*GeoPeer{}}
	for i := 1; i <= 80; i++ {
		a.observe(fmt.Sprintf("8.8.8.%d", i))
	}
	r := Report{}
	a.finish(&r)
	if !r.GeoIP.Enabled || r.GeoIP.Countries[0].IPCount != 80 || r.GeoIP.ASNs[0].IPCount != 80 || len(r.GeoIP.ASNs[0].IPs) != 64 || r.GeoIP.ASNs[0].SuspiciousIPCount != 0 || len(r.GeoIP.Correlations) != 0 {
		t.Fatal(r.GeoIP)
	}
}
func TestGeoIPSimilarityRequiresTargetPatternAndTime(t *testing.T) {
	for _, same := range []bool{true, false} {
		t.Run(fmt.Sprint(same), func(t *testing.T) {
			g := testGeo(t, 8)
			path := filepath.Join(t.TempDir(), "access.log")
			second := "00:00:20"
			if !same {
				second = "00:10:20"
			}
			text := fmt.Sprintf("8.8.8.8 - - [01/Nov/2026:00:00:00 +0000] \"GET /.env HTTP/1.1\" 404 0\n8.8.8.9 - - [01/Nov/2026:%s +0000] \"GET /.env HTTP/1.1\" 404 0\n", second)
			os.WriteFile(path, []byte(text), 0600)
			r := Analyze([]string{path}, Options{GeoIP: g})
			if (len(r.GeoIP.Correlations) > 0) != same {
				t.Fatal("unsupported ASN-only similarity", r.GeoIP.Correlations)
			}
			if same {
				c := r.GeoIP.Correlations[0]
				if c.ASN != "64500" || c.Path != "/.env" || c.IPCount != 2 || len(c.IncidentIDs) != 2 {
					t.Fatal(c)
				}
			}
		})
	}
}
func TestGeoIPManagedMetadataInEveryReport(t *testing.T) {
	dir := managedFixture(t)
	g, w, e := OpenManagedGeoIP("", "", dir, "", 8)
	if e != nil || len(w) > 0 {
		t.Fatal(e, w)
	}
	defer g.Close()
	a := &geoAnalysis{g: g, max: 8, peers: map[string]*GeoPeer{}}
	a.observe("8.8.8.8")
	r := Report{}
	a.finish(&r)
	for _, format := range []string{"summary", "json", "csv", "html"} {
		var b bytes.Buffer
		if e = WriteReport(&b, r, format); e != nil {
			t.Fatal(e)
		}
		for _, want := range []string{"2026-11", "1970-01-01", "64500", "found"} {
			if !strings.Contains(b.String(), want) {
				t.Fatalf("%s missing %s", format, want)
			}
		}
	}
}

package main

import (
	"os"
	"time"
	"webaudit/audit"
)

func main() {
	g, e := audit.OpenGeoIP("audit/testdata/geoip/country.mmdb", "audit/testdata/geoip/asn.mmdb", "", 4096)
	if e != nil {
		panic(e)
	}
	defer g.Close()
	r := audit.Analyze([]string{"examples/geoip-sample.log"}, audit.Options{GeoIP: g, Now: func() time.Time { return time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC) }})
	for i := range r.Files {
		r.Files[i].Path = "examples/geoip-sample.log"
	}
	for i := range r.Findings {
		for j := range r.Findings[i].Evidence {
			r.Findings[i].Evidence[j].Event.File = "examples/geoip-sample.log"
		}
	}
	for _, group := range [][]audit.SourceAlert{r.UpstreamAlerts, r.AuraMatches, r.AuraAnalysis} {
		for i := range group {
			for j := range group[i].Events {
				group[i].Events[j].File = "examples/geoip-sample.log"
			}
		}
	}
	f, e := os.Create("examples/geoip-sample-report.html")
	if e != nil {
		panic(e)
	}
	if e = audit.WriteReport(f, r, "html"); e != nil {
		f.Close()
		panic(e)
	}
	if e = f.Close(); e != nil {
		panic(e)
	}
}

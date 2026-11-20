package audit

import (
	"fmt"
	"testing"
)

func TestGeoIPMetricsAndLargeCardinality(t *testing.T) {
	g := testGeo(t, 128)
	for i := 0; i < 10; i++ {
		g.Lookup("8.8.8.8")
	}
	g.Lookup("10.0.0.1")
	m := g.Metrics()
	if m.ReaderLookups != 2 || m.LRUHits != 9 || m.PublicLookupCalls != 10 || m.CacheHitRate != 0.9 {
		t.Fatal(m)
	}
	for i := 0; i < 65536; i++ {
		g.Lookup(fmt.Sprintf("11.%d.%d.1", i>>8, i&255))
	}
	if m = g.Metrics(); m.CachedIPs != 128 {
		t.Fatal(m)
	}
	g2 := testGeo(t, 128)
	a := &geoAnalysis{g: g2, max: 128, peers: map[string]*GeoPeer{}}
	for i := 0; i < 100; i++ {
		a.observe("8.8.8.8")
	}
	m = g2.Metrics()
	if m.ReaderLookups != 2 || m.PeerCacheHits != 99 || m.CacheHitRate != 0.99 {
		t.Fatal(m)
	}
	for i := 0; i < 65536; i++ {
		a.observe(fmt.Sprintf("11.%d.%d.1", i>>8, i&255))
	}
	if len(a.peers) != 128 || g2.Metrics().UntrackedRequests == 0 {
		t.Fatal("unbounded peers or missing lower-bound telemetry")
	}
}

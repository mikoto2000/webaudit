package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
	"webaudit/internal/geoipdb"
)

func managedFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	id := "gen-test"
	root := filepath.Join(dir, "versions", id)
	os.MkdirAll(root, 0700)
	meta := geoipdb.Metadata{Format: 1, Current: geoipdb.Generation{ID: id}, CheckedAt: time.Unix(123, 0).UTC()}
	for _, role := range []string{"country", "asn"} {
		b, e := os.ReadFile("testdata/geoip/" + role + ".mmdb")
		if e != nil {
			t.Fatal(e)
		}
		p := filepath.Join(root, role+".mmdb")
		os.WriteFile(p, b, 0600)
		d, e := geoipdb.InspectFile(p, role)
		if e != nil {
			t.Fatal(e)
		}
		d.Version = "2026-11"
		d.URL = "https://download.db-ip.com/free/dbip-" + role + "-lite-2026-11.mmdb.gz"
		d.DownloadedAt = time.Unix(123, 0).UTC()
		d.File = "versions/" + id + "/" + role + ".mmdb"
		meta.Current.Databases = append(meta.Current.Databases, d)
	}
	b, _ := json.Marshal(meta)
	os.WriteFile(filepath.Join(dir, "metadata.json"), b, 0600)
	return dir
}
func TestManagedGeoIPSnapshotAndExplicitPriority(t *testing.T) {
	dir := managedFixture(t)
	g, w, e := OpenManagedGeoIP("", "", dir, "", 4)
	if e != nil || len(w) > 0 || g == nil {
		t.Fatal(w, e)
	}
	defer g.Close()
	x := g.Lookup("8.8.8.8")
	if x.Status != "found" || val(g.Metadata()[0].Version) != "2026-11" || g.Metadata()[0].DownloadedAt == nil {
		t.Fatal(x, g.Metadata())
	}
	explicit, w, e := OpenManagedGeoIP("testdata/geoip/country.mmdb", "", dir, "", 4)
	if e != nil || len(w) > 0 {
		t.Fatal(w, e)
	}
	defer explicit.Close()
	if explicit.Metadata()[0].Version != nil || val(explicit.Metadata()[1].Version) != "2026-11" {
		t.Fatal("explicit metadata mixed with managed DB", explicit.Metadata())
	}
	os.WriteFile(filepath.Join(dir, "metadata.json"), []byte("corrupt"), 0600)
	bad, w, e := OpenManagedGeoIP("", "", dir, "testdata/geoip", 4)
	if e != nil || bad != nil || len(w) == 0 {
		t.Fatal("corrupt managed pair silently fell back", w, e)
	}
	if _, _, e = OpenManagedGeoIP("missing.mmdb", "", dir, "", 4); e == nil {
		t.Fatal("explicit path error swallowed")
	}
	// Already-open readers retain the old snapshot even if the manifest changes.
	if g.Lookup("8.8.8.9").Status != "found" {
		t.Fatal("snapshot changed")
	}
}
func TestLookupStates(t *testing.T) {
	var absent *GeoIP
	if absent.Lookup("8.8.8.8").Status != "db_not_installed" {
		t.Fatal("absent state")
	}
	g := testGeo(t, 4)
	for ip, want := range map[string]string{"8.8.8.8": "found", "2606:4700::1111": "found", "1.1.1.1": "not_found", "10.0.0.1": "non_public", "bad": "invalid_ip"} {
		if x := g.Lookup(ip); x.Status != want {
			t.Fatalf("%s %+v", ip, x)
		}
	}
	g.country.Close()
	if x := g.Lookup("8.8.8.10"); x.Status != "read_error" || x.CountryStatus != "read_error" {
		t.Fatal(x)
	}
}

func TestExplicitWrongRoleAndExcludedStates(t *testing.T) {
	if g, e := OpenGeoIP("testdata/geoip/asn.mmdb", "", "", 4); e == nil {
		g.Close()
		t.Fatal("wrong-role explicit database accepted")
	}
	g := testGeo(t, 4)
	x := g.Lookup("10.0.0.1")
	if x.CountryStatus != "not_queried" || x.ASNStatus != "not_queried" {
		t.Fatal(x)
	}
}

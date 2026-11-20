package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"webaudit/internal/geoipdb"
)

func TestGeoIPManagementCLI(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	var out, err bytes.Buffer
	if code := run([]string{"geoip", "status"}, &out, &err); code != 0 || !strings.Contains(out.String(), "Not installed") {
		t.Fatalf("%d %s %s", code, out.String(), err.String())
	}
	for _, args := range [][]string{{"geoip"}, {"geoip", "other"}, {"geoip", "status", "extra"}} {
		out.Reset()
		err.Reset()
		if run(args, &out, &err) != 2 {
			t.Fatal(args)
		}
	}
	d := filepath.Join(os.Getenv("XDG_DATA_HOME"), "webaudit", "geoip")
	os.MkdirAll(d, 0700)
	os.WriteFile(filepath.Join(d, "metadata.json"), []byte("broken"), 0600)
	out.Reset()
	err.Reset()
	if run([]string{"geoip", "status"}, &out, &err) != 1 || !strings.Contains(err.String(), "corrupt") {
		t.Fatal(out.String(), err.String())
	}
}

func installManagedForCLI(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", root)
	dir := filepath.Join(root, "webaudit", "geoip")
	id := "gen-cli"
	os.MkdirAll(filepath.Join(dir, "versions", id), 0700)
	meta := geoipdb.Metadata{Format: 1, Current: geoipdb.Generation{ID: id}, CheckedAt: time.Unix(123, 0).UTC()}
	for _, role := range []string{"country", "asn"} {
		b, e := os.ReadFile("../../audit/testdata/geoip/" + role + ".mmdb")
		if e != nil {
			t.Fatal(e)
		}
		p := filepath.Join(dir, "versions", id, role+".mmdb")
		os.WriteFile(p, b, 0600)
		d, e := geoipdb.InspectFile(p, role)
		if e != nil {
			t.Fatal(e)
		}
		d.File = "versions/" + id + "/" + role + ".mmdb"
		d.Version = "2026-11"
		d.DownloadedAt = time.Unix(123, 0).UTC()
		d.URL = "https://download.db-ip.com/free/dbip-" + role + "-lite-2026-11.mmdb.gz"
		meta.Current.Databases = append(meta.Current.Databases, d)
	}
	b, _ := json.Marshal(meta)
	os.WriteFile(filepath.Join(dir, "metadata.json"), b, 0600)
	return dir
}
func TestAnalysisAutomaticallyUsesManagedGeoIP(t *testing.T) {
	dir := installManagedForCLI(t)
	log := filepath.Join(t.TempDir(), "access.log")
	os.WriteFile(log, []byte(strings.Replace(logLine, "192.0.2.1", "8.8.8.8", 1)+"\n"), 0600)
	var out, err bytes.Buffer
	if code := run([]string{log, "--format", "json"}, &out, &err); code != 0 || !strings.Contains(out.String(), `"version": "2026-11"`) {
		t.Fatalf("%d %s %s", code, out.String(), err.String())
	}
	os.WriteFile(filepath.Join(dir, "metadata.json"), []byte("broken"), 0600)
	out.Reset()
	err.Reset()
	if code := run([]string{log, "--format", "json"}, &out, &err); code != 0 || !strings.Contains(err.String(), "Managed GeoIP unavailable") || strings.Contains(out.String(), `"geoip":`) {
		t.Fatalf("%d %s %s", code, out.String(), err.String())
	}
	out.Reset()
	err.Reset()
	if code := run([]string{log, "--geoip-country", "missing.mmdb"}, &out, &err); code != 2 {
		t.Fatal("explicit error hidden", code)
	}
}

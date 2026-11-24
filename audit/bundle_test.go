package audit

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundleInventoryAndManifest(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.log.gz")
	f, err := os.Create(input)
	if err != nil {
		t.Fatal(err)
	}
	z := gzip.NewWriter(f)
	raw := `192.0.2.1 - - [01/Nov/2026:00:00:00 +0000] "GET /.env HTTP/1.1" 404 0`
	if _, err := z.Write([]byte(raw + "\n\nbad record\n")); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "report")
	r, err := GenerateBundle([]string{input}, target, Options{}, BundleOptions{System: "<system>", Investigator: "tester", Language: "ja"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Schema != "webaudit/investigation-1" || r.Metadata.System != "<system>" || r.Status != "partial" {
		t.Fatalf("bad report: %+v", r)
	}
	if len(r.Inventory) != 1 {
		t.Fatal(r.Inventory)
	}
	in := r.Inventory[0]
	original, _ := os.ReadFile(input)
	sum := sha256.Sum256(original)
	if in.SHA256 == nil || *in.SHA256 != hex.EncodeToString(sum[:]) || in.HashScope != "original_file_bytes" || in.Compression != "gzip" {
		t.Fatalf("wrong original fingerprint: %+v", in)
	}
	if in.TotalLines != 3 || in.Parsed != 1 || in.Unparsed != 1 || in.Excluded != 1 || in.First == nil || in.Last == nil {
		t.Fatalf("bad counts: %+v", in)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(target, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest BundleManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Schema != "webaudit/manifest-1" || manifest.RulesSHA256 == "" || manifest.Complete {
		t.Fatal(manifest)
	}
	for _, a := range manifest.Artifacts {
		data, err := os.ReadFile(filepath.Join(target, filepath.FromSlash(a.Path)))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if a.SHA256 != hex.EncodeToString(sum[:]) || a.Bytes != int64(len(data)) {
			t.Fatal("artifact hash mismatch", a)
		}
	}
	if _, err := GenerateBundle([]string{input}, target, Options{}, BundleOptions{}); err == nil {
		t.Fatal("existing output accepted")
	}
	if _, err := os.Stat(filepath.Join(target, "diagnostics", "parse-errors.csv")); err != nil {
		t.Fatal(err)
	}
}

func TestBundleDedupEmptyUnreadableAndPrivateSettings(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.log")
	b := filepath.Join(dir, "b.log")
	empty := filepath.Join(dir, "empty.log")
	raw := `192.0.2.1 - - [01/Nov/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 0`
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte(raw+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := GenerateBundle([]string{a, b, empty, filepath.Join(dir, "missing.log")}, filepath.Join(dir, "report"), Options{DeduplicateFiles: true}, BundleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var excluded int64
	for _, in := range r.Inventory {
		excluded += in.Excluded
	}
	if len(r.Inventory) != 4 || excluded != 1 || r.Status != "partial" {
		t.Fatalf("incomplete inventory: %+v", r.Inventory)
	}
	// Only safe structured options are serialized, never the custom regex text.
	options := Options{LogRegex: "secret-cookie-token"}.defaults()
	settings := bundleSettings(options, BundleOptions{}.defaults())
	data, _ := json.Marshal(settings)
	if strings.Contains(string(data), "secret-cookie-token") {
		t.Fatal("secret regex exposed")
	}
}

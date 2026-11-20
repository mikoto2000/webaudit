package geoipdb

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/oschwald/maxminddb-golang/v2"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var ErrNotInstalled = errors.New("GeoIP databases are not installed; run 'webaudit geoip download'")

type Database struct {
	Role         string     `json:"role"`
	Provider     string     `json:"provider"`
	Type         string     `json:"type"`
	Version      string     `json:"version"`
	URL          string     `json:"url"`
	DownloadedAt time.Time  `json:"downloaded_at"`
	BuildTime    *time.Time `json:"build_time"`
	Size         int64      `json:"size"`
	SHA256       string     `json:"sha256"`
	SourceSHA1   string     `json:"source_sha1"`
	File         string     `json:"file"`
}
type Generation struct {
	ID        string     `json:"id"`
	Databases []Database `json:"databases"`
}
type Metadata struct {
	Format    int         `json:"format"`
	Current   Generation  `json:"current"`
	Previous  *Generation `json:"previous,omitempty"`
	CheckedAt time.Time   `json:"last_checked_at"`
}

var generationID = regexp.MustCompile(`^gen-[a-zA-Z0-9_-]{1,80}$`)

func ReadMetadata(dir string) (*Metadata, error) {
	f, err := os.Open(filepath.Join(dir, "metadata.json"))
	if os.IsNotExist(err) {
		return nil, ErrNotInstalled
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("GeoIP metadata exceeds size limit")
	}
	var m Metadata
	if err = json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("GeoIP metadata is corrupt: %w", err)
	}
	if m.Format != 1 {
		return nil, fmt.Errorf("unsupported GeoIP metadata format %d", m.Format)
	}
	return &m, nil
}
func ValidateCurrent(dir string, m *Metadata) error {
	if m == nil {
		return ErrNotInstalled
	}
	return validateGeneration(dir, m.Current)
}
func validateGeneration(dir string, g Generation) error {
	if !generationID.MatchString(g.ID) || len(g.Databases) != 2 {
		return fmt.Errorf("invalid GeoIP generation metadata")
	}
	for i, role := range []string{"country", "asn"} {
		d := g.Databases[i]
		expected := filepath.ToSlash(filepath.Join("versions", g.ID, role+".mmdb"))
		if d.Role != role || d.File != expected || d.Size <= 0 || len(d.SHA256) != 64 {
			return fmt.Errorf("invalid GeoIP %s metadata/path", role)
		}
		u, _ := url.Parse(d.URL)
		var releaseParts []string
		if u != nil {
			releaseParts = downloadPath.FindStringSubmatch(u.Path)
		}
		if allowedURL(d.URL) != nil || len(releaseParts) != 3 || releaseParts[1] != role || releaseParts[2] != d.Version || d.Provider != "DB-IP Lite" || d.DownloadedAt.IsZero() {
			return fmt.Errorf("GeoIP %s publication metadata mismatch", role)
		}
		sum, e := hex.DecodeString(d.SHA256)
		if e != nil || len(sum) != 32 {
			return fmt.Errorf("invalid GeoIP SHA256")
		}
		path := filepath.Join(dir, filepath.FromSlash(expected))
		// Reject symlinks at every managed component; a manifest cannot escape its root.
		for _, p := range []string{filepath.Join(dir, "versions"), filepath.Join(dir, "versions", g.ID), path} {
			st, e := os.Lstat(p)
			if e != nil {
				return fmt.Errorf("GeoIP %s: %w", role, e)
			}
			if st.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("GeoIP managed path is a symlink: %s", p)
			}
		}
		info, e := InspectFile(path, role)
		if e != nil {
			return e
		}
		if info.Size != d.Size || info.SHA256 != d.SHA256 || info.Type != d.Type || info.SourceSHA1 != d.SourceSHA1 || !sameTime(info.BuildTime, d.BuildTime) {
			return fmt.Errorf("GeoIP %s integrity mismatch (size/SHA256/type/build)", role)
		}
	}
	return nil
}
func sameTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

// InspectFile verifies both MMDB structure and the expected DB-IP record schema.
// No network operations occur in this function or metadata validation.
func InspectFile(path, role string) (Database, error) {
	d := Database{Role: role, Provider: "DB-IP Lite"}
	f, err := os.Open(path)
	if err != nil {
		return d, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return d, err
	}
	if !st.Mode().IsRegular() || st.Size() > 256<<20 {
		f.Close()
		return d, fmt.Errorf("GeoIP file is not a regular MMDB within size limit")
	}
	h := sha256.New()
	h1 := sha1.New()
	_, err = io.Copy(io.MultiWriter(h, h1), f)
	f.Close()
	if err != nil {
		return d, err
	}
	d.Size = st.Size()
	d.SHA256 = hex.EncodeToString(h.Sum(nil))
	d.SourceSHA1 = hex.EncodeToString(h1.Sum(nil))
	db, err := maxminddb.Open(path)
	if err != nil {
		return d, fmt.Errorf("GeoIP %s MMDB: %w", role, err)
	}
	defer db.Close()
	if err = db.Verify(); err != nil {
		return d, fmt.Errorf("GeoIP %s MMDB validation: %w", role, err)
	}
	d.Type = db.Metadata.DatabaseType
	expected := "DBIP-Country-Lite"
	if role == "asn" {
		expected = "DBIP-ASN-Lite"
	} else if role != "country" {
		return d, fmt.Errorf("unknown DB role")
	}
	if d.Type != expected && !strings.HasPrefix(d.Type, expected+" (") {
		return d, fmt.Errorf("expected %s database, got %q", role, d.Type)
	}
	if db.Metadata.BuildEpoch > 0 {
		v := time.Unix(int64(db.Metadata.BuildEpoch), 0).UTC()
		d.BuildTime = &v
	}
	found := false
	for result := range db.Networks() {
		if role == "country" {
			var r struct {
				Country struct {
					Code  *string           `maxminddb:"iso_code"`
					Names map[string]string `maxminddb:"names"`
				} `maxminddb:"country"`
			}
			if err = result.Decode(&r); err != nil {
				return d, fmt.Errorf("GeoIP country schema: %w", err)
			}
			found = found || r.Country.Code != nil || len(r.Country.Names) > 0
		} else {
			var r struct {
				Number *uint32 `maxminddb:"autonomous_system_number"`
				Org    *string `maxminddb:"autonomous_system_organization"`
			}
			if err = result.Decode(&r); err != nil {
				return d, fmt.Errorf("GeoIP ASN schema: %w", err)
			}
			found = found || r.Number != nil || r.Org != nil
		}
	}
	if !found {
		return d, fmt.Errorf("GeoIP %s database contains no expected fields", role)
	}
	return d, nil
}

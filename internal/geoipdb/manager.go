package geoipdb

import (
	"compress/gzip"
	"context"
	"crypto/sha1" // DB-IP publishes SHA1 for decompressed files; SHA256 is used at rest.
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Manager struct {
	Dir         string
	Source      Source
	Now         func() time.Time
	maxDatabase int64
	fail        func(string) error
}
type Result struct {
	Metadata *Metadata
	Changed  []string
	Warnings []string
}

func NewManager(dir string) *Manager {
	return &Manager{Dir: dir, Source: NewProvider(), Now: time.Now, maxDatabase: 256 << 20}
}
func (m *Manager) fault(point string) error {
	if m.fail != nil {
		return m.fail(point)
	}
	return nil
}
func (m *Manager) Reconcile(ctx context.Context, update bool) (Result, error) {
	var out Result
	if e := os.MkdirAll(m.Dir, 0700); e != nil {
		return out, e
	}
	unlock, e := lock(m.Dir)
	if e != nil {
		return out, e
	}
	defer unlock()
	old, e := ReadMetadata(m.Dir)
	if e != nil && !errors.Is(e, ErrNotInstalled) {
		return out, e
	}
	if old != nil {
		if e = ValidateCurrent(m.Dir, old); e != nil {
			return out, e
		}
		out.Metadata = old
	}
	m.cleanup(old, &out)
	if old != nil && !update {
		return out, nil
	}
	if old == nil && !update {
		for _, role := range []string{"country", "asn"} {
			if _, e := os.Lstat(filepath.Join(m.Dir, role+".mmdb")); !os.IsNotExist(e) {
				return out, fmt.Errorf("unmanaged %s.mmdb already exists; use explicit DB paths or 'geoip update' to install a managed generation", role)
			}
		}
	}
	releases := make([]Release, 2)
	changed := make([]bool, 2)
	for i, role := range []string{"country", "asn"} {
		r, e := m.Source.Latest(ctx, role)
		if e != nil {
			return out, e
		}
		if r.Role != role || r.Version == "" || allowedURL(r.URL) != nil {
			return out, fmt.Errorf("invalid %s release", role)
		}
		releases[i] = r
		if old != nil && r.Version < old.Current.Databases[i].Version {
			return out, fmt.Errorf("official %s release is older than installed; refusing downgrade", role)
		}
		changed[i] = old == nil || r.Version != old.Current.Databases[i].Version || r.SHA1 != old.Current.Databases[i].SourceSHA1
		if changed[i] {
			out.Changed = append(out.Changed, role)
		}
	}
	if len(out.Changed) == 0 {
		next := *old
		next.CheckedAt = m.Now().UTC()
		if e = m.publish(&next); e != nil {
			return out, e
		}
		out.Metadata = &next
		return out, nil
	}
	stage, e := os.MkdirTemp(m.Dir, ".staging-")
	if e != nil {
		return out, e
	}
	defer os.RemoveAll(stage)
	id := "gen-" + strings.TrimPrefix(filepath.Base(stage), ".staging-")
	next := &Metadata{Format: 1, CheckedAt: m.Now().UTC(), Current: Generation{ID: id}}
	if old != nil {
		previous := old.Current
		next.Previous = &previous
	}
	for i, role := range []string{"country", "asn"} {
		path := filepath.Join(stage, role+".mmdb")
		var d Database
		if changed[i] {
			d, e = m.download(ctx, releases[i], path)
		} else {
			d = old.Current.Databases[i]
			e = copyFile(filepath.Join(m.Dir, filepath.FromSlash(d.File)), path)
		}
		if e != nil {
			return out, fmt.Errorf("GeoIP %s: %w", role, e)
		}
		d.File = filepath.ToSlash(filepath.Join("versions", id, role+".mmdb"))
		next.Current.Databases = append(next.Current.Databases, d)
		if e = m.fault("after-" + role); e != nil {
			return out, e
		}
	}
	if e = os.MkdirAll(filepath.Join(m.Dir, "versions"), 0700); e != nil {
		return out, e
	}
	final := filepath.Join(m.Dir, "versions", id)
	if e = os.Rename(stage, final); e != nil {
		return out, e
	}
	published := false
	defer func() {
		if !published {
			os.RemoveAll(final)
		}
	}()
	if e = m.fault("after-generation"); e != nil {
		return out, e
	}
	if e = ValidateCurrent(m.Dir, next); e != nil {
		return out, e
	}
	if e = ctx.Err(); e != nil {
		return out, e
	}
	if e = m.publish(next); e != nil {
		return out, e
	}
	published = true
	out.Metadata = next
	m.cleanup(next, &out)
	return out, nil
}
func (m *Manager) download(ctx context.Context, r Release, path string) (Database, error) {
	var d Database
	packed, e := os.CreateTemp(filepath.Dir(path), "compressed-")
	if e != nil {
		return d, e
	}
	defer os.Remove(packed.Name())
	e = m.Source.Fetch(ctx, r, packed)
	if closeErr := packed.Close(); e == nil {
		e = closeErr
	}
	if e != nil {
		return d, e
	}
	in, e := os.Open(packed.Name())
	if e != nil {
		return d, e
	}
	defer in.Close()
	z, e := gzip.NewReader(in)
	if e != nil {
		return d, fmt.Errorf("invalid gzip: %w", e)
	}
	defer z.Close()
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return d, e
	}
	h := sha1.New()
	n, e := io.Copy(io.MultiWriter(f, h), io.LimitReader(z, m.maxDatabase+1))
	if e == nil && n > m.maxDatabase {
		e = fmt.Errorf("decompressed database exceeds size limit")
	}
	if e == nil {
		e = f.Sync()
	}
	if closeErr := f.Close(); e == nil {
		e = closeErr
	}
	if e != nil {
		return d, e
	}
	if hex.EncodeToString(h.Sum(nil)) != r.SHA1 {
		return d, fmt.Errorf("official decompressed MMDB SHA1 mismatch")
	}
	d, e = InspectFile(path, r.Role)
	if e != nil {
		return d, e
	}
	d.Version = r.Version
	d.URL = r.URL
	d.SourceSHA1 = r.SHA1
	d.DownloadedAt = m.Now().UTC()
	return d, nil
}
func copyFile(from, to string) error {
	in, e := os.Open(from)
	if e != nil {
		return e
	}
	defer in.Close()
	out, e := os.OpenFile(to, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = io.Copy(out, in)
	if e == nil {
		e = out.Sync()
	}
	if closeErr := out.Close(); e == nil {
		e = closeErr
	}
	return e
}
func (m *Manager) publish(meta *Metadata) error {
	if e := m.fault("manifest-write"); e != nil {
		return e
	}
	f, e := os.CreateTemp(m.Dir, ".manifest-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	e = enc.Encode(meta)
	if e == nil {
		e = f.Sync()
	}
	if closeErr := f.Close(); e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	if e = m.fault("manifest-replace"); e != nil {
		return e
	}
	if e = replaceFile(f.Name(), filepath.Join(m.Dir, "metadata.json")); e != nil {
		return e
	}
	// The commit point is the single manifest replacement. Directory sync is best
	// effort: some platforms/filesystems do not support it. Process interruption is
	// safe; storage hardware power-loss guarantees depend on the filesystem.
	if dir, e := os.Open(m.Dir); e == nil {
		dir.Sync()
		dir.Close()
	}
	return nil
}
func (m *Manager) Rollback(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	unlock, e := lock(m.Dir)
	if e != nil {
		return e
	}
	defer unlock()
	meta, e := ReadMetadata(m.Dir)
	if e != nil {
		return e
	}
	if meta.Previous == nil {
		return fmt.Errorf("no previous GeoIP generation is available")
	}
	if e = validateGeneration(m.Dir, *meta.Previous); e != nil {
		return fmt.Errorf("previous generation is invalid: %w", e)
	}
	previous := meta.Current
	meta.Current = *meta.Previous
	meta.Previous = &previous
	return m.publish(meta)
}
func (m *Manager) cleanup(meta *Metadata, out *Result) {
	entries, e := os.ReadDir(m.Dir)
	if e == nil {
		for _, x := range entries {
			if strings.HasPrefix(x.Name(), ".staging-") || strings.HasPrefix(x.Name(), ".manifest-") {
				if e = os.RemoveAll(filepath.Join(m.Dir, x.Name())); e != nil {
					out.Warnings = append(out.Warnings, "Could not remove interrupted GeoIP staging: "+e.Error())
				}
			}
		}
	}
	keep := map[string]bool{}
	if meta != nil {
		keep[meta.Current.ID] = true
		if meta.Previous != nil {
			keep[meta.Previous.ID] = true
		}
	}
	entries, e = os.ReadDir(filepath.Join(m.Dir, "versions"))
	if e != nil {
		return
	}
	for _, x := range entries {
		if generationID.MatchString(x.Name()) && !keep[x.Name()] {
			if e = os.RemoveAll(filepath.Join(m.Dir, "versions", x.Name())); e != nil {
				out.Warnings = append(out.Warnings, "Old GeoIP generation is in use; cleanup deferred: "+e.Error())
			}
		}
	}
}

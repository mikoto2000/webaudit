package geoipdb

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeSource struct {
	versions      map[string]string
	data          map[string][]byte
	calls         map[string]int
	fail          string
	badSHA        bool
	wait, started chan struct{}
}

func fixture(t *testing.T, role string) []byte {
	t.Helper()
	b, e := os.ReadFile("../../audit/testdata/geoip/" + role + ".mmdb")
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func (s *fakeSource) Latest(ctx context.Context, role string) (Release, error) {
	if s.wait != nil {
		close(s.started)
		<-s.wait
		s.wait = nil
	}
	b := s.data[role]
	sum := sha1.Sum(b)
	sha := hex.EncodeToString(sum[:])
	if s.badSHA {
		sha = strings.Repeat("0", 40)
	}
	v := s.versions[role]
	return Release{Role: role, Version: v, URL: "https://download.db-ip.com/free/dbip-" + role + "-lite-" + v + ".mmdb.gz", SHA1: sha}, nil
}
func (s *fakeSource) Fetch(ctx context.Context, r Release, w io.Writer) error {
	s.calls[r.Role]++
	if s.fail == r.Role {
		return errors.New("simulated transfer failure")
	}
	z := gzip.NewWriter(w)
	if _, e := z.Write(s.data[r.Role]); e != nil {
		return e
	}
	return z.Close()
}
func manager(t *testing.T) (*Manager, *fakeSource) {
	t.Helper()
	s := &fakeSource{versions: map[string]string{"country": "2026-10", "asn": "2026-10"}, data: map[string][]byte{"country": fixture(t, "country"), "asn": fixture(t, "asn")}, calls: map[string]int{}}
	m := NewManager(t.TempDir())
	m.Source = s
	m.Now = func() time.Time { return time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC) }
	return m, s
}
func TestInstallAndSelectiveUpdate(t *testing.T) {
	m, s := manager(t)
	ctx := context.Background()
	r, e := m.Reconcile(ctx, false)
	if e != nil || len(r.Changed) != 2 {
		t.Fatal(r, e)
	}
	first := r.Metadata.Current.ID
	if _, e = m.Reconcile(ctx, false); e != nil || s.calls["country"] != 1 {
		t.Fatal("download replaced existing DB", e)
	}
	r, e = m.Reconcile(ctx, true)
	if e != nil || len(r.Changed) != 0 || r.Metadata.Current.ID != first {
		t.Fatal(r, e)
	}
	for _, role := range []string{"country", "asn"} {
		s.versions[role] = "2026-11"
		before := s.calls[role]
		other := "country"
		if role == "country" {
			other = "asn"
		}
		otherBefore := s.calls[other]
		r, e = m.Reconcile(ctx, true)
		if e != nil || len(r.Changed) != 1 || r.Changed[0] != role || s.calls[role] != before+1 || s.calls[other] != otherBefore {
			t.Fatal(r, e)
		}
		if e = ValidateCurrent(m.Dir, r.Metadata); e != nil {
			t.Fatal(e)
		}
	}
	if e = m.Rollback(ctx); e != nil {
		t.Fatal(e)
	}
	meta, e := ReadMetadata(m.Dir)
	if e != nil || meta.Current.Databases[1].Version != "2026-10" {
		t.Fatal(meta, e)
	}
}
func TestUpdateFailureKeepsPublishedPair(t *testing.T) {
	for _, point := range []string{"transfer", "after-country", "manifest-write", "manifest-replace", "after-generation"} {
		t.Run(point, func(t *testing.T) {
			m, s := manager(t)
			ctx := context.Background()
			if _, e := m.Reconcile(ctx, false); e != nil {
				t.Fatal(e)
			}
			before, _ := os.ReadFile(filepath.Join(m.Dir, "metadata.json"))
			s.versions["country"], s.versions["asn"] = "2026-11", "2026-11"
			if point == "transfer" {
				s.fail = "asn"
			} else {
				m.fail = func(p string) error {
					if p == point {
						return errors.New("injected " + point)
					}
					return nil
				}
			}
			if _, e := m.Reconcile(ctx, true); e == nil {
				t.Fatal("failure ignored")
			}
			after, _ := os.ReadFile(filepath.Join(m.Dir, "metadata.json"))
			if !bytes.Equal(before, after) {
				t.Fatal("published pair changed on failure")
			}
			meta, e := ReadMetadata(m.Dir)
			if e != nil || ValidateCurrent(m.Dir, meta) != nil {
				t.Fatal("old DB unusable", e)
			}
			m.fail = nil
			s.fail = ""
			if _, e = m.Reconcile(ctx, true); e != nil {
				t.Fatal("retry failed", e)
			}
		})
	}
}
func TestInvalidDownloadsNeverPublished(t *testing.T) {
	for _, kind := range []string{"wrong-role", "invalid-mmdb", "checksum", "expanded-size", "corrupt-gzip"} {
		t.Run(kind, func(t *testing.T) {
			m, s := manager(t)
			switch kind {
			case "wrong-role":
				s.data["country"] = fixture(t, "asn")
			case "invalid-mmdb":
				s.data["country"] = []byte("broken")
			case "checksum":
				s.badSHA = true
			case "expanded-size":
				m.maxDatabase = 10
			case "corrupt-gzip":
				m.Source = badGzipSource{s}
			}
			if _, e := m.Reconcile(context.Background(), false); e == nil {
				t.Fatal("invalid download accepted")
			}
			if _, e := os.Stat(filepath.Join(m.Dir, "metadata.json")); !os.IsNotExist(e) {
				t.Fatal("invalid pair published")
			}
		})
	}
}

type badGzipSource struct{ *fakeSource }

func (s badGzipSource) Fetch(ctx context.Context, r Release, w io.Writer) error {
	_, e := io.WriteString(w, "not gzip")
	return e
}
func TestConcurrentUpdateAndInterruptedRecovery(t *testing.T) {
	m, s := manager(t)
	s.wait = make(chan struct{})
	s.started = make(chan struct{})
	wait := s.wait
	done := make(chan error, 1)
	go func() { _, e := m.Reconcile(context.Background(), false); done <- e }()
	<-s.started
	m2 := NewManager(m.Dir)
	m2.Source = s
	if _, e := m2.Reconcile(context.Background(), true); e == nil {
		t.Fatal("second writer acquired lock")
	}
	close(wait)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	os.Mkdir(filepath.Join(m.Dir, ".staging-interrupted"), 0700)
	os.WriteFile(filepath.Join(m.Dir, ".staging-interrupted", "partial"), []byte("x"), 0600)
	os.Mkdir(filepath.Join(m.Dir, "versions", "gen-orphan"), 0700)
	if _, e := m.Reconcile(context.Background(), true); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(m.Dir, ".staging-interrupted")); !os.IsNotExist(e) {
		t.Fatal("stale staging retained")
	}
	if _, e := os.Stat(filepath.Join(m.Dir, "versions", "gen-orphan")); !os.IsNotExist(e) {
		t.Fatal("orphan retained")
	}
}
func TestMetadataIntegrityAndRollback(t *testing.T) {
	m, s := manager(t)
	ctx := context.Background()
	m.Reconcile(ctx, false)
	s.versions["country"] = "2026-11"
	r, e := m.Reconcile(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(m.Dir, filepath.FromSlash(r.Metadata.Current.Databases[0].File))
	os.WriteFile(p, []byte("tamper"), 0600)
	if e = ValidateCurrent(m.Dir, r.Metadata); e == nil {
		t.Fatal("tampering undetected")
	}
	if e = m.Rollback(ctx); e != nil {
		t.Fatal("cannot recover previous pair", e)
	}
	meta, _ := ReadMetadata(m.Dir)
	if e = ValidateCurrent(m.Dir, meta); e != nil {
		t.Fatal(e)
	}
	meta.Current.Databases[0].File = "../../escape"
	if e = ValidateCurrent(m.Dir, meta); e == nil {
		t.Fatal("path escape accepted")
	}
}
func TestLockReleasedWhenProcessExits(t *testing.T) {
	if dir := os.Getenv("WEBAUDIT_LOCK_TEST"); dir != "" {
		f, e := lock(dir)
		if e != nil {
			os.Exit(3)
		}
		defer f()
		fmt.Println("locked")
		select {}
	}
	d := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockReleasedWhenProcessExits$")
	cmd.Env = append(os.Environ(), "WEBAUDIT_LOCK_TEST="+d)
	pipe, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	line, e := bufio.NewReader(pipe).ReadString('\n')
	if e != nil || strings.TrimSpace(line) != "locked" {
		t.Fatal(line, e)
	}
	cmd.Process.Kill()
	cmd.Wait()
	release, e := lock(d)
	if e != nil {
		t.Fatal("dead process left stale lock", e)
	}
	release()
}

func TestMetadataPublicationFieldsAndSymlinkSafety(t *testing.T) {
	m, _ := manager(t)
	r, e := m.Reconcile(context.Background(), false)
	if e != nil {
		t.Fatal(e)
	}
	original := r.Metadata.Current.Databases[0]
	for _, mutate := range []func(*Database){func(d *Database) { d.Version = "2099-12" }, func(d *Database) { d.URL = "https://evil.test/file" }, func(d *Database) { d.SourceSHA1 = strings.Repeat("0", 40) }} {
		r.Metadata.Current.Databases[0] = original
		mutate(&r.Metadata.Current.Databases[0])
		if e = ValidateCurrent(m.Dir, r.Metadata); e == nil {
			t.Fatal("inconsistent publication metadata accepted")
		}
	}
}

// These regression boundaries are already enforced by the Phase B implementation.
func TestGzipCRCAndManagedSymlinkBoundaries(t *testing.T) {
	t.Run("CRC", func(t *testing.T) {
		m, s := manager(t)
		m.Source = crcSource{s}
		if _, e := m.Reconcile(context.Background(), false); e == nil {
			t.Fatal("bad gzip CRC published")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		m, _ := manager(t)
		outside := t.TempDir()
		if e := os.Symlink(outside, filepath.Join(m.Dir, "versions")); e != nil {
			t.Skip("symlink creation unavailable on this OS/account:", e)
		}
		if _, e := m.Reconcile(context.Background(), false); e == nil {
			t.Fatal("managed symlink accepted")
		}
		entries, _ := os.ReadDir(outside)
		if len(entries) != 0 {
			t.Fatal("managed path escaped root")
		}
	})
}

type crcSource struct{ *fakeSource }

func (s crcSource) Fetch(ctx context.Context, r Release, w io.Writer) error {
	var b bytes.Buffer
	if e := s.fakeSource.Fetch(ctx, r, &b); e != nil {
		return e
	}
	data := b.Bytes()
	data[len(data)-8] ^= 0xff
	_, e := w.Write(data)
	return e
}

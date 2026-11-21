package watch

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"
	"webaudit/audit"
)

const maxStateBytes = 32 << 20

type Snapshot struct {
	Schema        int
	RulesVersion  string
	Targets       []string
	Cursors       []Cursor
	Engine        *Engine
	Notifications map[string]uint64
}
type stateEnvelope struct {
	Schema        int
	Key, Checksum string
	Data          json.RawMessage
}
type Store struct {
	Path    string
	targets []string
	key     string
	reset   bool
	unlock  func()
}

func StateDir() (string, error) {
	base := os.Getenv("XDG_STATE_HOME")
	if base != "" && !filepath.IsAbs(base) {
		return "", fmt.Errorf("XDG_STATE_HOME must be absolute")
	}
	if base == "" {
		if runtime.GOOS == "windows" {
			base = os.Getenv("LOCALAPPDATA")
			if !filepath.IsAbs(base) {
				return "", fmt.Errorf("LOCALAPPDATA must be absolute")
			}
		} else {
			home, e := os.UserHomeDir()
			if e != nil {
				return "", e
			}
			base = filepath.Join(home, ".local", "state")
		}
	}
	return filepath.Join(base, "webaudit", "watch"), nil
}
func regularPath(p string) error {
	st, e := os.Lstat(p)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("state path must be regular: %s", p)
	}
	return nil
}
func OpenStore(targets []string, key string, reset bool) (*Store, error) {
	dir, err := StateDir()
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	for p := dir; ; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e != nil {
			return nil, e
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("symlink state directory rejected")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	sorted := append([]string(nil), targets...)
	sort.Strings(sorted)
	sorted = unique(sorted)
	name := hash(strings.Join(sorted, "\x00"))
	s := &Store{Path: filepath.Join(dir, name+".json"), targets: sorted, key: key, reset: reset}
	if err = regularPath(s.Path); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(dir, name+".lock")
	if err = regularPath(lockPath); err != nil {
		return nil, err
	}
	s.unlock, err = stateLock(lockPath)
	if err != nil {
		return nil, err
	}
	// Clean only abandoned private write temporaries, never another target's checkpoint.
	if d, e := os.Open(dir); e == nil {
		entries, _ := d.ReadDir(128)
		d.Close()
		for _, v := range entries {
			if strings.HasPrefix(v.Name(), ".state-") && v.Type().IsRegular() {
				if st, e := v.Info(); e == nil && time.Since(st.ModTime()) > 24*time.Hour {
					_ = os.Remove(filepath.Join(dir, v.Name()))
				}
			}
		}
	}
	return s, nil
}
func (s *Store) Close() {
	if s.unlock != nil {
		s.unlock()
		s.unlock = nil
	}
}
func (s *Store) validate(v *Snapshot) error {
	if v == nil || v.Schema != 1 || v.RulesVersion != audit.RulesVersion || !reflect.DeepEqual(v.Targets, s.targets) || v.Engine == nil || v.Engine.Incidents == nil {
		return fmt.Errorf("incompatible watch state; use --reset-state")
	}
	if len(v.Cursors) > 4096 || len(v.Engine.Records) > 100000 || len(v.Engine.Incidents) > 10000 || len(v.Notifications) > 160000 {
		return fmt.Errorf("state collections exceed limits")
	}
	for _, c := range v.Cursors {
		if c.Offset < 0 || c.Number < 0 || len(c.Partial) > 16<<20 || !filepath.IsAbs(c.Path) || c.ID == "" {
			return fmt.Errorf("invalid file cursor")
		}
	}
	for id, i := range v.Engine.Incidents {
		if i == nil || i.Event.IncidentID != id || i.Event.Revision == 0 || i.Event.Sequence > v.Engine.Sequence || i.Event.SchemaVersion != 1 {
			return fmt.Errorf("invalid incident state")
		}
	}
	return nil
}
func (s *Store) Load() (*Snapshot, error) {
	if s.reset {
		return nil, nil
	}
	if err := regularPath(s.Path); err != nil {
		return nil, err
	}
	f, err := os.Open(s.Path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxStateBytes {
		return nil, fmt.Errorf("state exceeds size limit")
	}
	var env stateEnvelope
	if err = json.Unmarshal(b, &env); err != nil {
		return nil, fmt.Errorf("corrupt watch state: %w", err)
	}
	if env.Schema != 1 || env.Key != s.key || env.Checksum != hash(string(env.Data)) {
		return nil, fmt.Errorf("incompatible or corrupt watch state; use --reset-state")
	}
	var v Snapshot
	if err = json.Unmarshal(env.Data, &v); err != nil {
		return nil, err
	}
	if err = s.validate(&v); err != nil {
		return nil, err
	}
	return &v, nil
}
func (s *Store) Save(v *Snapshot) error {
	if err := s.validate(v); err != nil {
		return err
	}
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(data) > maxStateBytes-1024 {
		return fmt.Errorf("state exceeds size limit")
	}
	b, err := json.Marshal(stateEnvelope{Schema: 1, Key: s.key, Checksum: hash(string(data)), Data: data})
	if err != nil {
		return err
	}
	if len(b) > maxStateBytes {
		return fmt.Errorf("state exceeds size limit")
	}
	if err = regularPath(s.Path); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.Path), ".state-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err != nil {
		return err
	}
	if err = replaceState(tmp, s.Path); err != nil {
		return err
	}
	s.reset = false
	return syncStateDir(filepath.Dir(s.Path))
}
func Capture(r *Reader, e *Engine, notifications map[string]uint64) *Snapshot {
	v := &Snapshot{Schema: 1, RulesVersion: audit.RulesVersion, Targets: append([]string(nil), r.Targets...), Engine: e, Notifications: notifications}
	for _, f := range r.files {
		c := f.Cursor
		c.Partial = append([]byte(nil), c.Partial...)
		v.Cursors = append(v.Cursors, c)
	}
	return v
}
func Restore(r *Reader, e *Engine, v *Snapshot) error {
	if v == nil {
		return nil
	}
	if !reflect.DeepEqual(r.Targets, v.Targets) || len(v.Cursors) > r.o.MaxFiles || len(v.Engine.Records) > e.o.MaxEvents || len(v.Engine.Incidents) > e.o.MaxIncidents {
		return fmt.Errorf("checkpoint exceeds configured limits; use --reset-state")
	}
	for _, c := range v.Cursors {
		if len(c.Partial) > r.o.MaxLineBytes {
			return fmt.Errorf("checkpoint partial line exceeds limit")
		}
	}
	old := r.files
	r.files = nil
	for _, c := range v.Cursors {
		var f *trackedFile
		for i, x := range old {
			if x != nil && x.ID == c.ID {
				f = x
				old[i] = nil
				break
			}
		}
		if f == nil {
			f = r.findRotated(c)
		}
		if f == nil {
			r.warn("checkpoint file identity unavailable; unread rotated data may be lost")
			continue
		}
		st, err := f.file.Stat()
		if err != nil || st.Size() < c.Offset || anchor(f.file, c.Offset) != c.Anchor {
			r.warn("checkpoint content changed; restarting file from beginning")
			f.Cursor = Cursor{Path: f.Path, ID: f.ID}
		} else {
			f.Cursor = c
		}
		r.files = append(r.files, f)
	}
	// Files that appeared during downtime start at the beginning, not at EOF.
	for _, f := range old {
		if f != nil {
			f.Offset = 0
			f.Number = 0
			f.Partial = nil
			f.Anchor = ""
			f.Discard = false
			r.files = append(r.files, f)
		}
	}
	e.Records = v.Engine.Records
	e.Incidents = v.Engine.Incidents
	e.MaxTime = v.Engine.MaxTime
	e.FinalizedUntil = v.Engine.FinalizedUntil
	e.Sequence = v.Engine.Sequence
	e.dirty = false
	return nil
}
func (r *Reader) findRotated(c Cursor) *trackedFile {
	d, err := os.Open(filepath.Dir(c.Path))
	if err != nil {
		return nil
	}
	defer d.Close()
	for n := 0; n < 4096; n += 128 {
		entries, er := d.ReadDir(128)
		for _, entry := range entries {
			if !entry.Type().IsRegular() {
				continue
			}
			path := filepath.Join(filepath.Dir(c.Path), entry.Name())
			f, e := openLog(path)
			if e != nil {
				continue
			}
			id, e := fileID(f)
			if e == nil && id == c.ID {
				st, se := f.Stat()
				ls, le := os.Lstat(path)
				if se == nil && le == nil && ls.Mode()&os.ModeSymlink == 0 && os.SameFile(st, ls) {
					return &trackedFile{Cursor: Cursor{Path: c.Path, ID: id}, file: f, detached: time.Now()}
				}
			}
			f.Close()
		}
		if er != nil {
			break
		}
	}
	return nil
}

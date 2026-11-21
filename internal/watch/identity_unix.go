//go:build !windows

package watch

import (
	"fmt"
	"os"
	"syscall"
)

func fileID(f *os.File) (string, error) {
	s, e := f.Stat()
	if e != nil {
		return "", e
	}
	v, ok := s.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("file identity unavailable")
	}
	return fmt.Sprintf("%x:%x", v.Dev, v.Ino), nil
}

func openLog(path string) (*os.File, error) { return os.Open(path) }

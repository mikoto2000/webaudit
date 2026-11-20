//go:build !windows

package geoipdb

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
)

func lock(dir string) (func(), error) {
	f, e := os.OpenFile(dir+string(os.PathSeparator)+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return nil, fmt.Errorf("another GeoIP writer is running (retry after it exits): %w", e)
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}
func replaceFile(from, to string) error { return os.Rename(from, to) }

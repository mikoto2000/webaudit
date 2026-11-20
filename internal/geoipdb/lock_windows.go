//go:build windows

package geoipdb

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
)

func lock(dir string) (func(), error) {
	f, e := os.OpenFile(dir+string(os.PathSeparator)+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	var ov windows.Overlapped
	if e = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ov); e != nil {
		f.Close()
		return nil, fmt.Errorf("another GeoIP writer is running (retry after it exits): %w", e)
	}
	return func() { windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &ov); f.Close() }, nil
}
func replaceFile(from, to string) error {
	a, e := windows.UTF16PtrFromString(from)
	if e != nil {
		return e
	}
	b, e := windows.UTF16PtrFromString(to)
	if e != nil {
		return e
	}
	return windows.MoveFileEx(a, b, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

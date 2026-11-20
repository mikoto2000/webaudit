//go:build !windows

package main

import (
	"golang.org/x/sys/unix"
	"runtime"
)

func peakRSS() (uint64, error) {
	var r unix.Rusage
	if e := unix.Getrusage(unix.RUSAGE_SELF, &r); e != nil {
		return 0, e
	}
	n := uint64(r.Maxrss)
	if runtime.GOOS != "darwin" {
		n *= 1024
	}
	return n, nil
}

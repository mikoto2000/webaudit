//go:build windows

package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"unsafe"
)

func peakRSS() (uint64, error) {
	var m struct {
		CB, PageFaults                                                                                                            uint32
		PeakWorkingSet, WorkingSet, QuotaPeakPaged, QuotaPaged, QuotaPeakNonPaged, QuotaNonPaged, Pagefile, PeakPagefile, Private uintptr
	}
	m.CB = uint32(unsafe.Sizeof(m))
	proc := windows.NewLazySystemDLL("psapi.dll").NewProc("GetProcessMemoryInfo")
	r, _, e := proc.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&m)), uintptr(m.CB))
	if r == 0 {
		return 0, fmt.Errorf("GetProcessMemoryInfo: %v", e)
	}
	return uint64(m.PeakWorkingSet), nil
}

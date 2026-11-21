//go:build windows

package watch

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
)

func fileID(f *os.File) (string, error) {
	var i windows.ByHandleFileInformation
	e := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &i)
	return fmt.Sprintf("%x:%x:%x", i.VolumeSerialNumber, i.FileIndexHigh, i.FileIndexLow), e
}

func openLog(path string) (*os.File, error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	h, e := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(h), path), nil
}

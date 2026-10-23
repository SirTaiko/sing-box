//go:build windows

package main

import (
	"os"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/windows"
)

// fileAttributeTagInfo mirrors FILE_ATTRIBUTE_TAG_INFO from WinBase.h.
type fileAttributeTagInfo struct {
	FileAttributes uint32
	ReparseTag     uint32
}

// openToolOutputFile opens an existing or new output without truncating it and
// without following a final-component reparse point. FILE_FLAG_OPEN_REPARSE_POINT
// makes CreateFile acquire the directory entry itself instead of its target, so
// a symbolic link or junction installed after the Lstat guard is never followed.
// The share mode matches os.OpenFile, so ordinary concurrent access semantics
// are unchanged.
func openToolOutputFile(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, E.New("create output: invalid handle for ", path)
	}
	return file, nil
}

// verifyToolOutputHandle refuses any acquired reparse point, including a
// symbolic link, junction or mount point, before the shared caller truncates the
// descriptor. The decision is made on the object actually opened, not on a
// repeated pathname Lstat: a pathname retry cannot close the replacement
// window, while the handle identifies the object that would be truncated.
func verifyToolOutputHandle(file *os.File) error {
	var info fileAttributeTagInfo
	if err := windows.GetFileInformationByHandleEx(
		windows.Handle(file.Fd()),
		windows.FileAttributeTagInfo,
		(*byte)(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		return E.Cause(err, "inspect opened output")
	}
	if info.ReparseTag != 0 {
		return E.New("refusing to write to the reparse point opened for output")
	}
	return nil
}

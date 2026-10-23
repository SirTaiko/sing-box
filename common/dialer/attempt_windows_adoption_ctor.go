//go:build windows && go1.26 && !go1.27

package dialer

import (
	"os"
	"syscall"
	_ "unsafe"

	"golang.org/x/sys/windows"

	E "github.com/sagernet/sing/common/exceptions"
)

// adoptionCarrierName is the File name net.FileConn reports in its errors.
const adoptionCarrierName = "tcp-desync"

// netNewWindowsFile is the inspected socket-aware File constructor of the
// qualified Go toolchain. In os/file_windows.go it is declared as
//
//	//go:linkname net_newWindowsFile net.newWindowsFile
//	func net_newWindowsFile(h syscall.Handle, name string) *File
//
// and its body selects the "file+net" poll kind, so File.Close and the File
// finalizer both call closesocket instead of CloseHandle for the descriptor.
// That is the only reason this non-public symbol is referenced: the adoption
// carrier is a Winsock socket, and os.NewFile would classify it as an ordinary
// file and dispose of it with CloseHandle, which Microsoft forbids for sockets.
//
// The Go linker restricts this symbol to package net, so checked linking
// rejects this reference. The console release build already links with the
// project's unchecked-link configuration (`-checklinkname=0` in
// release/LDFLAGS and cmd/internal/build_shared); that is a blanket linker
// policy, not a per-symbol permission and not a general internal-ABI waiver.
// The Windows build therefore requires the audited Go 1.26.x toolchain; the
// exact 1.26.9 qualification gate is release/check-windows-adoption-go.py.
//
//go:linkname netNewWindowsFile net.newWindowsFile
func netNewWindowsFile(handle syscall.Handle, name string) *os.File

// newSocketAdoptionFile constructs the socket-aware carrier File for the single
// net.FileConn adoption. The hidden constructor panics on an invalid handle, so
// the handle is validated first; on rejection the caller still owns the carrier
// and retires it with closesocket.
func newSocketAdoptionFile(handle windows.Handle) (adoptionFile, error) {
	if handle == 0 || handle == windows.InvalidHandle {
		return nil, E.New("desync: adoption carrier handle is invalid")
	}
	return &osAdoptionFile{file: netNewWindowsFile(syscall.Handle(handle), adoptionCarrierName)}, nil
}

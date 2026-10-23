//go:build windows && (!go1.26 || go1.27)

package dialer

// A Windows build requires the audited Go 1.26.x toolchain. The socket-aware
// adoption constructor, its FileConn duplication-error propagation and the
// IOCP/finalizer contract were inspected and qualified only for the exact
// Go1.26.9 release (see docs/configuration/direct-desync-socks-build.md and
// release/check-windows-adoption-go.py).
//
// The reference below makes such a build fail closed with
// "undefined: newSocketAdoptionFile" instead of compiling a generic os.NewFile
// fallback, whose Close and finalizer would dispose of a Winsock descriptor
// with CloseHandle. This is a compile-time refusal, not a runtime plaintext
// fallback: there is no supported Windows build outside the qualified
// toolchain, including configurations that disable desync at runtime.
var _ = newSocketAdoptionFile

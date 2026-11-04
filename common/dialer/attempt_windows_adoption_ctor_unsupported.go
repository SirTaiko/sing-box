//go:build windows && (!go1.26 || go1.27)

package dialer

// A Windows build requires the audited Go 1.26.x toolchain. The direct-owned
// adoption bridge, its five exact net.newFD/init/setAddr/Close/newTCPConn
// symbols and the IOCP/finalizer contract were inspected and qualified only for
// the exact Go1.26.9 release (see docs/configuration/direct-desync-socks-build.md
// and release/check-windows-adoption-go.py).
//
// The reference below makes such a build fail closed with
// "undefined: newOwnedSocketConn" instead of compiling a generic FileConn/os.File
// fallback. This is a compile-time refusal, not a runtime plaintext fallback:
// there is no supported Windows build outside the qualified toolchain,
// including configurations that disable desync at runtime.
var _ = newOwnedSocketConn

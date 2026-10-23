//go:build !linux && !windows

package desync

import (
	"net"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// Other platforms compile the stream subsystem but do not claim tpws native
// socket applicability. Native-only knobs are rejected at compile time rather
// than accepted as no-ops; ordinary HTTP/TLS/split stream transformation still
// works through plain TCP writes. Target platforms are Ubuntu and Windows.

func platformStreamCaps() streamCapsInfo {
	return streamCapsInfo{}
}

func newPlatformStreamNative() streamNative {
	return unsupportedStreamNative{}
}

type unsupportedStreamNative struct{}

func (unsupportedStreamNative) Prepare(uintptr, streamSocketConfig) error {
	return E.New("desync: native stream socket controls are not implemented on this platform")
}

func (unsupportedStreamNative) NewSender(net.Conn, func() time.Time) (streamSender, error) {
	return nil, E.New("desync: native stream send is not implemented on this platform")
}

var _ streamSender = (*plainSender)(nil)
var _ streamNative = unsupportedStreamNative{}

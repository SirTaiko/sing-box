//go:build linux

package direct

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/common/desync"
	"github.com/sagernet/sing-box/common/dialer"
	M "github.com/sagernet/sing/common/metadata"

	"golang.org/x/sys/unix"
)

// TestCombinedPrepareSocketOrdersPacketBindBeforeStreamControls exercises the
// real Linux packet lease preparation (exclusive bind + capture) and the
// stream preconnect controls on one dialer-owned fd. The stream seam checks
// that the packet bind happened first; reversing the order makes it fail.
func TestCombinedPrepareSocketOrdersPacketBindBeforeStreamControls(t *testing.T) {
	backend := &countingBackend{}
	engine, err := desync.NewEngine(testPacketConfig(t), backend)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	fake := &fakeStreamAttachment{}
	boundBeforeStream := false
	fake.prepare = func(preparedFD uintptr) error {
		sockaddr, err := unix.Getsockname(int(preparedFD))
		if err != nil {
			return err
		}
		inet4, isIPv4 := sockaddr.(*unix.SockaddrInet4)
		if !isIPv4 {
			return errors.New("unexpected local endpoint family")
		}
		boundBeforeStream = inet4.Port != 0
		return nil
	}
	hook := &desyncHook{engine: engine, stream: fake, lifetime: context.Background()}
	lease, err := hook.NewAttempt(context.Background(), dialer.AttemptIntent{
		Network:     "tcp",
		Destination: M.SocksaddrFrom(netip.MustParseAddr("203.0.113.11"), 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !lease.RequiresExclusiveBind() {
		t.Fatal("combined attempt must own the exclusive bind")
	}
	if err = lease.PrepareSocket(uintptr(fd)); err != nil {
		t.Fatal(err)
	}
	if !boundBeforeStream {
		t.Fatal("stream PrepareSocket ran before the packet lease bound the socket")
	}
	if prepares, _ := fake.counts(); prepares != 1 {
		t.Fatalf("stream PrepareSocket calls = %d, want 1", prepares)
	}
	if backend.opened.Load() != 1 {
		t.Fatalf("capture opened %d times", backend.opened.Load())
	}
	// The dialer keeps fd ownership: preparation must not close it.
	if _, err = unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE); err != nil {
		t.Fatalf("PrepareSocket closed the dialer-owned fd: %v", err)
	}
	if err = lease.Close(nil); err != nil {
		t.Fatal(err)
	}
	if backend.closed.Load() != 1 {
		t.Fatalf("capture closed %d times", backend.closed.Load())
	}
}

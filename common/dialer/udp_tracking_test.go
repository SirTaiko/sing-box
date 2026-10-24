package dialer

// A packet-desync attempt lease wraps the native connected UDP transport before
// the dialer applies its UDP read tracking, so the tracking decision must use
// the native-socket capability instead of a concrete *net.UDPConn assertion.
// These regressions are hermetic: the platform native attempt is replaced by an
// owned in-memory transport, so no host socket exists.

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type udpTrackingRawConn struct{}

func (udpTrackingRawConn) Control(func(uintptr)) error    { return nil }
func (udpTrackingRawConn) Read(func(uintptr) bool) error  { return nil }
func (udpTrackingRawConn) Write(func(uintptr) bool) error { return nil }

// udpTrackingTransport is the owned byte transport of one hermetic native
// attempt. It also carries the native socket capability that an owning lease
// wrapper forwards from the transport it wraps.
type udpTrackingTransport struct {
	net.Conn
	closes atomic.Int32
	raw    syscall.RawConn
}

func (c *udpTrackingTransport) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

func (c *udpTrackingTransport) SyscallConn() (syscall.RawConn, error) {
	return c.raw, nil
}

// udpTrackingPlainConn hides the concrete transport exactly like the plain
// byte-transport fixtures of the attachment tests: it exposes no native socket.
type udpTrackingPlainConn struct{ net.Conn }

// udpTrackingBrokenConn advertises the native socket capability without a
// usable descriptor, so the tracking wrapper cannot be applied to it.
type udpTrackingBrokenConn struct {
	net.Conn
	lease *udpTrackingLease
	once  sync.Once
	err   error
}

func (c *udpTrackingBrokenConn) SyscallConn() (syscall.RawConn, error) {
	return nil, errors.New("fixture: no native socket")
}

func (c *udpTrackingBrokenConn) Close() error {
	c.once.Do(func() {
		c.err = errors.Join(c.Conn.Close(), c.lease.leaseClose())
	})
	return c.err
}

// udpTrackingLeaseConn models protocol/direct's leaseUDPConn: it hides the
// concrete transport behind the attempt lease owner, forwards the native socket
// capability and closes the transport and the lease exactly once.
type udpTrackingLeaseConn struct {
	net.Conn
	lease *udpTrackingLease
	once  sync.Once
	err   error
}

func (c *udpTrackingLeaseConn) SyscallConn() (syscall.RawConn, error) {
	syscallConn, isSyscallConn := c.Conn.(syscall.Conn)
	if !isSyscallConn {
		return nil, errors.New("fixture: lease transport has no native socket")
	}
	return syscallConn.SyscallConn()
}

func (c *udpTrackingLeaseConn) Close() error {
	c.once.Do(func() {
		c.err = errors.Join(c.Conn.Close(), c.lease.leaseClose())
	})
	return c.err
}

type udpTrackingHook struct {
	leases   atomic.Int32
	closed   atomic.Int32
	attached atomic.Int32
	attach   func(*udpTrackingLease, net.Conn) (net.Conn, error)
}

func (h *udpTrackingHook) NewAttempt(context.Context, AttemptIntent) (AttemptLease, error) {
	h.leases.Add(1)
	return &udpTrackingLease{hook: h}, nil
}

type udpTrackingLease struct {
	hook     *udpTrackingHook
	closures atomic.Int32
}

func (*udpTrackingLease) PrepareSocket(uintptr) error    { return nil }
func (*udpTrackingLease) RequiresExclusiveBind() bool    { return true }
func (*udpTrackingLease) SetLocalAddress(netip.AddrPort) {}
func (*udpTrackingLease) StartCapture() error            { return nil }

func (l *udpTrackingLease) AttachConn(conn net.Conn) (net.Conn, error) {
	l.hook.attached.Add(1)
	if l.hook.attach != nil {
		return l.hook.attach(l, conn)
	}
	return conn, nil
}

func (*udpTrackingLease) AttachPacketConn(conn net.PacketConn) net.PacketConn { return conn }

// leaseClose is owned by the returned transport, exactly like the production
// lease wrapper. The attempt-level Close below is the failed-attempt control and
// must never run for a successful dial.
func (l *udpTrackingLease) leaseClose() error {
	l.closures.Add(1)
	return nil
}

func (l *udpTrackingLease) Close(error) error {
	l.hook.closed.Add(1)
	return nil
}

type udpTrackingManager struct {
	tracked net.Conn
}

func (*udpTrackingManager) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (*udpTrackingManager) Count() int                                     { return 0 }
func (*udpTrackingManager) CloseAll()                                      {}
func (m *udpTrackingManager) TrackConn(conn net.Conn) net.Conn {
	m.tracked = conn
	return conn
}
func (*udpTrackingManager) TrackPacketConn(conn net.PacketConn) net.PacketConn { return conn }
func (*udpTrackingManager) NewConnection(context.Context, N.Dialer, net.Conn, adapter.InboundContext, N.CloseHandlerFunc) {
}
func (*udpTrackingManager) NewPacketConnection(context.Context, N.Dialer, N.PacketConn, adapter.InboundContext, N.CloseHandlerFunc) {
}

type udpTrackingFixture struct {
	dialer    *DefaultDialer
	hook      *udpTrackingHook
	transport *udpTrackingTransport
	peer      net.Conn
}

func newUDPTrackingFixture(t *testing.T) *udpTrackingFixture {
	t.Helper()
	client, peer := net.Pipe()
	fixture := &udpTrackingFixture{
		hook:      &udpTrackingHook{},
		transport: &udpTrackingTransport{Conn: client, raw: udpTrackingRawConn{}},
		peer:      peer,
	}
	fixture.dialer = &DefaultDialer{attemptHook: fixture.hook}
	previousAttempt := dialNativeAttempt
	dialNativeAttempt = func(context.Context, net.Dialer, string, string, AttemptLease) (net.Conn, error) {
		return fixture.transport, nil
	}
	t.Cleanup(func() {
		dialNativeAttempt = previousAttempt
		_ = peer.Close()
	})
	return fixture
}

func (f *udpTrackingFixture) dial(t *testing.T, network string) (net.Conn, error) {
	t.Helper()
	return f.dialer.DialContext(context.Background(), network, M.SocksaddrFrom(netip.MustParseAddr("198.51.100.20"), 443))
}

// TestConnectedUDPAttemptKeepsDialerTracking is the QA361-D1 regression: a
// connected UDP dial that returns an owning lease wrapper must still reach the
// dialer's UDP tracking wrapper, with the lease owner left in place as the
// lifecycle owner.
func TestConnectedUDPAttemptKeepsDialerTracking(t *testing.T) {
	t.Run("packet-lease-owner", func(t *testing.T) {
		fixture := newUDPTrackingFixture(t)
		var leaseConn *udpTrackingLeaseConn
		fixture.hook.attach = func(lease *udpTrackingLease, conn net.Conn) (net.Conn, error) {
			leaseConn = &udpTrackingLeaseConn{Conn: conn, lease: lease}
			return leaseConn, nil
		}
		conn, err := fixture.dial(t, "udp")
		if err != nil {
			t.Fatalf("connected UDP dial: %v", err)
		}
		tracked, isTracked := conn.(*udpConn)
		if !isTracked {
			t.Fatalf("connected UDP transport %T lost the dialer tracking wrapper: UDP EOF emulation and Upstream/ReaderReplaceable are skipped", conn)
		}
		if upstream := tracked.Upstream(); upstream != leaseConn {
			t.Fatalf("tracking wrapper upstream = %T, want the lease owner", upstream)
		}
		if !tracked.ReaderReplaceable() || !tracked.WriterReplaceable() {
			t.Fatal("tracking wrapper is not reader/writer replaceable")
		}
		rawConn, rawErr := tracked.SyscallConn()
		if rawErr != nil || rawConn != fixture.transport.raw {
			t.Fatalf("native socket capability lost: raw=%v err=%v", rawConn, rawErr)
		}
		written := make(chan error, 1)
		go func() {
			_, writeErr := fixture.peer.Write([]byte("abc"))
			written <- writeErr
		}()
		buffer := make([]byte, 8)
		read, readErr := tracked.Read(buffer)
		if writeErr := <-written; writeErr != nil {
			t.Fatal(writeErr)
		}
		if readErr != nil || read != 3 || string(buffer[:read]) != "abc" {
			t.Fatalf("tracked read = %d, %v, %q", read, readErr, buffer[:read])
		}
		if err = tracked.Close(); err != nil {
			t.Fatalf("close tracked transport: %v", err)
		}
		if fixture.transport.closes.Load() != 1 {
			t.Fatalf("native transport closes = %d, want 1", fixture.transport.closes.Load())
		}
		if leaseConn.lease.closures.Load() != 1 {
			t.Fatalf("lease closes = %d, want 1", leaseConn.lease.closures.Load())
		}
		if fixture.hook.closed.Load() != 0 {
			t.Fatalf("attempt-level lease close ran %d times for a returned transport", fixture.hook.closed.Load())
		}
		if err = tracked.Close(); err != nil {
			t.Fatalf("repeat close: %v", err)
		}
		if fixture.transport.closes.Load() != 1 || leaseConn.lease.closures.Load() != 1 {
			t.Fatal("repeat close released the transport or the lease twice")
		}
		if fixture.hook.attached.Load() != 1 || fixture.hook.leases.Load() != 1 {
			t.Fatalf("attempt composition: leases=%d attached=%d", fixture.hook.leases.Load(), fixture.hook.attached.Load())
		}
	})

	t.Run("plain-transport", func(t *testing.T) {
		fixture := newUDPTrackingFixture(t)
		conn, err := fixture.dial(t, "udp")
		if err != nil {
			t.Fatalf("connected UDP dial: %v", err)
		}
		tracked, isTracked := conn.(*udpConn)
		if !isTracked {
			t.Fatalf("UDP transport %T with a native socket was not tracked", conn)
		}
		if upstream := tracked.Upstream(); upstream != fixture.transport {
			t.Fatalf("tracking wrapper upstream = %T, want the transport", upstream)
		}
		if err = tracked.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		if fixture.transport.closes.Load() != 1 || fixture.hook.closed.Load() != 0 {
			t.Fatalf("transport closes = %d, attempt-level closes = %d", fixture.transport.closes.Load(), fixture.hook.closed.Load())
		}
	})

	t.Run("no-native-socket", func(t *testing.T) {
		fixture := newUDPTrackingFixture(t)
		var plain *udpTrackingPlainConn
		fixture.hook.attach = func(_ *udpTrackingLease, conn net.Conn) (net.Conn, error) {
			plain = &udpTrackingPlainConn{Conn: conn}
			return plain, nil
		}
		conn, err := fixture.dial(t, "udp")
		if err != nil {
			t.Fatalf("connected UDP dial: %v", err)
		}
		if conn != plain {
			t.Fatalf("transport without a native socket was wrapped: %T", conn)
		}
		if err = conn.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		if fixture.transport.closes.Load() != 1 {
			t.Fatalf("native transport closes = %d, want 1", fixture.transport.closes.Load())
		}
	})

	t.Run("native-socket-error", func(t *testing.T) {
		fixture := newUDPTrackingFixture(t)
		var broken *udpTrackingBrokenConn
		fixture.hook.attach = func(lease *udpTrackingLease, conn net.Conn) (net.Conn, error) {
			broken = &udpTrackingBrokenConn{Conn: conn, lease: lease}
			return broken, nil
		}
		conn, err := fixture.dial(t, "udp")
		if err == nil {
			t.Fatal("a UDP transport that cannot expose its native socket was returned as tracked")
		}
		if conn != nil {
			t.Fatalf("failed tracking returned a connection: %T", conn)
		}
		if fixture.transport.closes.Load() != 1 || broken.lease.closures.Load() != 1 {
			t.Fatalf("terminal tracking failure did not release the transport and its lease: transport=%d lease=%d",
				fixture.transport.closes.Load(), broken.lease.closures.Load())
		}
	})

	t.Run("tcp-network", func(t *testing.T) {
		fixture := newUDPTrackingFixture(t)
		conn, err := fixture.dial(t, "tcp")
		if err != nil {
			t.Fatalf("TCP dial: %v", err)
		}
		if conn != fixture.transport {
			t.Fatalf("TCP attempt was wrapped as a connected UDP transport: %T", conn)
		}
		if err = conn.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	})

	t.Run("connection-manager", func(t *testing.T) {
		fixture := newUDPTrackingFixture(t)
		manager := &udpTrackingManager{}
		fixture.dialer.connectionManager = manager
		fixture.hook.attach = func(lease *udpTrackingLease, conn net.Conn) (net.Conn, error) {
			return &udpTrackingLeaseConn{Conn: conn, lease: lease}, nil
		}
		conn, err := fixture.dial(t, "udp")
		if err != nil {
			t.Fatalf("connected UDP dial: %v", err)
		}
		if conn != manager.tracked {
			t.Fatalf("connection manager tracked %T, want the returned transport", manager.tracked)
		}
		if _, isTracked := manager.tracked.(*udpConn); !isTracked {
			t.Fatalf("connection manager tracked %T instead of the UDP tracking wrapper", manager.tracked)
		}
		if err = conn.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	})
}

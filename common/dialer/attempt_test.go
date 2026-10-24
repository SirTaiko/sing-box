package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/database64128/tfo-go/v2"
)

func TestDialContextUsesAttemptHook(t *testing.T) {
	hook := &countHook{}
	dialer := &DefaultDialer{attemptHook: hook}
	destination := M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), 1)
	_, err := dialer.DialContext(context.Background(), "tcp", destination)
	if err == nil {
		t.Fatal("expected connection refusal")
	}
	if hook.leases.Load() != 1 {
		t.Fatalf("leases = %d", hook.leases.Load())
	}
	if hook.prepared.Load() != 1 {
		t.Fatalf("prepare called %d times", hook.prepared.Load())
	}
	if hook.closed.Load() != 1 {
		t.Fatalf("failed attempt lease was not closed: %d", hook.closed.Load())
	}
	// The enabled Windows ConnectEx path takes the admission reference before
	// any native effect and releases it exactly once; every platform must
	// balance whatever it acquired.
	if C.IsWindows && hook.holds.Load() != 1 {
		t.Fatalf("native hold acquisitions = %d, want 1", hook.holds.Load())
	}
	if hook.releases.Load() != hook.holds.Load() {
		t.Fatalf("native holds not balanced: acquired=%d released=%d", hook.holds.Load(), hook.releases.Load())
	}
}

func TestListenPacketUsesAttemptHook(t *testing.T) {
	hook := &countHook{}
	dialer := &DefaultDialer{attemptHook: hook}
	conn, err := dialer.ListenPacket(context.Background(), M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), 53))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if hook.leases.Load() != 1 {
		t.Fatalf("leases = %d", hook.leases.Load())
	}
	if hook.started.Load() != 1 {
		t.Fatalf("capture started %d times", hook.started.Load())
	}
	if hook.attached.Load() != 1 {
		t.Fatalf("packet conn attached %d times", hook.attached.Load())
	}
}

// TestDialContextWithoutHookKeepsDeferredTFO pins the exact ordinary direct
// path: with no attempt hook, TCP uses the deferred TFO dialer, so a dial to a
// closed port returns a lazy connection instead of failing eagerly.
func TestDialContextWithoutHookKeepsDeferredTFO(t *testing.T) {
	dialer := &DefaultDialer{
		dialer4: tfo.Dialer{Dialer: net.Dialer{}},
		dialer6: tfo.Dialer{Dialer: net.Dialer{}},
	}
	conn, err := dialer.DialContext(context.Background(), "tcp", M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), 1))
	if err != nil {
		t.Fatalf("deferred TFO path connected eagerly: %v", err)
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDialContextAttachFailureIsTerminal(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
	}()
	hook := &countHook{attachErr: errors.New("stream wrapper rejected the connection")}
	dialer := &DefaultDialer{attemptHook: hook}
	destination := M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), uint16(listener.Addr().(*net.TCPAddr).Port))
	conn, err := dialer.DialContext(context.Background(), "tcp", destination)
	if err == nil {
		t.Fatal("an attachment failure must fail the dial")
	}
	if conn != nil {
		t.Fatal("an attachment failure must not return the unwrapped connection")
	}
	if hook.connAttached.Load() != 1 {
		t.Fatalf("AttachConn calls = %d", hook.connAttached.Load())
	}
	if hook.closed.Load() != 1 {
		t.Fatalf("failed lease closed %d times", hook.closed.Load())
	}
	if C.IsWindows && hook.holds.Load() != 1 {
		t.Fatalf("native hold acquisitions = %d, want 1", hook.holds.Load())
	}
	if hook.releases.Load() != hook.holds.Load() {
		t.Fatalf("native holds not balanced: acquired=%d released=%d", hook.holds.Load(), hook.releases.Load())
	}
}

func TestSerialNetworkClosesLoserLease(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	hook := &countHook{
		// The loser is a distinct loopback destination whose attempt is
		// refused during preparation. This is deterministic on every target:
		// the test does not depend on the platform routing or refusing a
		// particular 127/8 address, while the successful attempt still uses a
		// real loopback listener and the real native dial path.
		prepareErrAddr: netip.MustParseAddr("127.0.0.2"),
		prepareErr:     errors.New("fixture: loser attempt preparation refused"),
	}
	dialer := &DefaultDialer{attemptHook: hook}
	destination := M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), uint16(listener.Addr().(*net.TCPAddr).Port))
	conn, err := DialSerialNetwork(context.Background(), dialer, "tcp", destination,
		[]netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.1")},
		nil, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if hook.leases.Load() != 2 {
		t.Fatalf("leases = %d, want one per address attempt", hook.leases.Load())
	}
	if hook.prepared.Load() != 2 {
		t.Fatalf("prepared attempts = %d, want both address attempts", hook.prepared.Load())
	}
	if hook.closed.Load() != 1 {
		t.Fatalf("loser leases closed = %d, want 1", hook.closed.Load())
	}
	if hook.connAttached.Load() != 1 {
		t.Fatalf("successful attempts attached = %d, want 1", hook.connAttached.Load())
	}
	if C.IsWindows && hook.holds.Load() != 2 {
		t.Fatalf("native hold acquisitions = %d, want one per attempt", hook.holds.Load())
	}
	if hook.releases.Load() != hook.holds.Load() {
		t.Fatalf("native holds not balanced: acquired=%d released=%d", hook.holds.Load(), hook.releases.Load())
	}
}

type fakeInterfaceMonitor struct {
	tun.DefaultInterfaceMonitor
	defaultInterface *control.Interface
}

func (m *fakeInterfaceMonitor) DefaultInterface() *control.Interface { return m.defaultInterface }

func (m *fakeInterfaceMonitor) MyInterfaces() []string { return nil }

type fakeNetworkManager struct {
	adapter.NetworkManager
	interfaces []adapter.NetworkInterface
	monitor    tun.DefaultInterfaceMonitor
}

func (m *fakeNetworkManager) NetworkInterfaces() []adapter.NetworkInterface { return m.interfaces }

func (m *fakeNetworkManager) InterfaceMonitor() tun.DefaultInterfaceMonitor { return m.monitor }

// TestParallelInterfaceLosersCloseTheirLeases covers the parallel-interface
// racer path: every racer owns a lease, the successful one attaches exactly
// once and a failing fallback racer releases its lease.
func TestParallelInterfaceLosersCloseTheirLeases(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
	}()
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("loopback interface is unavailable")
	}
	primary := adapter.NetworkInterface{Interface: control.Interface{Index: loopback.Index, Name: loopback.Name}}
	// An empty name with index -1 is rejected by control.BindToInterface0
	// before connect, so the fallback racer deterministically fails.
	fallback := adapter.NetworkInterface{Interface: control.Interface{Index: -1}}
	hook := &countHook{}
	dialer := &DefaultDialer{
		attemptHook: hook,
		networkManager: &fakeNetworkManager{
			interfaces: []adapter.NetworkInterface{primary, fallback},
			monitor:    &fakeInterfaceMonitor{defaultInterface: &control.Interface{Index: loopback.Index, Name: loopback.Name}},
		},
		dialer4: tfo.Dialer{Dialer: net.Dialer{}},
		dialer6: tfo.Dialer{Dialer: net.Dialer{}},
	}
	conn, isPrimary, err := dialer.dialParallelInterfaceFastFallback(context.Background(), net.Dialer{}, "tcp",
		listener.Addr().String(), C.NetworkStrategyFallback, nil, nil, 0, func(time.Time) {})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !isPrimary {
		t.Fatal("the default interface racer must win")
	}
	deadline := time.Now().Add(3 * time.Second)
	for hook.closed.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if hook.leases.Load() != 2 {
		t.Fatalf("leases = %d, want one per racer (closed=%d attached=%d)", hook.leases.Load(), hook.closed.Load(), hook.connAttached.Load())
	}
	if hook.closed.Load() != 1 {
		t.Fatalf("losing racer leases closed = %d, want 1 (leases=%d attached=%d prepared=%d)", hook.closed.Load(), hook.leases.Load(), hook.connAttached.Load(), hook.prepared.Load())
	}
	if hook.connAttached.Load() != 1 {
		t.Fatalf("winning racer attachments = %d, want 1", hook.connAttached.Load())
	}
}

type countHook struct {
	leases       atomic.Int32
	prepared     atomic.Int32
	closed       atomic.Int32
	started      atomic.Int32
	attached     atomic.Int32
	connAttached atomic.Int32
	holds        atomic.Int32
	releases     atomic.Int32
	attachErr    error
	// prepareErrAddr makes one specific attempt destination fail at
	// PrepareSocket. It is the platform-independent way to obtain a failed
	// serial attempt: the fixture never relies on the target OS routing or
	// refusing a particular loopback address.
	prepareErrAddr netip.Addr
	prepareErr     error
}

func (h *countHook) NewAttempt(ctx context.Context, intent AttemptIntent) (AttemptLease, error) {
	h.leases.Add(1)
	return &countLease{
		hook:         h,
		failPrepare:  h.prepareErrAddr.IsValid() && intent.Destination.Addr == h.prepareErrAddr,
		prepareError: h.prepareErr,
	}, nil
}

type countLease struct {
	hook         *countHook
	failPrepare  bool
	prepareError error
}

func (l *countLease) PrepareSocket(fd uintptr) error {
	l.hook.prepared.Add(1)
	if l.failPrepare {
		if l.prepareError != nil {
			return l.prepareError
		}
		return errors.New("fixture: attempt preparation failed")
	}
	return nil
}

func (l *countLease) SetLocalAddress(address netip.AddrPort) {}

func (l *countLease) StartCapture() error {
	l.hook.started.Add(1)
	return nil
}

func (l *countLease) RequiresExclusiveBind() bool { return true }

// AcquireNativeHold is the faithful test admission capability of this fixture
// lease. The real enabled Windows ConnectEx path takes one admission
// reference before any socket/event/OVERLAPPED exists and releases it exactly
// once after the native operation reaches its terminal state; the fixture
// counts both directions through an idempotent release.
func (l *countLease) AcquireNativeHold() (func(), error) {
	l.hook.holds.Add(1)
	var once sync.Once
	return func() {
		once.Do(func() { l.hook.releases.Add(1) })
	}, nil
}

func (l *countLease) AttachConn(conn net.Conn) (net.Conn, error) {
	l.hook.connAttached.Add(1)
	if l.hook.attachErr != nil {
		return nil, l.hook.attachErr
	}
	return conn, nil
}

func (l *countLease) AttachPacketConn(conn net.PacketConn) net.PacketConn {
	l.hook.attached.Add(1)
	return conn
}

func (l *countLease) Close(reason error) error {
	l.hook.closed.Add(1)
	return nil
}

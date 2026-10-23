package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
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
}

func TestSerialNetworkClosesLoserLease(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	hook := &countHook{}
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
	if hook.closed.Load() != 1 {
		t.Fatalf("loser leases closed = %d, want 1", hook.closed.Load())
	}
	if hook.connAttached.Load() != 1 {
		t.Fatalf("successful attempts attached = %d, want 1", hook.connAttached.Load())
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
	attachErr    error
}

func (h *countHook) NewAttempt(ctx context.Context, intent AttemptIntent) (AttemptLease, error) {
	h.leases.Add(1)
	return &countLease{hook: h}, nil
}

type countLease struct {
	hook *countHook
}

func (l *countLease) PrepareSocket(fd uintptr) error {
	l.hook.prepared.Add(1)
	return nil
}

func (l *countLease) SetLocalAddress(address netip.AddrPort) {}

func (l *countLease) StartCapture() error {
	l.hook.started.Add(1)
	return nil
}

func (l *countLease) RequiresExclusiveBind() bool { return true }

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

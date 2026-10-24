package direct

// R354-UDP1: a returned packet-enabled UDP transport owns the close of the
// attempt's existing lease. These regressions are memory-only: the real
// Engine, the real installed bridge and real lease/capture lifecycle run with
// a counting fake backend, while net.Pipe and no-I/O fixtures stand in for the
// returned transports. No host socket, DNS or injection is used.

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/desync"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

type udpLifetimeConn struct {
	net.Conn
	closes   atomic.Int32
	closeErr error
}

func (c *udpLifetimeConn) Close() error {
	c.closes.Add(1)
	if c.closeErr != nil {
		return c.closeErr
	}
	return c.Conn.Close()
}

type udpLifetimePacket struct {
	closes   atomic.Int32
	closeErr error
}

func (p *udpLifetimePacket) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("fixture: no packet IO")
}

func (p *udpLifetimePacket) WriteTo([]byte, net.Addr) (int, error) {
	return 0, errors.New("fixture: no packet IO")
}

func (p *udpLifetimePacket) Close() error {
	p.closes.Add(1)
	return p.closeErr
}

func (p *udpLifetimePacket) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 40000}
}

func (p *udpLifetimePacket) SetDeadline(time.Time) error      { return nil }
func (p *udpLifetimePacket) SetReadDeadline(time.Time) error  { return nil }
func (p *udpLifetimePacket) SetWriteDeadline(time.Time) error { return nil }

type udpLifetimeRawConn struct{}

func (udpLifetimeRawConn) Control(func(uintptr)) error    { return nil }
func (udpLifetimeRawConn) Read(func(uintptr) bool) error  { return nil }
func (udpLifetimeRawConn) Write(func(uintptr) bool) error { return nil }

// udpLifetimeSyscallConn advertises a native socket capability, so the wrapper
// forwarding can be asserted without a host descriptor.
type udpLifetimeSyscallConn struct {
	net.Conn
}

func (udpLifetimeSyscallConn) SyscallConn() (syscall.RawConn, error) {
	return udpLifetimeRawConn{}, nil
}

func newUDPLeaseEngine(t *testing.T, maxLeases int, rules ...option.DirectDesyncRule) (*desync.Engine, *desyncHook, *countingBackend) {
	t.Helper()
	config, err := desync.Compile(&option.DirectDesyncOptions{Rules: rules}, "")
	if err != nil {
		t.Fatalf("desync.Compile: %v", err)
	}
	config.Limits.MaxLeases = maxLeases
	backend := &countingBackend{}
	engine, err := desync.NewEngine(config, backend)
	if err != nil {
		t.Fatalf("desync.NewEngine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	return engine, &desyncHook{engine: engine, lifetime: context.Background()}, backend
}

func packetUDPAttempt(t *testing.T, hook *desyncHook, listener bool) *desyncLease {
	t.Helper()
	intent := dialer.AttemptIntent{
		Network:     "udp",
		Destination: M.SocksaddrFrom(netip.MustParseAddr("198.51.100.20"), 443),
	}
	if listener {
		intent.Destination = M.Socksaddr{}
		intent.Source = netip.MustParseAddrPort("192.0.2.1:40000")
	}
	lease, err := hook.NewAttempt(context.Background(), intent)
	if err != nil {
		t.Fatalf("NewAttempt: %v", err)
	}
	if err = lease.StartCapture(); err != nil {
		t.Fatalf("StartCapture: %v", err)
	}
	return lease.(*desyncLease)
}

// TestPacketUDPReturnedTransportOwnsLease is the core R354-UDP1 regression:
// both returned UDP transports must discharge the already charged packet lease
// and its capture when they are closed, and must return the admission capacity.
func TestPacketUDPReturnedTransportOwnsLease(t *testing.T) {
	for _, listener := range []bool{false, true} {
		name := "connected"
		if listener {
			name = "listener"
		}
		t.Run(name, func(t *testing.T) {
			engine, hook, backend := newUDPLeaseEngine(t, 1, option.DirectDesyncRule{Network: []string{"udp"}, Methods: []string{}})
			lease := packetUDPAttempt(t, hook, listener)
			if backend.opened.Load() != 1 || engine.ActiveLeases() != 1 {
				t.Fatalf("attempt not admitted/opened: opened=%d charged=%d", backend.opened.Load(), engine.ActiveLeases())
			}
			if listener {
				raw := &udpLifetimePacket{}
				returned := lease.AttachPacketConn(raw)
				if returned == net.PacketConn(raw) {
					t.Fatal("listener AttachPacketConn returned the raw transport without a lease owner")
				}
				if err := returned.Close(); err != nil {
					t.Fatalf("returned listener Close: %v", err)
				}
				if raw.closes.Load() != 1 {
					t.Fatalf("raw listener closed %d times, want 1", raw.closes.Load())
				}
			} else {
				client, peer := net.Pipe()
				defer peer.Close()
				raw := &udpLifetimeConn{Conn: client}
				returned, err := lease.AttachConn(raw)
				if err != nil {
					t.Fatalf("AttachConn: %v", err)
				}
				if returned == net.Conn(raw) {
					t.Fatal("connected UDP AttachConn returned the raw transport without a lease owner")
				}
				if err = returned.Close(); err != nil {
					t.Fatalf("returned connection Close: %v", err)
				}
				if raw.closes.Load() != 1 {
					t.Fatalf("raw connection closed %d times, want 1", raw.closes.Load())
				}
			}
			if closed := backend.closed.Load(); closed != 1 {
				t.Fatalf("returned Close left the capture open: closes=%d", closed)
			}
			if charged := engine.ActiveLeases(); charged != 0 {
				t.Fatalf("returned Close left %d charged lease(s)", charged)
			}
			next, err := hook.NewAttempt(context.Background(), dialer.AttemptIntent{
				Network:     "tcp",
				Destination: M.SocksaddrFrom(netip.MustParseAddr("198.51.100.21"), 443),
			})
			if err != nil {
				t.Fatalf("closed UDP transport did not return admission capacity: %v", err)
			}
			if err = next.Close(nil); err != nil {
				t.Fatalf("replacement lease Close: %v", err)
			}
		})
	}
}

// TestPacketUDPReturnedCloseIsExactlyOnce covers repeated and concurrent Close
// of the returned transport: the native transport and the lease are released
// once, and every call reports success.
func TestPacketUDPReturnedCloseIsExactlyOnce(t *testing.T) {
	t.Run("repeat", func(t *testing.T) {
		engine, hook, backend := newUDPLeaseEngine(t, 1, option.DirectDesyncRule{Network: []string{"udp"}, Methods: []string{}})
		lease := packetUDPAttempt(t, hook, true)
		raw := &udpLifetimePacket{}
		returned := lease.AttachPacketConn(raw)
		if err := returned.Close(); err != nil {
			t.Fatalf("first Close: %v", err)
		}
		if err := returned.Close(); err != nil {
			t.Fatalf("repeated Close: %v", err)
		}
		if raw.closes.Load() != 1 || backend.closed.Load() != 1 {
			t.Fatalf("repeated Close released twice: raw=%d capture=%d", raw.closes.Load(), backend.closed.Load())
		}
		if engine.ActiveLeases() != 0 {
			t.Fatalf("repeated Close left %d charged lease(s)", engine.ActiveLeases())
		}
	})
	t.Run("concurrent", func(t *testing.T) {
		engine, hook, backend := newUDPLeaseEngine(t, 1, option.DirectDesyncRule{Network: []string{"udp"}, Methods: []string{}})
		lease := packetUDPAttempt(t, hook, true)
		raw := &udpLifetimePacket{}
		returned := lease.AttachPacketConn(raw)
		var wait sync.WaitGroup
		for index := 0; index < 8; index++ {
			wait.Add(1)
			go func() {
				defer wait.Done()
				if err := returned.Close(); err != nil {
					t.Errorf("concurrent Close: %v", err)
				}
			}()
		}
		wait.Wait()
		if raw.closes.Load() != 1 || backend.closed.Load() != 1 {
			t.Fatalf("concurrent Close released twice: raw=%d capture=%d", raw.closes.Load(), backend.closed.Load())
		}
		if engine.ActiveLeases() != 0 {
			t.Fatalf("concurrent Close left %d charged lease(s)", engine.ActiveLeases())
		}
	})
}

// TestPacketUDPReturnedCloseJoinsRawError pins that a native close failure is
// reported without suppressing the lease/capture cleanup.
func TestPacketUDPReturnedCloseJoinsRawError(t *testing.T) {
	_, hook, backend := newUDPLeaseEngine(t, 1, option.DirectDesyncRule{Network: []string{"udp"}, Methods: []string{}})
	lease := packetUDPAttempt(t, hook, true)
	rawErr := errors.New("fixture: native listener close failed")
	raw := &udpLifetimePacket{closeErr: rawErr}
	returned := lease.AttachPacketConn(raw)
	err := returned.Close()
	if !errors.Is(err, rawErr) {
		t.Fatalf("returned Close error = %v, want the raw close error", err)
	}
	if err = returned.Close(); !errors.Is(err, rawErr) {
		t.Fatalf("repeated Close error = %v, want the same joined error", err)
	}
	if backend.closed.Load() != 1 {
		t.Fatalf("capture not released after a raw close error: closes=%d", backend.closed.Load())
	}
	if charged := lease.lease.Engine().ActiveLeases(); charged != 0 {
		t.Fatalf("raw close error left %d charged lease(s)", charged)
	}
}

// TestPacketUDPReturnedCloseKeepsNativeSocketCapability pins that the wrapper
// still exposes the optional syscall.Conn view of the returned UDP transport.
func TestPacketUDPReturnedCloseKeepsNativeSocketCapability(t *testing.T) {
	_, hook, backend := newUDPLeaseEngine(t, 1, option.DirectDesyncRule{Network: []string{"udp"}, Methods: []string{}})
	client, peer := net.Pipe()
	defer peer.Close()
	connectedLease := packetUDPAttempt(t, hook, false)
	attached, err := connectedLease.AttachConn(&udpLifetimeSyscallConn{Conn: client})
	if err != nil {
		t.Fatalf("AttachConn: %v", err)
	}
	nativeConn, ok := attached.(syscall.Conn)
	if !ok {
		t.Fatalf("returned connected transport %T does not expose SyscallConn", attached)
	}
	raw, err := nativeConn.SyscallConn()
	if err != nil || raw == nil {
		t.Fatalf("forwarded SyscallConn = %v, %v", raw, err)
	}
	if err = attached.Close(); err != nil {
		t.Fatalf("returned connected Close: %v", err)
	}
	if backend.closed.Load() != 1 || connectedLease.lease.Engine().ActiveLeases() != 0 {
		t.Fatalf("connected transport did not retire its lease: capture=%d charged=%d", backend.closed.Load(), connectedLease.lease.Engine().ActiveLeases())
	}
	listenerLease := packetUDPAttempt(t, hook, true)
	returned := listenerLease.AttachPacketConn(&udpLifetimePacket{})
	listenerConn, ok := returned.(syscall.Conn)
	if !ok {
		t.Fatalf("returned listener %T does not expose SyscallConn", returned)
	}
	if _, err = listenerConn.SyscallConn(); err == nil {
		t.Fatal("a transport without a native descriptor must report the missing capability")
	}
	if err = returned.Close(); err != nil {
		t.Fatalf("returned listener Close: %v", err)
	}
}

// TestPacketUDPReturnedCloseEngineOrdering covers Engine.Close before, after
// and concurrently with the returned transport close. The capture is released
// once, the charged map ends empty and no call errors or panics.
func TestPacketUDPReturnedCloseEngineOrdering(t *testing.T) {
	build := func(t *testing.T) (*desync.Engine, *desyncLease, *udpLifetimePacket, *countingBackend, net.PacketConn) {
		t.Helper()
		engine, hook, backend := newUDPLeaseEngine(t, 1, option.DirectDesyncRule{Network: []string{"udp"}, Methods: []string{}})
		lease := packetUDPAttempt(t, hook, true)
		raw := &udpLifetimePacket{}
		return engine, lease, raw, backend, lease.AttachPacketConn(raw)
	}
	t.Run("engine-before-transport", func(t *testing.T) {
		engine, _, raw, backend, returned := build(t)
		if err := engine.Close(); err != nil {
			t.Fatalf("Engine.Close: %v", err)
		}
		if err := returned.Close(); err != nil {
			t.Fatalf("Close after Engine.Close: %v", err)
		}
		if raw.closes.Load() != 1 || backend.closed.Load() != 1 {
			t.Fatalf("release after Engine.Close: raw=%d capture=%d", raw.closes.Load(), backend.closed.Load())
		}
		if engine.ActiveLeases() != 0 {
			t.Fatalf("lease still charged after Engine.Close: %d", engine.ActiveLeases())
		}
	})
	t.Run("transport-before-engine", func(t *testing.T) {
		engine, _, raw, backend, returned := build(t)
		if err := returned.Close(); err != nil {
			t.Fatalf("returned Close: %v", err)
		}
		if err := engine.Close(); err != nil {
			t.Fatalf("Engine.Close after transport: %v", err)
		}
		if raw.closes.Load() != 1 || backend.closed.Load() != 1 {
			t.Fatalf("release before Engine.Close: raw=%d capture=%d", raw.closes.Load(), backend.closed.Load())
		}
		if engine.ActiveLeases() != 0 {
			t.Fatalf("lease still charged after transport Close: %d", engine.ActiveLeases())
		}
	})
	t.Run("concurrent", func(t *testing.T) {
		engine, _, raw, backend, returned := build(t)
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			_ = engine.Close()
		}()
		go func() {
			defer wait.Done()
			if err := returned.Close(); err != nil {
				t.Errorf("concurrent returned Close: %v", err)
			}
		}()
		wait.Wait()
		if raw.closes.Load() != 1 || backend.closed.Load() != 1 {
			t.Fatalf("concurrent Engine/transport release: raw=%d capture=%d", raw.closes.Load(), backend.closed.Load())
		}
		if engine.ActiveLeases() != 0 {
			t.Fatalf("concurrent release left %d charged lease(s)", engine.ActiveLeases())
		}
	})
}

// TestPacketUDPReturnedCloseRespectsRetainedNativeHold pins that the returned
// transport retires the capture immediately but cannot discharge a charge that
// an independent native hold still owns; the hold's own release performs the
// final retirement as before.
func TestPacketUDPReturnedCloseRespectsRetainedNativeHold(t *testing.T) {
	engine, hook, backend := newUDPLeaseEngine(t, 1, option.DirectDesyncRule{Network: []string{"udp"}, Methods: []string{}})
	lease := packetUDPAttempt(t, hook, true)
	release, err := lease.lease.AcquireNativeHold()
	if err != nil {
		t.Fatalf("AcquireNativeHold: %v", err)
	}
	raw := &udpLifetimePacket{}
	returned := lease.AttachPacketConn(raw)
	if err = returned.Close(); err != nil {
		t.Fatalf("returned Close: %v", err)
	}
	if backend.closed.Load() != 1 {
		t.Fatalf("capture not released with a retained hold present: closes=%d", backend.closed.Load())
	}
	if charged := engine.ActiveLeases(); charged != 1 {
		t.Fatalf("retained hold charge = %d, want the charged tombstone", charged)
	}
	if _, err = hook.NewAttempt(context.Background(), dialer.AttemptIntent{
		Network:     "tcp",
		Destination: M.SocksaddrFrom(netip.MustParseAddr("198.51.100.21"), 443),
	}); err == nil {
		t.Fatal("a retained hold must keep the single admission slot charged")
	}
	release()
	release() // the native release is idempotent
	if charged := engine.ActiveLeases(); charged != 0 {
		t.Fatalf("released hold left %d charged lease(s)", charged)
	}
	next, err := hook.NewAttempt(context.Background(), dialer.AttemptIntent{
		Network:     "tcp",
		Destination: M.SocksaddrFrom(netip.MustParseAddr("198.51.100.21"), 443),
	})
	if err != nil {
		t.Fatalf("released hold did not return capacity: %v", err)
	}
	if err = next.Close(nil); err != nil {
		t.Fatal(err)
	}
}

// buildUDPProbePacket builds a minimal IPv4/UDP datagram. Only the fields the
// parser requires are set; IPv4 UDP checksum zero is valid.
func buildUDPProbePacket(destination netip.AddrPort, payload []byte) []byte {
	packet := make([]byte, 20+8+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[4:6], 0x4433)
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], netip.MustParseAddr("192.0.2.1").AsSlice())
	copy(packet[16:20], destination.Addr().AsSlice())
	binary.BigEndian.PutUint16(packet[20:22], 40000)
	binary.BigEndian.PutUint16(packet[22:24], destination.Port())
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload)))
	copy(packet[28:], payload)
	return packet
}

// TestPacketUDPReturnedCloseRetiresPeerState pins that closing the returned
// transport also retires the lease's per-peer state and its aggregate charge:
// with the peer allowance at one, a later listener can admit a new peer only if
// the closed transport retired the previous one.
func TestPacketUDPReturnedCloseRetiresPeerState(t *testing.T) {
	engine, hook, _ := newUDPLeaseEngine(t, 1, option.DirectDesyncRule{
		Network: []string{"udp"},
		Port:    []uint16{9999},
		Methods: []string{"fake"},
		Fake: &option.DirectDesyncFakeOptions{
			Repeats:  1,
			Payloads: []option.DirectDesyncPayload{{Protocol: "unknown", Hex: "0001"}},
		},
	})
	first := packetUDPAttempt(t, hook, true)
	var firstInjections atomic.Int32
	firstPacket := buildUDPProbePacket(netip.MustParseAddrPort("198.51.100.30:9999"), []byte("first-peer"))
	if verdict := first.lease.HandlePacket(firstPacket, desync.DirectionOutbound, func([]byte) error {
		firstInjections.Add(1)
		return nil
	}, nil); firstInjections.Load() == 0 {
		t.Fatalf("first peer state not admitted: verdict=%v", verdict)
	}
	raw := &udpLifetimePacket{}
	returned := first.AttachPacketConn(raw)
	if err := returned.Close(); err != nil {
		t.Fatalf("returned Close: %v", err)
	}
	if engine.ActiveLeases() != 0 {
		t.Fatalf("returned Close left %d charged lease(s)", engine.ActiveLeases())
	}
	second := packetUDPAttempt(t, hook, true)
	var secondInjections atomic.Int32
	secondPacket := buildUDPProbePacket(netip.MustParseAddrPort("198.51.100.31:9999"), []byte("second-peer"))
	if verdict := second.lease.HandlePacket(secondPacket, desync.DirectionOutbound, func([]byte) error {
		secondInjections.Add(1)
		return nil
	}, nil); secondInjections.Load() == 0 {
		t.Fatalf("closed transport did not retire the previous peer charge: verdict=%v", verdict)
	}
	secondReturned := second.AttachPacketConn(&udpLifetimePacket{})
	if err := secondReturned.Close(); err != nil {
		t.Fatalf("second returned Close: %v", err)
	}
	if engine.ActiveLeases() != 0 {
		t.Fatalf("second returned Close left %d charged lease(s)", engine.ActiveLeases())
	}
}

package direct

// QA361-D1 regression at the production boundary: with packet desync enabled,
// a connected UDP dial through the real direct outbound and the real installed
// attempt bridge must still return the dialer's UDP tracking wrapper. The
// attempt lease owner has to stay in the upstream chain, because it is the
// object that closes the native transport and retires the capture exactly once.
//
// This test opens loopback UDP sockets and therefore runs only in the isolated
// lab environment (loopback interface up), never on the workstation.

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/desync"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// udpTrackingLabPeer returns the loopback peer socket and the destination to
// dial. The peer stays open for the whole test so the regression can carry a
// datagram in both directions through the returned transport.
func udpTrackingLabPeer(t *testing.T) (*net.UDPConn, M.Socksaddr) {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("isolated lab requires a working loopback UDP bind: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})
	destination := M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), uint16(listener.LocalAddr().(*net.UDPAddr).Port))
	return listener, destination
}

func udpTrackingLabDestination(t *testing.T) M.Socksaddr {
	t.Helper()
	_, destination := udpTrackingLabPeer(t)
	return destination
}

// assertUDPPayloadBothWays carries one datagram out through the returned
// transport and one back in, so the regression proves the wrapper is a working
// connection and not only a type assertion.
func assertUDPPayloadBothWays(t *testing.T, conn net.Conn, peer *net.UDPConn) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set transport deadline: %v", err)
	}
	if err := peer.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set peer deadline: %v", err)
	}
	if _, err := conn.Write([]byte("desync-udp-tracking-out")); err != nil {
		t.Fatalf("write through returned transport: %v", err)
	}
	outbound := make([]byte, 64)
	read, peerAddr, err := peer.ReadFromUDP(outbound)
	if err != nil {
		t.Fatalf("peer read of returned transport payload: %v", err)
	}
	if string(outbound[:read]) != "desync-udp-tracking-out" {
		t.Fatalf("peer payload = %q", outbound[:read])
	}
	if _, err = peer.WriteToUDP([]byte("desync-udp-tracking-in"), peerAddr); err != nil {
		t.Fatalf("peer reply: %v", err)
	}
	inbound := make([]byte, 64)
	read, err = conn.Read(inbound)
	if err != nil {
		t.Fatalf("read through returned transport: %v", err)
	}
	if string(inbound[:read]) != "desync-udp-tracking-in" {
		t.Fatalf("returned transport payload = %q", inbound[:read])
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clear transport deadline: %v", err)
	}
	if err = peer.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clear peer deadline: %v", err)
	}
}

func newUDPTrackingOutbound(t *testing.T, options option.DirectOutboundOptions) *Outbound {
	t.Helper()
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), retainedReportNetwork{})
	ctx = service.ContextWith[adapter.DNSTransportManager](ctx, retainedReportDNS{})
	options.UDPFragmentDefault = true
	// The production outbound logs the returned-connection boundary through
	// this context logger; NewOutbound with a nil logger panics on the first
	// real dial (QA364-T1). NOP() is the repository's normal logger fixture.
	made, err := NewOutbound(ctx, nil, logger.NOP(), "udp-tracking", options)
	if err != nil {
		t.Fatalf("NewOutbound: %v", err)
	}
	outbound, isOutbound := made.(*Outbound)
	if !isOutbound {
		t.Fatalf("constructor returned %T", made)
	}
	return outbound
}

func assertTrackedUDPTransport(t *testing.T, conn net.Conn, wantLeaseOwner bool) {
	t.Helper()
	reader, isReplaceable := conn.(N.ReaderWithUpstream)
	if !isReplaceable || !reader.ReaderReplaceable() {
		t.Fatalf("connected UDP transport %T has no replaceable reader view: UDP EOF tracking and Upstream were skipped", conn)
	}
	writer, isReplaceable := conn.(N.WriterWithUpstream)
	if !isReplaceable || !writer.WriterReplaceable() {
		t.Fatalf("connected UDP transport %T has no replaceable writer view", conn)
	}
	upstream, hasUpstream := conn.(common.WithUpstream)
	if !hasUpstream {
		t.Fatalf("connected UDP transport %T exposes no owned upstream", conn)
	}
	upstreamConn, isConn := upstream.Upstream().(net.Conn)
	if !isConn {
		t.Fatalf("connected UDP upstream is %T, not a connection", upstream.Upstream())
	}
	_, rawUpstream := upstreamConn.(*net.UDPConn)
	if wantLeaseOwner && rawUpstream {
		t.Fatal("UDP tracking wrapper unwrapped past the lease owner to the raw transport")
	}
	if !wantLeaseOwner && !rawUpstream {
		t.Fatalf("control UDP transport upstream is %T, want the native *net.UDPConn", upstreamConn)
	}
	syscallConn, hasSyscall := conn.(syscall.Conn)
	if !hasSyscall {
		t.Fatalf("connected UDP transport %T lost the native socket capability", conn)
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil || rawConn == nil {
		t.Fatalf("native socket capability unusable: raw=%v err=%v", rawConn, err)
	}
}

func TestConnectedUDPDesyncKeepsDialerTracking(t *testing.T) {
	destination := udpTrackingLabDestination(t)
	t.Run("packet-desync", func(t *testing.T) {
		peer, destination := udpTrackingLabPeer(t)
		outbound := newUDPTrackingOutbound(t, option.DirectOutboundOptions{
			Desync: &option.DirectDesyncOptions{Rules: []option.DirectDesyncRule{{
				Network: []string{"udp"},
				Methods: []string{},
			}}},
		})
		original := outbound.desync
		if original == nil {
			t.Fatal("packet rule produced no engine")
		}
		t.Cleanup(func() {
			_ = original.Close()
		})
		installed, isDefaultDialer := common.Cast[*dialer.DefaultDialer](outbound.dialer)
		if !isDefaultDialer {
			t.Fatal("production constructor did not install a DefaultDialer")
		}
		hook, isBridge := installed.AttemptHook().(*desyncHook)
		if !isBridge {
			t.Fatal("production constructor did not install the attempt bridge")
		}
		config := original.Config()
		config.Limits.MaxLeases = 1
		backend := &countingBackend{}
		engine, err := desync.NewEngine(config, backend)
		if err != nil {
			t.Fatalf("desync.NewEngine: %v", err)
		}
		hook.engine = engine
		outbound.desync = engine
		t.Cleanup(func() {
			_ = engine.Close()
		})
		conn, err := outbound.DialContext(context.Background(), "udp", destination)
		if err != nil {
			t.Fatalf("connected packet-UDP dial: %v", err)
		}
		assertTrackedUDPTransport(t, conn, true)
		if backend.opened.Load() != 1 {
			t.Fatalf("attempt capture opened %d times", backend.opened.Load())
		}
		assertUDPPayloadBothWays(t, conn, peer)
		if err = conn.Close(); err != nil {
			t.Fatalf("close tracked transport: %v", err)
		}
		if backend.closed.Load() != 1 {
			t.Fatalf("returned transport close retired the capture %d times", backend.closed.Load())
		}
		if charged := engine.ActiveLeases(); charged != 0 {
			t.Fatalf("returned transport close left %d charged packet leases", charged)
		}
		next, nextErr := hook.NewAttempt(context.Background(), dialer.AttemptIntent{
			Network:     "udp",
			Destination: M.ParseSocksaddr("198.51.100.21:443"),
		})
		if nextErr != nil {
			t.Fatalf("tracked transport close did not return admission capacity: %v", nextErr)
		}
		_ = next.Close(nil)
	})

	t.Run("state-only-control", func(t *testing.T) {
		outbound := newUDPTrackingOutbound(t, option.DirectOutboundOptions{
			Desync: &option.DirectDesyncOptions{
				StreamRules: []option.DirectDesyncStreamRule{testStreamRule(443)},
			},
		})
		if outbound.desync == nil {
			t.Fatal("state-only configuration produced no engine")
		}
		t.Cleanup(func() {
			_ = outbound.desync.Close()
		})
		conn, err := outbound.DialContext(context.Background(), "udp", destination)
		if err != nil {
			t.Fatalf("connected state-only UDP dial: %v", err)
		}
		assertTrackedUDPTransport(t, conn, false)
		if err = conn.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	})

	t.Run("disabled-control", func(t *testing.T) {
		outbound := newUDPTrackingOutbound(t, option.DirectOutboundOptions{})
		conn, err := outbound.DialContext(context.Background(), "udp", destination)
		if err != nil {
			t.Fatalf("connected plain UDP dial: %v", err)
		}
		assertTrackedUDPTransport(t, conn, false)
		if err = conn.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	})
}

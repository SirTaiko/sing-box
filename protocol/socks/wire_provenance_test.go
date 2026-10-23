package socks

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	singSocks "github.com/sagernet/sing/protocol/socks"
)

func readSOCKS5Reply(t *testing.T, connection *testConnection) []byte {
	t.Helper()
	header := connection.read(t, 4)
	switch header[3] {
	case 0x01:
		return append(header, connection.read(t, 6)...)
	case 0x04:
		return append(header, connection.read(t, 18)...)
	case 0x03:
		length := connection.read(t, 1)
		return append(append(header, length...), connection.read(t, int(length[0])+2)...)
	default:
		t.Fatalf("unexpected SOCKS5 reply address type: %x", header[3])
		return nil
	}
}

// assertRoutePayload reads the preserved early bytes off the routed connection
// and checks the success reply is still emitted exactly once by the lazy
// handshake.
func assertRoutePayload(t *testing.T, connection *testConnection, call routeCall, payload []byte, socks4 bool) {
	t.Helper()
	received := make([]byte, len(payload))
	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(call.conn, received)
		readDone <- err
	}()
	if socks4 {
		reply := connection.read(t, 4)
		if reply[1] != 0x5A {
			t.Fatalf("unexpected SOCKS4 reply: %x", reply)
		}
	} else {
		reply := readSOCKS5Reply(t, connection)
		if reply[1] != 0x00 {
			t.Fatalf("unexpected SOCKS5 reply: %x", reply)
		}
	}
	if err := <-readDone; err != nil {
		t.Fatalf("read routed payload: %v", err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("routed payload differs: got %d bytes", len(received))
	}
	_ = call.conn.Close()
}

func TestSOCKS5BufferedEarlyPayloadReachesRoute(t *testing.T) {
	for _, size := range []int{1, 11, 4095, 4096, 8192} {
		size := size
		t.Run(func() string {
			return "payload-" + itoa(size)
		}(), func(t *testing.T) {
			inbound, router := newTestInbound(t, nil, option.SocksInboundOptions{NoResolve: false})
			connection := startTestConnection(t, inbound, context.Background())
			connection.negotiateSOCKS5(t)
			payload := make([]byte, size)
			for index := range payload {
				payload[index] = byte(index*11 + 5)
			}
			go func() {
				_, _ = connection.client.Write(append(socks5RequestATYP3("example.com", 443), payload...))
			}()
			call := router.waitRoute(t)
			if call.metadata.Destination.Fqdn != "example.com" {
				t.Fatalf("routed destination = %v", call.metadata.Destination)
			}
			assertRoutePayload(t, connection, call, payload, false)
		})
	}
}

func TestSOCKS5BufferedEarlyPayloadReachesRouteWithAuthentication(t *testing.T) {
	inbound, router := newTestInbound(t, nil, option.SocksInboundOptions{
		Users: []auth.User{{Username: "user", Password: "pass"}},
	})
	connection := startTestConnection(t, inbound, context.Background())
	connection.write(t, []byte{0x05, 0x01, 0x02})
	if reply := connection.read(t, 2); !bytes.Equal(reply, []byte{0x05, 0x02}) {
		t.Fatalf("unexpected method selection: %x", reply)
	}
	connection.write(t, []byte{0x01, 0x04, 'u', 's', 'e', 'r', 0x04, 'p', 'a', 's', 's'})
	if reply := connection.read(t, 2); !bytes.Equal(reply, []byte{0x01, 0x00}) {
		t.Fatalf("unexpected authentication status: %x", reply)
	}
	payload := []byte("authenticated-early-bytes")
	go func() {
		_, _ = connection.client.Write(append(socks5RequestATYP1(netip.MustParseAddr("203.0.113.9"), 443), payload...))
	}()
	call := router.waitRoute(t)
	if call.metadata.User != "user" {
		t.Fatalf("routed user = %q", call.metadata.User)
	}
	assertRoutePayload(t, connection, call, payload, false)
}

func TestSOCKS4FormsBufferedEarlyPayloadReachRoute(t *testing.T) {
	fixtures := []struct {
		name    string
		request func() []byte
	}{
		{name: "socks4-literal", request: func() []byte {
			return socks4Request(netip.MustParseAddr("192.0.2.9"), 443)
		}},
		{name: "socks4a-hostname", request: func() []byte {
			return socks4aRequest("example.com", 443)
		}},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			inbound, router := newTestInbound(t, nil, option.SocksInboundOptions{})
			connection := startTestConnection(t, inbound, context.Background())
			payload := []byte("socks4-early-bytes")
			go func() {
				_, _ = connection.client.Write(append(fixture.request(), payload...))
			}()
			call := router.waitRoute(t)
			assertRoutePayload(t, connection, call, payload, true)
		})
	}
}

func TestNoResolveMissingProvenanceFailsClosed(t *testing.T) {
	inbound, router := newTestInbound(t, nil, option.SocksInboundOptions{NoResolve: true})
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	legacyConn := singSocks.NewLazyConn(serverConn, 5)
	closeCalls := make(chan error, 1)
	go func() {
		inbound.newUserConnection(
			context.Background(), legacyConn,
			adapter.InboundContext{Destination: M.ParseSocksaddr("203.0.113.9:443")},
			func(err error) { closeCalls <- err },
		)
	}()
	reply := make([]byte, 10)
	if _, err := io.ReadFull(clientConn, reply); err != nil {
		t.Fatalf("read failure reply: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x01 {
		t.Fatalf("missing provenance reply = %x, want general failure code 1", reply)
	}
	select {
	case err := <-closeCalls:
		if err == nil {
			t.Fatal("missing provenance closed without an error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("onClose was not called")
	}
	router.expectNoRoute(t)
}

func TestNoResolveKeepsUoTLegacyEarlyPayload(t *testing.T) {
	inbound, router := newTestInbound(t, nil, option.SocksInboundOptions{NoResolve: true})
	connection := startTestConnection(t, inbound, context.Background())
	connection.negotiateSOCKS5(t)
	payload := []byte("legacy-uot-payload")
	datagram := []byte{0x00, 203, 0, 113, 7, 0x1f, 0x90, byte(len(payload) >> 8), byte(len(payload))}
	datagram = append(datagram, payload...)
	go func() {
		_, _ = connection.client.Write(append(socks5RequestATYP3(uot.LegacyMagicAddress, 0), datagram...))
	}()
	packetConn := waitPacketConnection(t, router)
	buffer := buf.NewPacket()
	defer buffer.Release()
	destination, err := readPacketWithLazyReply(t, connection, packetConn, buffer)
	if err != nil {
		t.Fatalf("read UoT legacy packet: %v", err)
	}
	if !bytes.Equal(buffer.Bytes(), payload) {
		t.Fatalf("UoT legacy payload = %q, want %q", buffer.Bytes(), payload)
	}
	if destination.String() != "203.0.113.7:8080" {
		t.Fatalf("UoT legacy destination = %v", destination)
	}
}

func TestNoResolveKeepsUoTV2EarlyPayload(t *testing.T) {
	inbound, router := newTestInbound(t, nil, option.SocksInboundOptions{NoResolve: true})
	connection := startTestConnection(t, inbound, context.Background())
	connection.negotiateSOCKS5(t)
	payload := []byte("v2-uot-payload")
	header := []byte{0x01, 0x01, 203, 0, 113, 8, 0x01, 0xbb}
	packet := append(header, byte(len(payload)>>8), byte(len(payload)))
	packet = append(packet, payload...)
	go func() {
		_, _ = connection.client.Write(append(socks5RequestATYP3(uot.MagicAddress, 0), packet...))
	}()
	// The UoT v2 request header is read by the shared router, which writes the
	// lazy success reply before dispatching the packet connection.
	if reply := readSOCKS5Reply(t, connection); reply[1] != 0x00 {
		t.Fatalf("unexpected UoT v2 success reply: %x", reply)
	}
	packetConn := waitPacketConnection(t, router)
	buffer := buf.NewPacket()
	defer buffer.Release()
	result := make(chan packetResult, 1)
	go func() {
		destination, err := packetConn.ReadPacket(buffer)
		result <- packetResult{destination: destination, err: err}
	}()
	var destination M.Socksaddr
	select {
	case packet := <-result:
		if packet.err != nil {
			t.Fatalf("read UoT v2 packet: %v", packet.err)
		}
		destination = packet.destination
	case <-time.After(5 * time.Second):
		t.Fatal("UoT v2 packet was not delivered")
	}
	if !bytes.Equal(buffer.Bytes(), payload) {
		t.Fatalf("UoT v2 payload = %q, want %q", buffer.Bytes(), payload)
	}
	if destination.String() != "203.0.113.8:443" {
		t.Fatalf("UoT v2 destination = %v", destination)
	}
}

type packetResult struct {
	destination M.Socksaddr
	err         error
}

func waitPacketConnection(t *testing.T, router *recordingRouter) N.PacketConn {
	t.Helper()
	select {
	case packetConn := <-router.packetConns:
		return packetConn
	case <-time.After(5 * time.Second):
		t.Fatal("packet connection was not routed")
		return nil
	}
}

// readPacketWithLazyReply reads a packet while the success reply is written by
// the lazy handshake, so the reply must be consumed concurrently.
func readPacketWithLazyReply(t *testing.T, connection *testConnection, packetConn N.PacketConn, buffer *buf.Buffer) (M.Socksaddr, error) {
	t.Helper()
	result := make(chan packetResult, 1)
	go func() {
		destination, err := packetConn.ReadPacket(buffer)
		result <- packetResult{destination: destination, err: err}
	}()
	reply := readSOCKS5Reply(t, connection)
	if reply[1] != 0x00 {
		t.Fatalf("unexpected UoT success reply: %x", reply)
	}
	select {
	case packet := <-result:
		return packet.destination, packet.err
	case <-time.After(5 * time.Second):
		t.Fatal("UoT packet was not delivered")
		return M.Socksaddr{}, nil
	}
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	position := len(digits)
	for value > 0 {
		position--
		digits[position] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[position:])
}

// TestNoResolveLiteralWireFormsRoute pins the literal acceptance row of the
// wire-provenance policy. The shared SOCKS address serializer unwraps an
// ATYP=4 IPv4-mapped IPv6 literal (::ffff:a.b.c.d) into a plain IPv4 address
// before the inbound observes it, so no_resolve must admit that normalized
// literal - the retained wire provenance still reports the ATYP=4 family. The
// native IPv6 and ATYP=1 forms keep their own family, and none of the literal
// forms may consult DNS or take a resolver slot.
func TestNoResolveLiteralWireFormsRoute(t *testing.T) {
	fixtures := []struct {
		name    string
		request func(netip.Addr, uint16) []byte
		wire    netip.Addr
		want    netip.Addr
	}{
		{
			name:    "socks5-atyp1-ipv4",
			request: socks5RequestATYP1,
			wire:    netip.MustParseAddr("203.0.113.9"),
			want:    netip.MustParseAddr("203.0.113.9"),
		},
		{
			name:    "socks5-atyp4-ipv6",
			request: socks5RequestATYP4,
			wire:    netip.MustParseAddr("2001:db8::9"),
			want:    netip.MustParseAddr("2001:db8::9"),
		},
		{
			name:    "socks5-atyp4-v4-mapped",
			request: socks5RequestATYP4,
			wire:    netip.MustParseAddr("::ffff:203.0.113.9"),
			want:    netip.MustParseAddr("203.0.113.9"),
		},
	}
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			services := newResolverServices()
			services.transports.transports["default-dns"] = &fakeDNSTransport{tag: "default-dns"}
			inbound, router := newTestInbound(t, services, option.SocksInboundOptions{
				NoResolve:           true,
				ResolverConcurrency: ptrValue(uint16(1)),
			})
			connection := startTestConnection(t, inbound, context.Background())
			connection.negotiateSOCKS5(t)
			connection.write(t, fixture.request(fixture.wire, 443))
			call := router.waitRoute(t)
			if call.metadata.Destination.Addr != fixture.want || call.metadata.Destination.Port != 443 {
				t.Fatalf("routed destination = %v, want %v:443", call.metadata.Destination, fixture.want)
			}
			if len(call.metadata.DestinationAddresses) != 0 {
				t.Fatalf("literal carried resolver addresses: %v", call.metadata.DestinationAddresses)
			}
			_ = call.conn.Close()
			if count := services.router.lookupCount(); count != 0 {
				t.Fatalf("literal performed %d DNS lookups", count)
			}
			if slots := len(inbound.resolver.slots); slots != 0 {
				t.Fatalf("literal held %d resolver slots", slots)
			}
		})
	}
}

// wireProvenanceProviderConn is a memory connection that reports explicit
// request provenance, standing in for the shared handshake's LazyConn. It can
// express metadata/destination pairs the shared parser never produces, which is
// exactly what the fail-closed admission checks must reject.
type wireProvenanceProviderConn struct {
	net.Conn
	requestMetadata singSocks.RequestMetadata
	known           bool
}

func (c *wireProvenanceProviderConn) RequestMetadata() (singSocks.RequestMetadata, bool) {
	return c.requestMetadata, c.known
}

// admitWireProvenance runs the inbound admission entry point with an explicit
// provenance capability. An admitted request is reported through the recording
// router; a rejected one through the handshake error.
func admitWireProvenance(t *testing.T, inbound *Inbound, router *recordingRouter, provider *wireProvenanceProviderConn, destination M.Socksaddr) (adapter.InboundContext, error) {
	t.Helper()
	closeCalls := make(chan error, 1)
	go inbound.newUserConnection(
		context.Background(), provider,
		adapter.InboundContext{Destination: destination},
		func(err error) { closeCalls <- err },
	)
	select {
	case call := <-router.calls:
		_ = call.conn.Close()
		return call.metadata, nil
	case err := <-closeCalls:
		return adapter.InboundContext{}, err
	case <-time.After(5 * time.Second):
		t.Fatal("admission neither routed nor closed the connection")
		return adapter.InboundContext{}, nil
	}
}

// TestNoResolveProviderProvenanceInvariants pins the consistency invariant
// between the immutable RequestMetadata value and the normalized destination.
// Production provenance only comes from the shared parser, so the two IP shapes
// below are the only ones it can publish: a native IPv6 ATYP=4 literal, and an
// IPv4 literal that is either ATYP=1 or an ATYP=4 IPv4-mapped address that the
// serializer normalized with Socksaddr.Unwrap. In particular, an IPv6-family
// provenance paired with a normalized IPv4 destination is the legitimate
// mapped-literal shape, not an inconsistency, because the family alone cannot
// record whether the 16 wire bytes were IPv4-mapped. Every other mismatch, a
// missing capability, and the original-wire Fqdn denial stay fail-closed.
func TestNoResolveProviderProvenanceInvariants(t *testing.T) {
	ipv4 := netip.MustParseAddr("203.0.113.9")
	ipv6 := netip.MustParseAddr("2001:db8::9")
	admitted := []struct {
		name        string
		destination M.Socksaddr
		metadata    singSocks.RequestMetadata
		want        netip.Addr
	}{
		{
			name:        "ipv4-family-ipv4-literal",
			destination: M.SocksaddrFrom(ipv4, 443),
			metadata:    singSocks.RequestMetadata{Version: 5, DestinationFamily: M.AddressFamilyIPv4},
			want:        ipv4,
		},
		{
			name:        "ipv6-family-ipv6-literal",
			destination: M.SocksaddrFrom(ipv6, 443),
			metadata:    singSocks.RequestMetadata{Version: 5, DestinationFamily: M.AddressFamilyIPv6},
			want:        ipv6,
		},
		{
			// ATYP=4 ::ffff:a.b.c.d after Socksaddr.Unwrap.
			name:        "ipv6-family-normalized-mapped-literal",
			destination: M.SocksaddrFrom(ipv4, 443),
			metadata:    singSocks.RequestMetadata{Version: 5, DestinationFamily: M.AddressFamilyIPv6},
			want:        ipv4,
		},
	}
	for _, testCase := range admitted {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			services := newResolverServices()
			services.transports.transports["default-dns"] = &fakeDNSTransport{tag: "default-dns"}
			inbound, router := newTestInbound(t, services, option.SocksInboundOptions{
				NoResolve:           true,
				ResolverConcurrency: ptrValue(uint16(1)),
			})
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			provider := &wireProvenanceProviderConn{Conn: serverConn, requestMetadata: testCase.metadata, known: true}
			metadata, err := admitWireProvenance(t, inbound, router, provider, testCase.destination)
			if err != nil {
				t.Fatalf("valid provenance was rejected: %v", err)
			}
			if metadata.Destination.Addr != testCase.want || metadata.Destination.Port != 443 {
				t.Fatalf("routed destination = %v, want %v:443", metadata.Destination, testCase.want)
			}
			if len(metadata.DestinationAddresses) != 0 {
				t.Fatalf("literal carried resolver addresses: %v", metadata.DestinationAddresses)
			}
			if count := services.router.lookupCount(); count != 0 {
				t.Fatalf("literal performed %d DNS lookups", count)
			}
			if slots := len(inbound.resolver.slots); slots != 0 {
				t.Fatalf("literal held %d resolver slots", slots)
			}
		})
	}
	denied := []struct {
		name        string
		destination M.Socksaddr
		metadata    singSocks.RequestMetadata
		known       bool
	}{
		{name: "missing-provenance", destination: M.SocksaddrFrom(ipv4, 443)},
		{name: "unknown-version-0", destination: M.SocksaddrFrom(ipv4, 443), metadata: singSocks.RequestMetadata{Version: 0, DestinationFamily: M.AddressFamilyIPv4}, known: true},
		{name: "unknown-version-3", destination: M.SocksaddrFrom(ipv4, 443), metadata: singSocks.RequestMetadata{Version: 3, DestinationFamily: M.AddressFamilyIPv4}, known: true},
		{name: "unknown-family", destination: M.SocksaddrFrom(ipv4, 443), metadata: singSocks.RequestMetadata{Version: 5, DestinationFamily: M.AddressFamilyEmpty}, known: true},
		{name: "socks4-version-with-ipv6-family", destination: M.SocksaddrFrom(ipv6, 443), metadata: singSocks.RequestMetadata{Version: 4, DestinationFamily: M.AddressFamilyIPv6}, known: true},
		{name: "ipv4-family-with-ipv6-literal", destination: M.SocksaddrFrom(ipv6, 443), metadata: singSocks.RequestMetadata{Version: 5, DestinationFamily: M.AddressFamilyIPv4}, known: true},
		{name: "ipv4-family-with-domain", destination: M.ParseSocksaddr("example.com:443"), metadata: singSocks.RequestMetadata{Version: 5, DestinationFamily: M.AddressFamilyIPv4}, known: true},
		{name: "ipv6-family-with-domain", destination: M.ParseSocksaddr("example.com:443"), metadata: singSocks.RequestMetadata{Version: 5, DestinationFamily: M.AddressFamilyIPv6}, known: true},
		{name: "fqdn-family-with-invalid-destination", destination: M.Socksaddr{}, metadata: singSocks.RequestMetadata{Version: 5, DestinationFamily: M.AddressFamilyFqdn}, known: true},
	}
	for _, testCase := range denied {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			services := newResolverServices()
			services.transports.transports["default-dns"] = &fakeDNSTransport{tag: "default-dns"}
			inbound, router := newTestInbound(t, services, option.SocksInboundOptions{
				NoResolve:           true,
				ResolverConcurrency: ptrValue(uint16(1)),
			})
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			provider := &wireProvenanceProviderConn{Conn: serverConn, requestMetadata: testCase.metadata, known: testCase.known}
			_, err := admitWireProvenance(t, inbound, router, provider, testCase.destination)
			if err == nil {
				t.Fatal("inconsistent provenance was admitted without an error")
			}
			if errors.Is(err, syscall.EPERM) {
				t.Fatalf("inconsistent provenance mapped to the domain-denied error: %v", err)
			}
			if routed := router.routed(); routed != 0 {
				t.Fatalf("inconsistent provenance caused %d route calls", routed)
			}
			if count := services.router.lookupCount(); count != 0 {
				t.Fatalf("inconsistent provenance performed %d DNS lookups", count)
			}
			if slots := len(inbound.resolver.slots); slots != 0 {
				t.Fatalf("inconsistent provenance held %d resolver slots", slots)
			}
		})
	}
	// The original-wire Fqdn denial keyed on the provenance family is preserved:
	// a numeric-looking domain normalized into an IPv4 literal is still refused
	// through the EPERM/code-2 path, never treated as a literal request.
	t.Run("fqdn-family-with-normalized-literal-is-domain-denied", func(t *testing.T) {
		services := newResolverServices()
		services.transports.transports["default-dns"] = &fakeDNSTransport{tag: "default-dns"}
		inbound, router := newTestInbound(t, services, option.SocksInboundOptions{
			NoResolve:           true,
			ResolverConcurrency: ptrValue(uint16(1)),
		})
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		provider := &wireProvenanceProviderConn{
			Conn:            serverConn,
			requestMetadata: singSocks.RequestMetadata{Version: 5, DestinationFamily: M.AddressFamilyFqdn},
			known:           true,
		}
		_, err := admitWireProvenance(t, inbound, router, provider, M.SocksaddrFrom(ipv4, 443))
		if !errors.Is(err, syscall.EPERM) {
			t.Fatalf("numeric-looking domain close error = %v, want syscall.EPERM", err)
		}
		if routed := router.routed(); routed != 0 {
			t.Fatalf("numeric-looking domain caused %d route calls", routed)
		}
		if count := services.router.lookupCount(); count != 0 {
			t.Fatalf("numeric-looking domain performed %d DNS lookups", count)
		}
		if slots := len(inbound.resolver.slots); slots != 0 {
			t.Fatalf("numeric-looking domain held %d resolver slots", slots)
		}
	})
}

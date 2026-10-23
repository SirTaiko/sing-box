package socks

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

type routeCall struct {
	conn     net.Conn
	metadata adapter.InboundContext
}

type recordingRouter struct {
	adapter.Router
	access      sync.Mutex
	routeCount  int
	packetCount int
	calls       chan routeCall
	packetConns chan N.PacketConn
}

func newRecordingRouter() *recordingRouter {
	return &recordingRouter{calls: make(chan routeCall, 16), packetConns: make(chan N.PacketConn, 4)}
}

func (r *recordingRouter) recordRoute(conn net.Conn, metadata adapter.InboundContext) {
	r.access.Lock()
	r.routeCount++
	r.access.Unlock()
	r.calls <- routeCall{conn: conn, metadata: metadata}
}

func (r *recordingRouter) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	r.recordRoute(conn, metadata)
	return nil
}

func (r *recordingRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.recordRoute(conn, metadata)
}

func (r *recordingRouter) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	r.access.Lock()
	r.packetCount++
	r.access.Unlock()
	return nil
}

func (r *recordingRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.access.Lock()
	r.packetCount++
	r.access.Unlock()
	select {
	case r.packetConns <- conn:
	default:
	}
}

func (r *recordingRouter) routed() int {
	r.access.Lock()
	defer r.access.Unlock()
	return r.routeCount
}

func (r *recordingRouter) packetRouted() int {
	r.access.Lock()
	defer r.access.Unlock()
	return r.packetCount
}

func (r *recordingRouter) waitRoute(t *testing.T) routeCall {
	t.Helper()
	select {
	case call := <-r.calls:
		return call
	case <-time.After(5 * time.Second):
		t.Fatal("route was not called")
		return routeCall{}
	}
}

func (r *recordingRouter) expectNoRoute(t *testing.T) {
	t.Helper()
	select {
	case call := <-r.calls:
		t.Fatalf("unexpected route call: %+v", call.metadata)
	case <-time.After(150 * time.Millisecond):
	}
}

func newTestInbound(t *testing.T, services *resolverServices, options option.SocksInboundOptions) (*Inbound, *recordingRouter) {
	t.Helper()
	router := newRecordingRouter()
	var (
		ctx  context.Context
		base adapter.Inbound
		err  error
	)
	if services != nil {
		ctx = services.context()
	} else {
		ctx = context.Background()
	}
	base, err = NewInbound(ctx, router, log.NewNOPFactory().NewLogger("socks-test"), "socks-in", options)
	if err != nil {
		t.Fatal(err)
	}
	inbound, loaded := base.(*Inbound)
	if !loaded {
		t.Fatalf("unexpected inbound type %T", base)
	}
	return inbound, router
}

type testConnection struct {
	client     net.Conn
	closeCalls chan error
	done       chan struct{}
}

func startTestConnection(t *testing.T, inbound *Inbound, ctx context.Context) *testConnection {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	err := clientConn.SetDeadline(time.Now().Add(15 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	connection := &testConnection{
		client:     clientConn,
		closeCalls: make(chan error, 4),
		done:       make(chan struct{}),
	}
	onClose := func(err error) {
		select {
		case connection.closeCalls <- err:
		default:
		}
	}
	go func() {
		defer close(connection.done)
		inbound.NewConnection(ctx, serverConn, adapter.InboundContext{
			Source: M.ParseSocksaddr("127.0.0.1:4567"),
		}, onClose)
	}()
	t.Cleanup(func() {
		_ = clientConn.Close()
	})
	return connection
}

func (c *testConnection) write(t *testing.T, payload []byte) {
	t.Helper()
	_, err := c.client.Write(payload)
	if err != nil {
		t.Fatal(err)
	}
}

func (c *testConnection) read(t *testing.T, length int) []byte {
	t.Helper()
	buffer := make([]byte, length)
	_, err := io.ReadFull(c.client, buffer)
	if err != nil {
		t.Fatalf("read %d bytes: %v", length, err)
	}
	return buffer
}

func (c *testConnection) waitClose(t *testing.T) error {
	t.Helper()
	select {
	case err := <-c.closeCalls:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("onClose was not called")
		return nil
	}
}

func (c *testConnection) negotiateSOCKS5(t *testing.T) {
	t.Helper()
	c.write(t, []byte{0x05, 0x01, 0x00})
	reply := c.read(t, 2)
	if !bytes.Equal(reply, []byte{0x05, 0x00}) {
		t.Fatalf("unexpected method selection: %x", reply)
	}
}

func socks5RequestATYP1(addr netip.Addr, port uint16) []byte {
	ip := addr.As4()
	return []byte{0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port)}
}

func socks5RequestATYP4(addr netip.Addr, port uint16) []byte {
	ip := addr.As16()
	request := []byte{0x05, 0x01, 0x00, 0x04}
	request = append(request, ip[:]...)
	return append(request, byte(port>>8), byte(port))
}

func socks5RequestATYP3(domain string, port uint16) []byte {
	request := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
	request = append(request, domain...)
	return append(request, byte(port>>8), byte(port))
}

func expectSOCKS5Failure(t *testing.T, connection *testConnection, code byte) {
	t.Helper()
	reply := connection.read(t, 10)
	want := []byte{0x05, code, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(reply, want) {
		t.Fatalf("socks5 reply = %x, want %x", reply, want)
	}
}

func socks4Request(addr netip.Addr, port uint16) []byte {
	ip := addr.As4()
	request := []byte{0x04, 0x01, byte(port >> 8), byte(port), ip[0], ip[1], ip[2], ip[3], 0x00}
	return request
}

func socks4aRequest(domain string, port uint16) []byte {
	request := []byte{0x04, 0x01, byte(port >> 8), byte(port), 0x00, 0x00, 0x00, 0x01, 0x00}
	request = append(request, []byte(domain)...)
	return append(request, 0x00)
}

func expectSOCKS4Failure(t *testing.T, connection *testConnection) {
	t.Helper()
	// sing's shared SOCKS4 failure writer emits its normal reply frame without a
	// bind address, so the existing mapping produces four bytes here.
	reply := connection.read(t, 4)
	want := []byte{0x00, 0x5B, 0x00, 0x00}
	if !bytes.Equal(reply, want) {
		t.Fatalf("socks4 reply = %x, want %x", reply, want)
	}
	remaining := make([]byte, 2)
	_, err := connection.client.Read(remaining)
	if err == nil {
		t.Fatal("SOCKS4 failure connection was not closed")
	}
}

func TestSOCKS5NoResolveRejectsDomainWithoutDNS(t *testing.T) {
	services := newResolverServices()
	services.transports.transports["default-dns"] = &fakeDNSTransport{tag: "default-dns"}
	inbound, router := newTestInbound(t, services, option.SocksInboundOptions{
		NoResolve:           true,
		ResolverConcurrency: ptrValue(uint16(2)),
	})
	connection := startTestConnection(t, inbound, context.Background())
	connection.negotiateSOCKS5(t)
	connection.write(t, socks5RequestATYP3("example.com", 443))
	expectSOCKS5Failure(t, connection, 0x02)
	if count := services.router.lookupCount(); count != 0 {
		t.Fatalf("no_resolve performed %d DNS lookups", count)
	}
	router.expectNoRoute(t)
	err := connection.waitClose(t)
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("onClose error = %v, want syscall.EPERM", err)
	}
}

func TestSOCKS5NoResolveLiteralBypass(t *testing.T) {
	inbound, router := newTestInbound(t, nil, option.SocksInboundOptions{NoResolve: true})
	connection := startTestConnection(t, inbound, context.Background())
	connection.negotiateSOCKS5(t)
	addr := netip.MustParseAddr("203.0.113.9")
	connection.write(t, socks5RequestATYP1(addr, 8443))
	call := router.waitRoute(t)
	if call.metadata.Destination.Addr != addr || call.metadata.Destination.Port != 8443 {
		t.Fatalf("routed destination = %v", call.metadata.Destination)
	}
	if len(call.metadata.DestinationAddresses) != 0 {
		t.Fatalf("literal destination carried resolver addresses: %v", call.metadata.DestinationAddresses)
	}
	_ = call.conn.Close()
}

func TestSOCKS5NoResolveIPv6LiteralBypass(t *testing.T) {
	inbound, router := newTestInbound(t, nil, option.SocksInboundOptions{NoResolve: true})
	connection := startTestConnection(t, inbound, context.Background())
	connection.negotiateSOCKS5(t)
	addr := netip.MustParseAddr("2001:db8::1")
	connection.write(t, socks5RequestATYP4(addr, 443))
	call := router.waitRoute(t)
	if call.metadata.Destination.Addr != addr {
		t.Fatalf("routed destination = %v", call.metadata.Destination)
	}
	_ = call.conn.Close()
}

func TestSOCKS5NoResolveKeepsAuthentication(t *testing.T) {
	inbound, router := newTestInbound(t, nil, option.SocksInboundOptions{
		NoResolve: true,
		Users:     []auth.User{{Username: "user", Password: "pass"}},
	})
	rejected := startTestConnection(t, inbound, context.Background())
	rejected.write(t, []byte{0x05, 0x01, 0x02})
	if reply := rejected.read(t, 2); !bytes.Equal(reply, []byte{0x05, 0x02}) {
		t.Fatalf("unexpected method selection: %x", reply)
	}
	rejected.write(t, []byte{0x01, 0x04, 'u', 's', 'e', 'r', 0x03, 'b', 'a', 'd'})
	if reply := rejected.read(t, 2); !bytes.Equal(reply, []byte{0x01, 0x01}) {
		t.Fatalf("unexpected authentication status: %x", reply)
	}
	router.expectNoRoute(t)

	accepted := startTestConnection(t, inbound, context.Background())
	accepted.write(t, []byte{0x05, 0x01, 0x02})
	if reply := accepted.read(t, 2); !bytes.Equal(reply, []byte{0x05, 0x02}) {
		t.Fatalf("unexpected method selection: %x", reply)
	}
	accepted.write(t, []byte{0x01, 0x04, 'u', 's', 'e', 'r', 0x04, 'p', 'a', 's', 's'})
	if reply := accepted.read(t, 2); !bytes.Equal(reply, []byte{0x01, 0x00}) {
		t.Fatalf("unexpected authentication status: %x", reply)
	}
	addr := netip.MustParseAddr("203.0.113.10")
	accepted.write(t, socks5RequestATYP1(addr, 443))
	call := router.waitRoute(t)
	if call.metadata.User != "user" {
		t.Fatalf("routed user = %q", call.metadata.User)
	}
	if call.metadata.Destination.Addr != addr {
		t.Fatalf("routed destination = %v", call.metadata.Destination)
	}
	_ = call.conn.Close()
}

func TestSOCKS5NoResolveKeepsUoTransport(t *testing.T) {
	inbound, router := newTestInbound(t, nil, option.SocksInboundOptions{NoResolve: true})
	connection := startTestConnection(t, inbound, context.Background())
	connection.negotiateSOCKS5(t)
	connection.write(t, socks5RequestATYP3(uot.LegacyMagicAddress, 0))
	deadline := time.Now().Add(5 * time.Second)
	for router.packetRouted() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if count := router.packetRouted(); count != 1 {
		t.Fatalf("UoT packet route count = %d, want 1", count)
	}
	router.expectNoRoute(t)
}

func TestSOCKS4aNoResolveRejectsDomain(t *testing.T) {
	services := newResolverServices()
	services.transports.transports["default-dns"] = &fakeDNSTransport{tag: "default-dns"}
	inbound, router := newTestInbound(t, services, option.SocksInboundOptions{
		NoResolve:           true,
		ResolverConcurrency: ptrValue(uint16(1)),
	})
	connection := startTestConnection(t, inbound, context.Background())
	connection.write(t, socks4aRequest("example.com", 80))
	expectSOCKS4Failure(t, connection)
	if count := services.router.lookupCount(); count != 0 {
		t.Fatalf("no_resolve performed %d DNS lookups", count)
	}
	router.expectNoRoute(t)
	err := connection.waitClose(t)
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("onClose error = %v, want syscall.EPERM", err)
	}
}

func TestSOCKS4aNoResolveRejectsIPLookingDomain(t *testing.T) {
	// The shared SOCKS4a parser normalizes an IP-looking hostname into a
	// literal address, but the retained wire provenance still reports the
	// SOCKS4a hostname form, so no_resolve refuses it before any other owner.
	inbound, router := newTestInbound(t, nil, option.SocksInboundOptions{NoResolve: true})
	connection := startTestConnection(t, inbound, context.Background())
	connection.write(t, socks4aRequest("192.0.2.9", 443))
	expectSOCKS4Failure(t, connection)
	router.expectNoRoute(t)
	err := connection.waitClose(t)
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("onClose error = %v, want syscall.EPERM", err)
	}
}

func TestSOCKS4LiteralBypassesNoResolve(t *testing.T) {
	inbound, router := newTestInbound(t, nil, option.SocksInboundOptions{NoResolve: true})
	connection := startTestConnection(t, inbound, context.Background())
	addr := netip.MustParseAddr("192.0.2.9")
	connection.write(t, socks4Request(addr, 443))
	call := router.waitRoute(t)
	if call.metadata.Destination.Addr != addr || call.metadata.Destination.Port != 443 {
		t.Fatalf("routed destination = %v", call.metadata.Destination)
	}
	_ = call.conn.Close()
}

func TestSOCKS5ResolvesDomainBeforeRoute(t *testing.T) {
	services := newResolverServices()
	localTransport := &fakeDNSTransport{tag: "dns-local"}
	services.transports.transports["dns-local"] = localTransport
	services.transports.transports["default-dns"] = &fakeDNSTransport{tag: "default-dns"}
	addresses := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}
	services.router.lookupFunc = func(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
		return addresses, nil
	}
	inbound, router := newTestInbound(t, services, option.SocksInboundOptions{
		ResolverConcurrency: ptrValue(uint16(2)),
		DomainResolver: &option.DomainResolveOptions{
			Server:   "dns-local",
			Strategy: option.DomainStrategy(C.DomainStrategyIPv4Only),
		},
	})
	connection := startTestConnection(t, inbound, context.Background())
	connection.negotiateSOCKS5(t)
	connection.write(t, socks5RequestATYP3("example.com", 443))
	call := router.waitRoute(t)
	if call.metadata.Destination.Fqdn != "example.com" || call.metadata.Destination.Port != 443 {
		t.Fatalf("routed destination = %v", call.metadata.Destination)
	}
	if len(call.metadata.DestinationAddresses) != 2 || call.metadata.DestinationAddresses[0] != addresses[0] || call.metadata.DestinationAddresses[1] != addresses[1] {
		t.Fatalf("routed addresses = %v", call.metadata.DestinationAddresses)
	}
	if count := services.router.lookupCount(); count != 1 {
		t.Fatalf("lookup count = %d, want 1", count)
	}
	lookup := services.router.lookupAt(0)
	if lookup.domain != "example.com" {
		t.Fatalf("lookup domain = %q", lookup.domain)
	}
	if lookup.options.Transport != localTransport {
		t.Fatal("Lookup did not receive the configured domain_resolver transport")
	}
	if lookup.options.Strategy != C.DomainStrategyIPv4Only {
		t.Fatalf("Lookup strategy = %v", lookup.options.Strategy)
	}
	if len(inbound.resolver.slots) != 0 {
		t.Fatalf("resolver slot was not released after the lookup: %d", len(inbound.resolver.slots))
	}
	if queued := inbound.resolver.queued.Load(); queued != 0 {
		t.Fatalf("resolver queued counter = %d", queued)
	}
	_ = call.conn.Close()
}

func TestSOCKS5LiteralSkipsResolver(t *testing.T) {
	services := newResolverServices()
	services.transports.transports["default-dns"] = &fakeDNSTransport{tag: "default-dns"}
	inbound, router := newTestInbound(t, services, option.SocksInboundOptions{
		ResolverConcurrency: ptrValue(uint16(2)),
	})
	connection := startTestConnection(t, inbound, context.Background())
	connection.negotiateSOCKS5(t)
	addr := netip.MustParseAddr("192.0.2.20")
	connection.write(t, socks5RequestATYP1(addr, 443))
	call := router.waitRoute(t)
	if call.metadata.Destination.Addr != addr {
		t.Fatalf("routed destination = %v", call.metadata.Destination)
	}
	if len(call.metadata.DestinationAddresses) != 0 {
		t.Fatalf("literal destination carried resolver addresses: %v", call.metadata.DestinationAddresses)
	}
	if count := services.router.lookupCount(); count != 0 {
		t.Fatalf("literal destination performed %d DNS lookups", count)
	}
	_ = call.conn.Close()
}

func TestSOCKS5ResolverNXDOMAIN(t *testing.T) {
	services := newResolverServices()
	services.transports.transports["default-dns"] = &fakeDNSTransport{tag: "default-dns"}
	services.router.lookupFunc = func(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
		return nil, errors.New("lookup example.com: no such host")
	}
	inbound, router := newTestInbound(t, services, option.SocksInboundOptions{
		ResolverConcurrency: ptrValue(uint16(1)),
	})
	connection := startTestConnection(t, inbound, context.Background())
	connection.negotiateSOCKS5(t)
	connection.write(t, socks5RequestATYP3("example.com", 443))
	expectSOCKS5Failure(t, connection, 0x01)
	router.expectNoRoute(t)
	if len(inbound.resolver.slots) != 0 {
		t.Fatal("resolver slot was not released after a failed lookup")
	}
}

func TestSOCKS5ResolverQueueFullRejectsConnection(t *testing.T) {
	services := newResolverServices()
	services.transports.transports["default-dns"] = &fakeDNSTransport{tag: "default-dns"}
	release := make(chan struct{})
	services.router.lookupFunc = func(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	}
	inbound, router := newTestInbound(t, services, option.SocksInboundOptions{
		ListenOptions:       option.ListenOptions{TCPMaxConnections: ptrValue(uint16(2))},
		ResolverConcurrency: ptrValue(uint16(1)),
	})
	first := startTestConnection(t, inbound, context.Background())
	first.negotiateSOCKS5(t)
	first.write(t, socks5RequestATYP3("first.example", 443))
	deadline := time.Now().Add(5 * time.Second)
	for services.router.lookupCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if services.router.lookupCount() != 1 {
		t.Fatal("first lookup did not start")
	}
	waiting := make([]*testConnection, 0, 2)
	for _, domain := range []string{"second.example", "third.example"} {
		connection := startTestConnection(t, inbound, context.Background())
		connection.negotiateSOCKS5(t)
		connection.write(t, socks5RequestATYP3(domain, 443))
		waiting = append(waiting, connection)
	}
	deadline = time.Now().Add(5 * time.Second)
	for inbound.resolver.queued.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if queued := inbound.resolver.queued.Load(); queued != 2 {
		t.Fatalf("queued lookups = %d, want 2", queued)
	}
	overflow := startTestConnection(t, inbound, context.Background())
	overflow.negotiateSOCKS5(t)
	overflow.write(t, socks5RequestATYP3("overflow.example", 443))
	expectSOCKS5Failure(t, overflow, 0x01)
	if count := services.router.lookupCount(); count != 1 {
		t.Fatalf("overflow connection reached the DNS router: %d lookups", count)
	}
	close(release)
	if call := router.waitRoute(t); call.metadata.Destination.Fqdn == "" {
		t.Fatal("unexpected empty routed destination")
	}
	deadline = time.Now().Add(5 * time.Second)
	for router.routed() < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if count := router.routed(); count != 3 {
		t.Fatalf("routed connections = %d, want 3", count)
	}
	if count := services.router.lookupCount(); count != 3 {
		t.Fatalf("lookup count = %d, want 3", count)
	}
	_ = waiting
}

func TestSOCKS5ResolverCanceledWhileQueued(t *testing.T) {
	services := newResolverServices()
	services.transports.transports["default-dns"] = &fakeDNSTransport{tag: "default-dns"}
	release := make(chan struct{})
	services.router.lookupFunc = func(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	}
	inbound, router := newTestInbound(t, services, option.SocksInboundOptions{
		ResolverConcurrency: ptrValue(uint16(1)),
	})
	first := startTestConnection(t, inbound, context.Background())
	first.negotiateSOCKS5(t)
	first.write(t, socks5RequestATYP3("first.example", 443))
	deadline := time.Now().Add(5 * time.Second)
	for services.router.lookupCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancelCtx, cancel := context.WithCancel(context.Background())
	second := startTestConnection(t, inbound, cancelCtx)
	second.negotiateSOCKS5(t)
	second.write(t, socks5RequestATYP3("second.example", 443))
	deadline = time.Now().Add(5 * time.Second)
	for inbound.resolver.queued.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	expectSOCKS5Failure(t, second, 0x01)
	if count := services.router.lookupCount(); count != 1 {
		t.Fatalf("canceled connection reached the DNS router: %d lookups", count)
	}
	router.expectNoRoute(t)
	close(release)
	call := router.waitRoute(t)
	if call.metadata.Destination.Fqdn != "first.example" {
		t.Fatalf("routed destination = %v", call.metadata.Destination)
	}
	if queued := inbound.resolver.queued.Load(); queued != 0 {
		t.Fatalf("queued counter leaked: %d", queued)
	}
	_ = call.conn.Close()
}

func TestSOCKS5ResolverLateResultIsNotRouted(t *testing.T) {
	services := newResolverServices()
	services.transports.transports["default-dns"] = &fakeDNSTransport{tag: "default-dns"}
	release := make(chan struct{})
	services.router.lookupFunc = func(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
		// Deliberately ignore cancellation: the late result must still be
		// discarded by the inbound before routing.
		<-release
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	}
	inbound, router := newTestInbound(t, services, option.SocksInboundOptions{
		ResolverConcurrency: ptrValue(uint16(1)),
	})
	ctx, cancel := context.WithCancel(context.Background())
	connection := startTestConnection(t, inbound, ctx)
	connection.negotiateSOCKS5(t)
	connection.write(t, socks5RequestATYP3("late.example", 443))
	deadline := time.Now().Add(5 * time.Second)
	for services.router.lookupCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	close(release)
	expectSOCKS5Failure(t, connection, 0x01)
	router.expectNoRoute(t)
	if count := router.routed(); count != 0 {
		t.Fatalf("late DNS result was routed: %d", count)
	}
}

func TestSOCKS5ResolverSlotReleasedAfterLookup(t *testing.T) {
	services := newResolverServices()
	services.transports.transports["default-dns"] = &fakeDNSTransport{tag: "default-dns"}
	services.router.lookupFunc = func(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	}
	inbound, router := newTestInbound(t, services, option.SocksInboundOptions{
		ResolverConcurrency: ptrValue(uint16(1)),
	})
	first := startTestConnection(t, inbound, context.Background())
	first.negotiateSOCKS5(t)
	first.write(t, socks5RequestATYP3("one.example", 443))
	firstCall := router.waitRoute(t)
	// The first connection is still open; the single slot must already be free.
	second := startTestConnection(t, inbound, context.Background())
	second.negotiateSOCKS5(t)
	second.write(t, socks5RequestATYP3("two.example", 443))
	secondCall := router.waitRoute(t)
	if count := services.router.lookupCount(); count != 2 {
		t.Fatalf("lookup count = %d, want 2", count)
	}
	_ = firstCall.conn.Close()
	_ = secondCall.conn.Close()
}

func TestSOCKS5DomainResolverWithoutConcurrencyKeepsOldBehavior(t *testing.T) {
	services := newResolverServices()
	services.transports.transports["default-dns"] = &fakeDNSTransport{tag: "default-dns"}
	inbound, router := newTestInbound(t, services, option.SocksInboundOptions{
		DomainResolver: &option.DomainResolveOptions{Server: "default-dns"},
	})
	if inbound.resolver != nil {
		t.Fatal("domain_resolver alone must not create resolver slots")
	}
	connection := startTestConnection(t, inbound, context.Background())
	connection.negotiateSOCKS5(t)
	connection.write(t, socks5RequestATYP3("example.com", 443))
	call := router.waitRoute(t)
	if call.metadata.Destination.Fqdn != "example.com" {
		t.Fatalf("routed destination = %v", call.metadata.Destination)
	}
	if len(call.metadata.DestinationAddresses) != 0 {
		t.Fatalf("old behavior resolved the destination: %v", call.metadata.DestinationAddresses)
	}
	if count := services.router.lookupCount(); count != 0 {
		t.Fatalf("inbound performed %d DNS lookups", count)
	}
	_ = call.conn.Close()
}

func TestSOCKS5FragmentedHandshake(t *testing.T) {
	inbound, router := newTestInbound(t, nil, option.SocksInboundOptions{NoResolve: true})
	connection := startTestConnection(t, inbound, context.Background())
	for _, fragment := range [][]byte{{0x05}, {0x01}, {0x00}} {
		connection.write(t, fragment)
	}
	reply := connection.read(t, 2)
	if !bytes.Equal(reply, []byte{0x05, 0x00}) {
		t.Fatalf("unexpected method selection: %x", reply)
	}
	addr := netip.MustParseAddr("198.51.100.7")
	request := socks5RequestATYP1(addr, 443)
	for _, fragment := range [][]byte{request[0:2], request[2:5], request[5:8], request[8:]} {
		connection.write(t, fragment)
	}
	call := router.waitRoute(t)
	if call.metadata.Destination.Addr != addr {
		t.Fatalf("routed destination = %v", call.metadata.Destination)
	}
	_ = call.conn.Close()
}

func TestSOCKS5PipelinedHandshake(t *testing.T) {
	inbound, router := newTestInbound(t, nil, option.SocksInboundOptions{NoResolve: true})
	connection := startTestConnection(t, inbound, context.Background())
	payload := []byte{0x05, 0x01, 0x00}
	payload = append(payload, socks5RequestATYP3("example.com", 443)...)
	payload = append(payload, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")...)
	connection.write(t, payload)
	if reply := connection.read(t, 2); !bytes.Equal(reply, []byte{0x05, 0x00}) {
		t.Fatalf("unexpected method selection: %x", reply)
	}
	expectSOCKS5Failure(t, connection, 0x02)
	router.expectNoRoute(t)
}

func TestSOCKS5PipelinedHandshakeWithEarlyData(t *testing.T) {
	services := newResolverServices()
	services.transports.transports["default-dns"] = &fakeDNSTransport{tag: "default-dns"}
	services.router.lookupFunc = func(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.44")}, nil
	}
	inbound, router := newTestInbound(t, services, option.SocksInboundOptions{
		ResolverConcurrency: ptrValue(uint16(2)),
	})
	connection := startTestConnection(t, inbound, context.Background())
	payload := []byte{0x05, 0x01, 0x00}
	payload = append(payload, socks5RequestATYP3("pipelined.example", 443)...)
	payload = append(payload, []byte("GET / HTTP/1.1\r\nHost: pipelined.example\r\n\r\n")...)
	connection.write(t, payload)
	if reply := connection.read(t, 2); !bytes.Equal(reply, []byte{0x05, 0x00}) {
		t.Fatalf("unexpected method selection: %x", reply)
	}
	call := router.waitRoute(t)
	if call.metadata.Destination.Fqdn != "pipelined.example" {
		t.Fatalf("routed destination = %v", call.metadata.Destination)
	}
	if len(call.metadata.DestinationAddresses) != 1 || call.metadata.DestinationAddresses[0] != netip.MustParseAddr("192.0.2.44") {
		t.Fatalf("routed addresses = %v", call.metadata.DestinationAddresses)
	}
	_ = call.conn.Close()
}

func TestSOCKS5ResolvedLookupCarriesInboundContext(t *testing.T) {
	services := newResolverServices()
	services.transports.transports["default-dns"] = &fakeDNSTransport{tag: "default-dns"}
	contexts := make(chan *adapter.InboundContext, 1)
	services.router.lookupFunc = func(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
		contexts <- adapter.ContextFrom(ctx)
		return []netip.Addr{netip.MustParseAddr("192.0.2.45")}, nil
	}
	inbound, router := newTestInbound(t, services, option.SocksInboundOptions{
		ResolverConcurrency: ptrValue(uint16(1)),
	})
	connection := startTestConnection(t, inbound, context.Background())
	connection.negotiateSOCKS5(t)
	connection.write(t, socks5RequestATYP3("context.example", 443))
	call := router.waitRoute(t)
	select {
	case lookupMetadata := <-contexts:
		if lookupMetadata == nil {
			t.Fatal("lookup context carried no inbound metadata")
		}
		if lookupMetadata.Inbound != "socks-in" || lookupMetadata.InboundType != C.TypeSOCKS {
			t.Fatalf("lookup metadata inbound = %q/%q", lookupMetadata.Inbound, lookupMetadata.InboundType)
		}
		if lookupMetadata.Destination.Fqdn != "context.example" {
			t.Fatalf("lookup metadata destination = %v", lookupMetadata.Destination)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lookup did not run")
	}
	_ = call.conn.Close()
}

func TestSOCKS5NoResolveRejectsIPLookingDomainWireForms(t *testing.T) {
	// ATYP=3 is the original domain form even when the text parses as an IP;
	// the retained wire provenance refuses all of them before route or DNS.
	fixtures := []struct {
		name   string
		domain string
	}{
		{name: "numeric-ipv4", domain: "203.0.113.9"},
		{name: "numeric-ipv6", domain: "2001:db8::9"},
		{name: "numeric-ipv4-mapped", domain: "::ffff:203.0.113.9"},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			services := newResolverServices()
			services.transports.transports["default-dns"] = &fakeDNSTransport{tag: "default-dns"}
			inbound, router := newTestInbound(t, services, option.SocksInboundOptions{
				NoResolve:           true,
				ResolverConcurrency: ptrValue(uint16(1)),
			})
			connection := startTestConnection(t, inbound, context.Background())
			connection.negotiateSOCKS5(t)
			connection.write(t, socks5RequestATYP3(fixture.domain, 443))
			expectSOCKS5Failure(t, connection, 0x02)
			if count := services.router.lookupCount(); count != 0 {
				t.Fatalf("no_resolve performed %d DNS lookups", count)
			}
			router.expectNoRoute(t)
			err := connection.waitClose(t)
			if !errors.Is(err, syscall.EPERM) {
				t.Fatalf("onClose error = %v, want syscall.EPERM", err)
			}
		})
	}
}

type fakePacketListener struct {
	conn net.PacketConn
	err  error
}

func (l *fakePacketListener) ListenPacket(listenConfig net.ListenConfig, ctx context.Context, network string, address string) (net.PacketConn, error) {
	return l.conn, l.err
}

type fakePacketConn struct {
	localAddr net.Addr
	readErr   error
}

func (c *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return 0, nil, c.readErr
}

func (c *fakePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return len(p), nil
}

func (c *fakePacketConn) Close() error                       { return nil }
func (c *fakePacketConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *fakePacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakePacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fakePacketConn) SetWriteDeadline(t time.Time) error { return nil }

func TestSOCKS5UDPAssociateRetainedWithNoResolve(t *testing.T) {
	inbound, router := newTestInbound(t, nil, option.SocksInboundOptions{NoResolve: true})
	inbound.packetListener = &fakePacketListener{
		conn: &fakePacketConn{
			localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353},
			readErr:   io.EOF,
		},
	}
	connection := startTestConnection(t, inbound, context.Background())
	connection.negotiateSOCKS5(t)
	request := []byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	connection.write(t, request)
	reply := connection.read(t, 10)
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("UDP associate reply = %x, want success", reply)
	}
	router.expectNoRoute(t)
}

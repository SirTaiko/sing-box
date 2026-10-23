package dialer

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func dialerAddr(value string) *badoption.Addr {
	address, err := netip.ParseAddr(value)
	if err != nil {
		panic(err)
	}
	addr := badoption.Addr(address)
	return &addr
}

func TestResolveBindZone(t *testing.T) {
	global, _ := netip.ParseAddr("2001:db8::1")
	resolved, err := resolveBindZone(global, "")
	if err != nil || resolved.String() != "2001:db8::1" {
		t.Fatalf("global address changed: %v %v", resolved, err)
	}
	linkLocal, _ := netip.ParseAddr("fe80::1")
	if _, err = resolveBindZone(linkLocal, ""); err == nil {
		t.Fatal("a link-local source without a zone must be rejected")
	}
	resolved, err = resolveBindZone(linkLocal, "eth0")
	if err != nil || resolved.Zone() != "eth0" {
		t.Fatalf("bind interface zone not applied: %v %v", resolved, err)
	}
	zoned, _ := netip.ParseAddr("fe80::1%eth9")
	resolved, err = resolveBindZone(zoned, "eth0")
	if err != nil || resolved.Zone() != "eth9" {
		t.Fatalf("explicit zone must win: %v %v", resolved, err)
	}
}

func TestNewDefaultPropagatesIPv6Zone(t *testing.T) {
	options := option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{
			Inet6BindAddress: dialerAddr("fe80::1234"),
			BindInterface:    "eth0",
		},
	}
	defaultDialer, err := NewDefault(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	tcpAddr, isTCPAddr := defaultDialer.dialer6.Dialer.LocalAddr.(*net.TCPAddr)
	if !isTCPAddr {
		t.Fatalf("unexpected TCP local address %T", defaultDialer.dialer6.Dialer.LocalAddr)
	}
	if tcpAddr.Zone != "eth0" {
		t.Fatalf("TCP source zone dropped: %+v", tcpAddr)
	}
	if !tcpAddr.IP.Equal(net.ParseIP("fe80::1234")) {
		t.Fatalf("TCP source address changed: %+v", tcpAddr)
	}
	udpAddr, isUDPAddr := defaultDialer.udpDialer6.LocalAddr.(*net.UDPAddr)
	if !isUDPAddr || udpAddr.Zone != "eth0" {
		t.Fatalf("UDP source zone dropped: %+v", defaultDialer.udpDialer6.LocalAddr)
	}
	if !strings.Contains(defaultDialer.udpAddr6, "%eth0") {
		t.Fatalf("endpoint identity lost the zone: %s", defaultDialer.udpAddr6)
	}
	// An explicit zone is preserved, not replaced by bind_interface.
	options.Inet6BindAddress = dialerAddr("fe80::1234%eth9")
	defaultDialer, err = NewDefault(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	tcpAddr = defaultDialer.dialer6.Dialer.LocalAddr.(*net.TCPAddr)
	if tcpAddr.Zone != "eth9" {
		t.Fatalf("explicit source zone not preserved: %+v", tcpAddr)
	}
	// No zone and no bind interface is an explicit error, never scope 0.
	options.Inet6BindAddress = dialerAddr("fe80::1234")
	options.BindInterface = ""
	if _, err = NewDefault(context.Background(), options); err == nil {
		t.Fatal("a scoped source without a resolvable zone must fail")
	}
}

func TestNewDefaultInstallsRemoteSocketOptions(t *testing.T) {
	// Absent options keep the exact previous option state and do not add our
	// socket control to the chain.
	plain, err := NewDefault(context.Background(), option.DialerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !plain.tcpSocketOptions.Empty() {
		t.Fatalf("unexpected built options %+v", plain.tcpSocketOptions)
	}
	if plain.tcpSocketControl != nil {
		t.Fatal("absent tcp_socket_options must not install a control")
	}
	receiveBuffer := uint32(1_000_000)
	sendBuffer := uint32(500_000)
	timeout := badoption.Duration(20 * time.Second)
	configured, err := NewDefault(context.Background(), option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{
			TCPSocketOptions: &option.TCPSocketOptions{
				ReceiveBufferSize: &receiveBuffer,
				SendBufferSize:    &sendBuffer,
				UserTimeout:       &timeout,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if configured.dialer4.Dialer.Control == nil || configured.dialer6.Dialer.Control == nil {
		t.Fatal("TCP options must be installed on both family dialers")
	}
	// The composed control chain changed, proving the options control was
	// prepended to the shared base dialer (and therefore to every copy used
	// by standard, parallel, fallback and deferred-TFO entrypoints).
	if configured.tcpSocketControl == nil {
		t.Fatal("tcp_socket_options did not install a socket control")
	}
	if err = configured.tcpSocketControl("udp", "192.0.2.1:53", nil); err != nil {
		t.Fatalf("the socket options control must skip UDP: %v", err)
	}
	// The deferred TFO facade wraps the same prepared net.Dialer, so the
	// control is present on that entrypoint too.
	if configured.dialer4.Dialer.Control == nil || configured.dialer6.Dialer.Control == nil {
		t.Fatal("TFO dialers lost the socket control")
	}
	if configured.tcpSocketOptions.ReceiveBufferSize != 500_000 || configured.tcpSocketOptions.SendBufferSize != 250_000 {
		t.Fatalf("Linux halving not applied: %+v", configured.tcpSocketOptions)
	}
	if configured.tcpSocketOptions.UserTimeoutMillis != 20_000 {
		t.Fatalf("user timeout milliseconds: %+v", configured.tcpSocketOptions)
	}
}

func TestNewDefaultRejectsInvalidSocketOptions(t *testing.T) {
	oversized := uint32(1 << 31)
	if _, err := NewDefault(context.Background(), option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{
			TCPSocketOptions: &option.TCPSocketOptions{ReceiveBufferSize: &oversized},
		},
	}); err == nil {
		t.Fatal("an out-of-range buffer must be rejected")
	}
	subMillisecond := badoption.Duration(1500 * time.Microsecond)
	if _, err := NewDefault(context.Background(), option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{
			TCPSocketOptions: &option.TCPSocketOptions{UserTimeout: &subMillisecond},
		},
	}); err == nil {
		t.Fatal("a positive sub-millisecond user timeout must be rejected")
	}
}

func TestLocalAddrPortKeepsZone(t *testing.T) {
	address := &net.TCPAddr{IP: net.ParseIP("fe80::1"), Zone: "eth0", Port: 1234}
	addrPort := localAddrPort(address)
	if addrPort.Addr().Zone() != "eth0" || addrPort.Port() != 1234 {
		t.Fatalf("attempt source fact lost the zone: %+v", addrPort)
	}
}

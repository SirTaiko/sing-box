package listener

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/json/badoption"
)

type fakeBindSource struct {
	snapshot func() []control.Interface
	calls    int
}

func (s *fakeBindSource) Interfaces() []control.Interface {
	s.calls++
	return s.snapshot()
}

type fakeBindClock struct {
	now     time.Time
	waits   int
	onWait  func()
	failNow error
}

func (c *fakeBindClock) Now() time.Time {
	return c.now
}

func (c *fakeBindClock) Wait(ctx context.Context, duration time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.failNow != nil {
		return c.failNow
	}
	c.waits++
	if c.onWait != nil {
		c.onWait()
	}
	c.now = c.now.Add(duration)
	return nil
}

func mustAddr(t *testing.T, value string) netip.Addr {
	t.Helper()
	address, err := netip.ParseAddr(value)
	if err != nil {
		t.Fatal(err)
	}
	return address
}

func mustPrefix(t *testing.T, value string) netip.Prefix {
	t.Helper()
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		t.Fatal(err)
	}
	return prefix
}

func testInterface(t *testing.T, name string, index int, flags net.Flags, prefixes ...string) control.Interface {
	t.Helper()
	addresses := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		addresses = append(addresses, mustPrefix(t, prefix))
	}
	return control.Interface{Name: name, Index: index, Flags: flags, Addresses: addresses}
}

func staticSource(interfaces ...control.Interface) *fakeBindSource {
	return &fakeBindSource{snapshot: func() []control.Interface {
		return interfaces
	}}
}

func upInterfaces(t *testing.T) []control.Interface {
	return []control.Interface{
		testInterface(t, "eth0", 1, net.FlagUp, "fe80::1/64", "fd00::1/8", "2001:db8::1/64"),
		testInterface(t, "eth1", 2, net.FlagUp, "fe80::2/64", "2001:db8:1::1/64"),
	}
}

func TestResolveTCPBindingsRanking(t *testing.T) {
	interfaces := upInterfaces(t)
	cases := []struct {
		name       string
		linkLocal  option.TCPListenLinkLocal
		expected   string
		expectFail bool
	}{
		{"unwanted-ula-first", option.TCPListenLinkLocalUnwanted, "fd00::1", false},
		{"prefer-linklocal-first", option.TCPListenLinkLocalPrefer, "fe80::1%eth0", false},
		{"force-linklocal-only", option.TCPListenLinkLocalForce, "fe80::1%eth0", false},
		{"no-ula-first", option.TCPListenLinkLocalNo, "fd00::1", false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			clock := &fakeBindClock{now: time.Unix(100, 0)}
			resolved, err := ResolveTCPBindings(context.Background(), []option.TCPListenBinding{{
				Interface: "eth0",
				IPVersion: 6,
				LinkLocal: testCase.linkLocal,
			}}, staticSource(interfaces...), clock)
			if testCase.expectFail {
				if err == nil {
					t.Fatal("expected a resolution error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if resolved[0].Address.String() != testCase.expected {
				t.Fatalf("expected %s, got %s", testCase.expected, resolved[0].Address)
			}
			if resolved[0].Interface != "eth0" || resolved[0].IPVersion != 6 {
				t.Fatalf("unexpected resolved facts %+v", resolved[0])
			}
			if clock.waits != 0 {
				t.Fatalf("a present address must not wait, waits=%d", clock.waits)
			}
		})
	}
}

func TestResolveTCPBindingsFallbackRanks(t *testing.T) {
	onlyGlobal := []control.Interface{testInterface(t, "eth0", 1, net.FlagUp, "2001:db8::1/64")}
	clock := &fakeBindClock{now: time.Unix(100, 0)}
	resolved, err := ResolveTCPBindings(context.Background(), []option.TCPListenBinding{{
		Interface: "eth0", IPVersion: 6, LinkLocal: option.TCPListenLinkLocalPrefer,
	}}, staticSource(onlyGlobal...), clock)
	if err != nil {
		t.Fatal(err)
	}
	if resolved[0].Address.String() != "2001:db8::1" {
		t.Fatalf("prefer must fall back to a global address, got %s", resolved[0].Address)
	}
	onlyLinkLocal := []control.Interface{testInterface(t, "eth0", 1, net.FlagUp, "fe80::1/64")}
	clock = &fakeBindClock{now: time.Unix(100, 0)}
	resolved, err = ResolveTCPBindings(context.Background(), []option.TCPListenBinding{{
		Interface: "eth0", IPVersion: 6, LinkLocal: option.TCPListenLinkLocalUnwanted,
	}}, staticSource(onlyLinkLocal...), clock)
	if err != nil {
		t.Fatal(err)
	}
	if resolved[0].Address.String() != "fe80::1%eth0" {
		t.Fatalf("unwanted must fall back to a zoned link-local address, got %s", resolved[0].Address)
	}
	if resolved[0].Address.Zone() != "eth0" {
		t.Fatalf("link-local selection must carry the interface zone, got %q", resolved[0].Address.Zone())
	}
	clock = &fakeBindClock{now: time.Unix(100, 0)}
	if _, err = ResolveTCPBindings(context.Background(), []option.TCPListenBinding{{
		Interface: "eth0", IPVersion: 6, LinkLocal: option.TCPListenLinkLocalNo,
	}}, staticSource(onlyLinkLocal...), clock); err == nil {
		t.Fatal("link_local=no must not select a link-local address")
	}
}

func TestResolveTCPBindingsPreferGrace(t *testing.T) {
	// Only a ULA is present: during the link-local grace `prefer` behaves as
	// `force`, then the normal ranking accepts the ULA at the exact boundary.
	ulaOnly := []control.Interface{testInterface(t, "eth0", 1, net.FlagUp, "fd00::1/8")}
	clock := &fakeBindClock{now: time.Unix(100, 0)}
	resolved, err := ResolveTCPBindings(context.Background(), []option.TCPListenBinding{{
		Interface:       "eth0",
		IPVersion:       6,
		LinkLocal:       option.TCPListenLinkLocalPrefer,
		WaitIP:          badoption.Duration(5 * time.Second),
		WaitIPLinkLocal: badoption.Duration(2 * time.Second),
	}}, staticSource(ulaOnly...), clock)
	if err != nil {
		t.Fatal(err)
	}
	if resolved[0].Address.String() != "fd00::1" {
		t.Fatalf("unexpected address %s", resolved[0].Address)
	}
	if elapsed := clock.now.Sub(time.Unix(100, 0)); elapsed != 2*time.Second {
		t.Fatalf("grace must end exactly at 2s, resolved after %s", elapsed)
	}
}

func TestResolveTCPBindingsUnwantedGrace(t *testing.T) {
	linkLocalOnly := []control.Interface{testInterface(t, "eth0", 1, net.FlagUp, "fe80::1/64")}
	clock := &fakeBindClock{now: time.Unix(100, 0)}
	resolved, err := ResolveTCPBindings(context.Background(), []option.TCPListenBinding{{
		Interface:       "eth0",
		IPVersion:       6,
		WaitIP:          badoption.Duration(5 * time.Second),
		WaitIPLinkLocal: badoption.Duration(2 * time.Second),
	}}, staticSource(linkLocalOnly...), clock)
	if err != nil {
		t.Fatal(err)
	}
	if resolved[0].Address.Zone() != "eth0" {
		t.Fatalf("unexpected address %s", resolved[0].Address)
	}
	if elapsed := clock.now.Sub(time.Unix(100, 0)); elapsed != 2*time.Second {
		t.Fatalf("unwanted grace must end exactly at 2s, resolved after %s", elapsed)
	}
}

func TestResolveTCPBindingsSeparateIfUpDeadline(t *testing.T) {
	start := time.Unix(100, 0)
	clock := &fakeBindClock{now: start}
	source := &fakeBindSource{snapshot: func() []control.Interface {
		flags := net.Flags(0)
		if !clock.now.Before(start.Add(2 * time.Second)) {
			flags = net.FlagUp
		}
		return []control.Interface{testInterface(t, "eth0", 1, flags, "2001:db8::1/64")}
	}}
	resolved, err := ResolveTCPBindings(context.Background(), []option.TCPListenBinding{{
		Interface: "eth0",
		IPVersion: 6,
		WaitIfUp:  badoption.Duration(2 * time.Second),
		WaitIP:    badoption.Duration(4 * time.Second),
	}}, source, clock)
	if err != nil {
		t.Fatal(err)
	}
	if resolved[0].Address.String() != "2001:db8::1" {
		t.Fatalf("unexpected address %s", resolved[0].Address)
	}
	if elapsed := clock.now.Sub(start); elapsed != 2*time.Second {
		t.Fatalf("ifup wait consumed the wrong budget: %s", elapsed)
	}
	// wait_ifup own timeout: the interface never comes up.
	clock = &fakeBindClock{now: start}
	downSource := staticSource(testInterface(t, "eth0", 1, 0, "2001:db8::1/64"))
	_, err = ResolveTCPBindings(context.Background(), []option.TCPListenBinding{{
		Interface: "eth0",
		IPVersion: 6,
		WaitIfUp:  badoption.Duration(time.Second),
		WaitIP:    badoption.Duration(4 * time.Second),
	}}, downSource, clock)
	if err == nil {
		t.Fatal("expected an ifup timeout")
	}
	if elapsed := clock.now.Sub(start); elapsed != time.Second {
		t.Fatalf("ifup timeout boundary wrong: %s", elapsed)
	}
}

func TestResolveTCPBindingsIPDeadlineBoundary(t *testing.T) {
	start := time.Unix(100, 0)
	empty := staticSource(testInterface(t, "eth0", 1, net.FlagUp))
	clock := &fakeBindClock{now: start}
	_, err := ResolveTCPBindings(context.Background(), []option.TCPListenBinding{{
		Interface: "eth0",
		IPVersion: 6,
		WaitIP:    badoption.Duration(2 * time.Second),
	}}, empty, clock)
	if err == nil {
		t.Fatal("expected an address timeout")
	}
	if elapsed := clock.now.Sub(start); elapsed != 2*time.Second {
		t.Fatalf("deadline boundary wrong: %s", elapsed)
	}
	// wait_ip=0 makes exactly one attempt and does not wait.
	clock = &fakeBindClock{now: start}
	_, err = ResolveTCPBindings(context.Background(), []option.TCPListenBinding{{
		Interface: "eth0", IPVersion: 6,
	}}, empty, clock)
	if err == nil || clock.waits != 0 {
		t.Fatalf("wait_ip=0 must fail immediately, waits=%d err=%v", clock.waits, err)
	}
}

func TestResolveTCPBindingsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ResolveTCPBindings(ctx, []option.TCPListenBinding{{
		Interface: "eth0", IPVersion: 6, WaitIP: badoption.Duration(time.Minute),
	}}, staticSource(), &fakeBindClock{now: time.Unix(100, 0)})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	// A cancellation during a wait is propagated too.
	ctx, cancel = context.WithCancel(context.Background())
	clock := &fakeBindClock{now: time.Unix(100, 0), onWait: cancel}
	_, err = ResolveTCPBindings(ctx, []option.TCPListenBinding{{
		Interface: "eth0", IPVersion: 6, WaitIP: badoption.Duration(time.Minute),
	}}, staticSource(), clock)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected wait cancellation, got %v", err)
	}
}

func TestResolveTCPBindingsExplicitZone(t *testing.T) {
	interfaces := upInterfaces(t)
	// An explicit zone that resolves is preserved.
	resolved, err := ResolveTCPBindings(context.Background(), []option.TCPListenBinding{{
		Address: addrOption("fe80::99%eth1"), IPVersion: 6,
	}}, staticSource(interfaces...), &fakeBindClock{now: time.Unix(100, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if resolved[0].Address.Zone() != "eth1" {
		t.Fatalf("zone not preserved: %s", resolved[0].Address)
	}
	// A link-local address without an explicit zone takes the scoped
	// interface as its zone.
	resolved, err = ResolveTCPBindings(context.Background(), []option.TCPListenBinding{{
		Address: addrOption("fe80::99"), Interface: "eth1", IPVersion: 6,
	}}, staticSource(interfaces...), &fakeBindClock{now: time.Unix(100, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if resolved[0].Address.Zone() != "eth1" {
		t.Fatalf("interface scope not applied: %s", resolved[0].Address)
	}
	// No zone and no resolvable interface is an error, never scope 0.
	if _, err = ResolveTCPBindings(context.Background(), []option.TCPListenBinding{{
		Address: addrOption("fe80::99"), IPVersion: 6,
	}}, staticSource(interfaces...), &fakeBindClock{now: time.Unix(100, 0)}); err == nil {
		t.Fatal("a scoped address without a zone must be rejected")
	}
	if _, err = ResolveTCPBindings(context.Background(), []option.TCPListenBinding{{
		Address: addrOption("fe80::99%missing0"), IPVersion: 6,
	}}, staticSource(interfaces...), &fakeBindClock{now: time.Unix(100, 0)}); err == nil {
		t.Fatal("an unresolvable zone must be rejected")
	}
}

func TestResolveTCPBindingsIPv4(t *testing.T) {
	interfaces := []control.Interface{
		testInterface(t, "eth0", 1, net.FlagUp, "192.0.2.2/24", "192.0.2.3/24"),
	}
	resolved, err := ResolveTCPBindings(context.Background(), []option.TCPListenBinding{{
		Interface: "eth0", IPVersion: 4,
	}}, staticSource(interfaces...), &fakeBindClock{now: time.Unix(100, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if resolved[0].Address.String() != "192.0.2.2" {
		t.Fatalf("IPv4 selection must preserve enumeration order, got %s", resolved[0].Address)
	}
	if resolved[0].IPVersion != 4 || resolved[0].Interface != "eth0" {
		t.Fatalf("unexpected resolved facts %+v", resolved[0])
	}
}

func TestResolveTCPBindingsExplicitAddressWaitsIfUp(t *testing.T) {
	start := time.Unix(100, 0)
	clock := &fakeBindClock{now: start}
	source := &fakeBindSource{snapshot: func() []control.Interface {
		flags := net.Flags(0)
		if !clock.now.Before(start.Add(time.Second)) {
			flags = net.FlagUp
		}
		return []control.Interface{testInterface(t, "eth1", 2, flags)}
	}}
	resolved, err := ResolveTCPBindings(context.Background(), []option.TCPListenBinding{{
		Address:   addrOption("fe80::99"),
		Interface: "eth1",
		IPVersion: 6,
		WaitIfUp:  badoption.Duration(2 * time.Second),
	}}, source, clock)
	if err != nil {
		t.Fatal(err)
	}
	if resolved[0].Address.Zone() != "eth1" {
		t.Fatalf("unexpected address %s", resolved[0].Address)
	}
	if elapsed := clock.now.Sub(start); elapsed != time.Second {
		t.Fatalf("explicit-address ifup wait wrong: %s", elapsed)
	}
}

func addrOption(value string) *badoption.Addr {
	address, err := netip.ParseAddr(value)
	if err != nil {
		panic(err)
	}
	addr := badoption.Addr(address)
	return &addr
}

package box_test

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

type object = map[string]any

func freePort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
func resolver(t *testing.T, ip string) int {
	t.Helper()
	sock, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	started := make(chan struct{})
	srv := &mdns.Server{PacketConn: sock, NotifyStartedFunc: func() { close(started) }, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, q *mdns.Msg) {
		r := new(mdns.Msg)
		r.SetReply(q)
		r.Answer = []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: q.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 1}, A: net.ParseIP(ip)}}
		_ = w.WriteMsg(r)
	})}
	go srv.ActivateAndServe()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return sock.LocalAddr().(*net.UDPAddr).Port
}

type session struct {
	view     context.Context
	path     string
	cfg      object
	ctx      context.Context
	core     *box.Box
	rpc      daemon.RuntimeConfigClient
	api      daemon.StartedServiceClient
	dns      daemon.DNSLookupClient
	proxy    int
	trackers *trafficcontrol.Manager
}

func newSession(t *testing.T, tun object) *session {
	t.Helper()
	apiPort, proxy := freePort(t), freePort(t)
	for proxy == apiPort {
		proxy = freePort(t)
	}
	apiService := object{"type": "api", "tag": "mvpn-api", "listen": "127.0.0.1", "listen_port": apiPort, "secret": "local-test-only"}
	inbounds := []object{{"type": "mixed", "tag": "proxy", "listen": "127.0.0.1", "listen_port": proxy}}
	if tun != nil {
		inbounds = append(inbounds, tun)
	}
	cfg := object{"log": object{"level": "error"}, "services": []object{apiService}, "inbounds": inbounds, "outbounds": []object{
		{"type": "direct", "tag": "direct"}, {"type": "direct", "tag": "a"}, {"type": "direct", "tag": "b"},
		{"type": "selector", "tag": "vpn-select", "outbounds": []string{"direct", "a", "b"}, "default": "direct", "interrupt_exist_connections": false}},
		"dns":   object{"servers": []object{{"type": "udp", "tag": "resolver", "server": "127.0.0.1", "server_port": resolver(t, "192.0.2.1")}}, "final": "resolver"},
		"route": object{"final": "vpn-select", "rules": []object{{"clash_mode": "Direct", "outbound": "direct"}, {"clash_mode": "Rule", "outbound": "vpn-select"}}}}
	if tun != nil {
		cfg["route"].(object)["auto_detect_interface"] = true
	}
	path := filepath.Join(t.TempDir(), "config.json")
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	ctx := include.Context(context.Background())
	ctxRegistry := ctx
	var opts option.Options
	if e := sjson.UnmarshalContext(ctx, b, &opts); e != nil {
		t.Fatal(e)
	}
	instance, e := box.New(box.Options{Context: ctx, Options: opts, RuntimeConfigPath: path})
	if e != nil {
		t.Fatal(e)
	}
	if e = instance.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = instance.Close() })
	conn, e := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", apiPort), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer local-test-only")
	view := service.FromContext[adapter.RuntimeConfig](ctxRegistry).ServiceContext(ctxRegistry)
	return &session{view: view, trackers: service.PtrFromContext[trafficcontrol.Manager](ctxRegistry), path: path, cfg: cfg, core: instance, ctx: ctx, rpc: daemon.NewRuntimeConfigClient(conn), api: daemon.NewStartedServiceClient(conn), dns: daemon.NewDNSLookupClient(conn), proxy: proxy}
}
func (s *session) apply(t *testing.T, selected string) error {
	t.Helper()
	b, e := json.Marshal(s.cfg)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(s.path+".pending", b, 0600); e != nil {
		t.Fatal(e)
	}
	d := sha256.Sum256(b)
	_, e = s.rpc.Apply(s.ctx, &daemon.ApplyRuntimeConfigRequest{Sha256: d[:], SelectedOutbound: selected})
	return e
}
func (s *session) selectTag(t *testing.T, tag string) {
	t.Helper()
	if _, e := s.api.SelectOutbound(s.ctx, &daemon.SelectOutboundRequest{GroupTag: "vpn-select", OutboundTag: tag}); e != nil {
		t.Fatal(e)
	}
}
func (s *session) connection(t *testing.T, upstream string) (net.Conn, string) {
	t.Helper()
	conn, e := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", s.proxy), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	if _, e = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstream, upstream); e != nil {
		t.Fatal(e)
	}
	r := bufio.NewReader(conn)
	line, _ := r.ReadString('\n')
	if strings.Contains(line, "200") {
		for {
			header, e := r.ReadString('\n')
			if e != nil {
				t.Fatal(e)
			}
			if header == "\r\n" {
				break
			}
		}
	}
	return conn, line
}
func TestDesktopLiveRouting(t *testing.T) {
	s := newSession(t, nil)
	started, e := s.api.GetStartedAt(s.ctx, &emptypb.Empty{})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.api.SetClashMode(s.ctx, &daemon.ClashMode{Mode: "Rule"}); e != nil {
		t.Fatal(e)
	}
	s.selectTag(t, "a")
	echo, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer echo.Close()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	long, line := s.connection(t, echo.Addr().String())
	if !strings.Contains(line, "200") {
		t.Fatal(line)
	}
	roundtrip := func() {
		t.Helper()
		_ = long.SetDeadline(time.Now().Add(3 * time.Second))
		if _, e := long.Write([]byte("ok")); e != nil {
			t.Fatal(e)
		}
		var b [2]byte
		if _, e := io.ReadFull(long, b[:]); e != nil || string(b[:]) != "ok" {
			t.Fatalf("existing flow: %q %v", b, e)
		}
	}
	roundtrip()
	s.selectTag(t, "b")
	roundtrip()
	route := s.cfg["route"].(object)
	before := route["rules"].([]object)
	route["rules"] = append([]object{{"port": echo.Addr().(*net.TCPAddr).Port, "action": "reject"}}, before...)
	if e = s.apply(t, "b"); e != nil {
		t.Fatal(e)
	}
	roundtrip()
	denied, status := s.connection(t, echo.Addr().String())
	defer denied.Close()
	if strings.Contains(status, "200") {
		_, _ = denied.Write([]byte("test"))
		var data [4]byte
		if _, err := io.ReadFull(denied, data[:]); err == nil {
			t.Fatal("rejected connection delivered application data")
		} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("reject did not terminate the new connection")
		}
	}
	lookup := func(expect string) {
		t.Helper()
		r, e := s.dns.LookupIPv4(s.ctx, &daemon.IPv4LookupRequest{Name: "live.example", Server: "resolver"})
		if e != nil || len(r.GetAddresses()) != 1 || r.Addresses[0] != expect {
			t.Fatalf("DNS=%v err=%v", r, e)
		}
	}
	lookup("192.0.2.1")
	ob := s.cfg["outbounds"].([]object)
	ob[3]["interrupt_exist_connections"] = true
	if e = s.apply(t, "b"); e != nil {
		t.Fatal(e)
	}
	s.selectTag(t, "a")
	_ = long.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, e = long.Read(b[:]); e == nil {
		t.Fatal("old server connection remained open")
	} else if timeout, ok := e.(net.Error); ok && timeout.Timeout() {
		t.Fatal("old server connection timed out instead of closing")
	}
	route["rules"] = before
	s.cfg["dns"].(object)["servers"].([]object)[0]["server_port"] = resolver(t, "192.0.2.2")
	if e = s.apply(t, "a"); e != nil {
		t.Fatal(e)
	}
	lookup("192.0.2.2")
	route["final"] = "missing"
	if e = s.apply(t, "a"); e == nil {
		t.Fatal("invalid profile accepted")
	}
	lookup("192.0.2.2")
	_, line = s.connection(t, echo.Addr().String())
	if !strings.Contains(line, "200") {
		t.Fatal("previous route not operational")
	}
	after, e := s.api.GetStartedAt(s.ctx, &emptypb.Empty{})
	if e != nil || after.GetStartedAt() != started.GetStartedAt() {
		t.Fatal("core start time changed", e)
	}
}

func TestDesktopLiveRouteChangeReconnectsAffectedFlows(t *testing.T) {
	for _, scope := range []string{"domain", "default", "process"} {
		t.Run(scope, func(t *testing.T) {
			if scope == "process" && runtime.GOOS != "linux" && runtime.GOOS != "windows" {
				t.Skip("mVPN desktop process lookup is tested on Linux and Windows")
			}
			s := newSession(t, nil)
			if _, err := s.api.SetClashMode(s.ctx, &daemon.ClashMode{Mode: "Rule"}); err != nil {
				t.Fatal(err)
			}
			route := s.cfg["route"].(object)
			rules := []object{
				{"clash_mode": "Direct", "outbound": "direct"},
				{"domain": "unchanged.test", "outbound": "vpn-select"},
			}
			route["rules"] = rules
			s.cfg["dns"].(object)["servers"].([]object)[0]["server_port"] = resolver(t, "127.0.0.1")
			if err := s.apply(t, "a"); err != nil {
				t.Fatal(err)
			}
			echo, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = echo.Close() })
			go func() {
				for {
					conn, err := echo.Accept()
					if err != nil {
						return
					}
					go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
				}
			}()
			checkAddr := net.JoinHostPort("ip-check.test", strconv.Itoa(echo.Addr().(*net.TCPAddr).Port))
			otherAddr := net.JoinHostPort("unchanged.test", strconv.Itoa(echo.Addr().(*net.TCPAddr).Port))
			dial := func(addr string) net.Conn {
				t.Helper()
				conn, status := s.connection(t, addr)
				if !strings.Contains(status, "200") {
					t.Fatal(status)
				}
				return conn
			}
			roundtrip := func(conn net.Conn) {
				t.Helper()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err := conn.Write([]byte("ok")); err != nil {
					t.Fatal(err)
				}
				var response [2]byte
				if _, err := io.ReadFull(conn, response[:]); err != nil || string(response[:]) != "ok" {
					t.Fatalf("proxy roundtrip: %q (%v)", response, err)
				}
			}
			affected, other := dial(checkAddr), dial(otherAddr)
			roundtrip(affected)
			roundtrip(other)
			switch scope {
			case "domain":
				route["rules"] = append(slices.Clone(rules), object{"domain_suffix": []string{"ip-check.test"}, "outbound": "direct"})
			case "process":
				executable, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				route["rules"] = append(slices.Clone(rules), object{"process_name": filepath.Base(executable), "outbound": "direct"})
			case "default":
				route["final"] = "direct"
			}
			if err := s.apply(t, "a"); err != nil {
				t.Fatal(err)
			}
			// The browser can retain this socket without another route lookup,
			// so merely updating the rules does not change its next request.
			_ = affected.SetReadDeadline(time.Now().Add(time.Second))
			var data [1]byte
			if _, err := affected.Read(data[:]); err == nil {
				t.Fatal("old browser connection remained open")
			} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("old browser connection timed out instead of closing")
			}
			roundtrip(other)
			fresh := dial(checkAddr)
			roundtrip(fresh)
			if !slices.ContainsFunc(s.trackers.Connections(), func(flow *trafficcontrol.TrackerMetadata) bool {
				return flow.Metadata.Destination.Fqdn == "ip-check.test" && flow.Metadata.RouteOutbound == "direct"
			}) {
				t.Fatal("the next browser connection did not use the direct route")
			}
		})
	}
}

func TestDesktopLiveUDP(t *testing.T) {
	s := newSession(t, nil)
	if _, err := s.api.SetClashMode(s.ctx, &daemon.ClashMode{Mode: "Rule"}); err != nil {
		t.Fatal(err)
	}
	s.selectTag(t, "a")
	echo, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		var data [64]byte
		for {
			n, peer, err := echo.ReadFrom(data[:])
			if err != nil {
				return
			}
			_, _ = echo.WriteTo(data[:n], peer)
		}
	}()
	proxy := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", uint16(s.proxy)), socks.Version5, "", "")
	target := M.SocksaddrFromNet(echo.LocalAddr())
	pc, err := proxy.ListenPacket(s.ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	exchange := func(c net.PacketConn) {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.WriteTo([]byte("udp"), target); err != nil {
			t.Fatal(err)
		}
		var reply [2048]byte
		n, _, err := c.ReadFrom(reply[:])
		if err != nil || string(reply[:n]) != "udp" {
			t.Fatalf("UDP reply %q %v", reply[:n], err)
		}
	}
	exchange(pc)
	var id string
	for _, tracker := range s.trackers.Connections() {
		if tracker.Metadata.Network == "udp" {
			id = tracker.ID.String()
		}
	}
	if id == "" {
		t.Fatal("UDP flow missing")
	}
	hasOld := func() bool {
		for _, tracker := range s.trackers.Connections() {
			if tracker.ID.String() == id {
				return true
			}
		}
		return false
	}
	s.selectTag(t, "b")
	exchange(pc)
	if !hasOld() {
		t.Fatal("server switch interrupted UDP with preference disabled")
	}
	s.cfg["outbounds"].([]object)[3]["interrupt_exist_connections"] = true
	if err = s.apply(t, "b"); err != nil {
		t.Fatal(err)
	}
	s.selectTag(t, "a")
	deadline := time.Now().Add(3 * time.Second)
	for hasOld() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if hasOld() {
		t.Fatal("old UDP association survived forced server switch")
	}
	fresh, err := proxy.ListenPacket(s.ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	exchange(fresh)
	id = ""
	for _, tracker := range s.trackers.Connections() {
		if tracker.Metadata.Network == "udp" && tracker.Metadata.RouteOutbound == "vpn-select" {
			id = tracker.ID.String()
		}
	}
	if id == "" {
		t.Fatal("expected an active UDP association over VPN")
	}
	s.cfg["outbounds"].([]object)[3]["interrupt_exist_connections"] = false
	route := s.cfg["route"].(object)
	route["rules"] = append([]object{{"network": "udp", "port": target.Port, "outbound": "direct"}}, route["rules"].([]object)...)
	if err = s.apply(t, "a"); err != nil {
		t.Fatal(err)
	}
	if hasOld() {
		t.Fatal("old UDP association survived change from VPN to direct")
	}
	direct, err := proxy.ListenPacket(s.ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	exchange(direct)
	if !slices.ContainsFunc(s.trackers.Connections(), func(flow *trafficcontrol.TrackerMetadata) bool {
		return flow.Metadata.Network == "udp" && flow.Metadata.RouteOutbound == "direct"
	}) {
		t.Fatal("expected the new UDP association to use the direct route")
	}
}

// Read back forwarding prefixes from the OS, including /32s printed by iproute2
// as bare addresses. DNS returning a new IP alone cannot verify this change.
func checkExcludedRoute(t *testing.T, ifIndex int, excluded string) {
	t.Helper()
	var data []byte
	var err error
	if runtime.GOOS == "windows" {
		data, err = exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", fmt.Sprintf("(Get-NetRoute -AddressFamily IPv4 -InterfaceIndex %d -PolicyStore ActiveStore).DestinationPrefix", ifIndex)).Output()
	} else {
		data, err = exec.Command("ip", "-4", "-o", "route", "show", "table", "41322").Output()
	}
	if err != nil {
		t.Fatal(err)
	}
	var prefixes []netip.Prefix
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		p, err := netip.ParsePrefix(fields[0])
		if err != nil {
			if a, e := netip.ParseAddr(fields[0]); e == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			} else {
				continue
			}
		}
		prefixes = append(prefixes, p)
	}
	for _, tail := range []string{"250", "251", "252"} {
		addr := netip.MustParseAddr("198.19.198." + tail)
		included := slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(addr) })
		if included == (tail == excluded) {
			t.Fatalf("OS route for %v is incorrect, expected excluded %v", addr, excluded)
		}
	}
}

// The lab runs this opt-in test in a Linux network namespace, or against a
// Windows TUN scoped to one unused test subnet. It never needs a real exit.
func TestDesktopLiveTun(t *testing.T) {
	if os.Getenv("MVPN_TEST_TUN") != "1" {
		t.Skip("requires a disposable desktop TUN")
	}
	const name = "mvpn-hot-test"
	tun := object{"type": "tun", "tag": "tun-in", "interface_name": name, "address": []string{"198.19.197.1/30"}, "mtu": 1500, "stack": "system", "auto_route": true, "strict_route": false, "dns_mode": "disabled", "route_address": []string{"198.19.198.0/24"}, "route_exclude_address": []string{"198.19.198.250/32"}}
	if runtime.GOOS == "linux" {
		tun["iproute2_table_index"] = 41322
		tun["iproute2_rule_index"] = 30330
	}
	s := newSession(t, tun)
	start, e := s.api.GetStartedAt(s.ctx, &emptypb.Empty{})
	if e != nil {
		t.Fatal(e)
	}
	original, e := net.InterfaceByName(name)
	if e != nil {
		t.Fatal(e)
	}
	check := func(wantMTU int) {
		t.Helper()
		link, e := net.InterfaceByName(name)
		if e != nil {
			t.Fatal(e)
		}
		mtu := link.MTU
		if runtime.GOOS == "windows" {
			// Wintun reports the link maximum (65535) in MIB_IF_ROW2. IPv4
			// fragmentation and routing use the IP interface's NLMTU.
			out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", fmt.Sprintf("(Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex %d).NlMtu", link.Index)).Output()
			if err != nil {
				t.Fatal(err)
			}
			mtu, err = strconv.Atoi(strings.TrimSpace(string(out)))
			if err != nil {
				t.Fatal(err)
			}
		}
		if link.Index != original.Index || mtu != wantMTU {
			t.Fatalf("TUN changed: index=%d IPv4 mtu=%d, want index=%d mtu=%d", link.Index, mtu, original.Index, wantMTU)
		}
		after, e := s.api.GetStartedAt(s.ctx, &emptypb.Empty{})
		if e != nil || after.GetStartedAt() != start.GetStartedAt() {
			t.Fatal("core replaced", e)
		}
	}
	tun["mtu"] = 1400
	if e = s.apply(t, "direct"); e != nil {
		t.Fatal(e)
	}
	check(1400)
	for _, last := range []string{"251", "252", "250"} {
		tun["route_exclude_address"] = []string{"198.19.198." + last + "/32"}
		if e = s.apply(t, "direct"); e != nil {
			t.Fatal(e)
		}
		check(1400)
		checkExcludedRoute(t, original.Index, last)
	}
	if runtime.GOOS == "linux" {
		for _, redirect := range []bool{true, false} {
			tun["auto_redirect"] = redirect
			if e = s.apply(t, "direct"); e != nil {
				t.Fatal(e)
			}
			check(1400)
		}
	}
	tun["mtu"] = 1500
	if e = s.apply(t, "direct"); e != nil {
		t.Fatal(e)
	}
	check(1500)
	t.Logf("pid=%d core_started_at=%d tun_index=%d MTU=1500/1400/1500", os.Getpid(), start.GetStartedAt(), original.Index)
}

func TestDesktopLiveResourceDependencies(t *testing.T) {
	s := newSession(t, nil)
	dnsConfig := s.cfg["dns"].(object)
	dnsConfig["rules"] = []object{{"domain": "fixture.test", "server": "resolver"}}
	dnsServers := append(dnsConfig["servers"].([]object), object{"type": "udp", "tag": "spare", "server": "127.0.0.1", "server_port": resolver(t, "192.0.2.5")})
	dnsConfig["servers"] = dnsServers
	outbounds := s.cfg["outbounds"].([]object)
	makeVless := func(tag, server string) object {
		return object{"type": "vless", "tag": tag, "server": server, "server_port": 12345, "uuid": "00000000-0000-4000-8000-000000000001"}
	}
	explicit := makeVless("explicit", "node.test")
	explicit["domain_resolver"] = "resolver"
	numeric := makeVless("numeric", "127.0.0.1")
	detour := makeVless("detoured", "127.0.0.1")
	detour["detour"] = "numeric"
	outbounds = append(outbounds, explicit, numeric, detour)
	if C.WithQUIC {
		outbounds = append(outbounds, object{"type": "hysteria2", "tag": "quic-test", "server": "127.0.0.1", "server_port": 12348, "password": "local-fixture", "tls": object{"enabled": true, "insecure": true}})
	}
	s.cfg["outbounds"] = outbounds
	apply := func() {
		t.Helper()
		if err := s.apply(t, "a"); err != nil {
			t.Fatal(err)
		}
	}
	apply()
	out := service.FromContext[adapter.OutboundManager](s.view)
	transport := service.FromContext[adapter.DNSTransportManager](s.view)
	get := func(tag string) adapter.Outbound {
		it, ok := out.Outbound(tag)
		if !ok {
			t.Fatalf("missing %s", tag)
		}
		return it
	}
	getDNS := func(tag string) adapter.DNSTransport {
		it, ok := transport.Transport(tag)
		if !ok {
			t.Fatalf("missing DNS %s", tag)
		}
		return it
	}
	startNumeric, startExplicit, startDetour, startGroup := get("numeric"), get("explicit"), get("detoured"), get("vpn-select")
	startDNS, startSpare := getDNS("resolver"), getDNS("spare")
	var quic adapter.Outbound
	if C.WithQUIC {
		quic = get("quic-test")
	}
	dnsServers[1]["server_port"] = resolver(t, "192.0.2.6")
	apply()
	if getDNS("spare") == startSpare || getDNS("resolver") != startDNS || get("vpn-select") != startGroup || get("numeric") != startNumeric || get("explicit") != startExplicit || get("detoured") != startDetour {
		t.Fatal("changing an unrelated resolver rebuilt existing bindings or kept the changed one")
	}
	dnsServers[0]["server_port"] = resolver(t, "192.0.2.7")
	apply()
	if getDNS("resolver") == startDNS || get("explicit") == startExplicit || get("vpn-select") == startGroup || get("numeric") != startNumeric || get("detoured") != startDetour {
		t.Fatal("resolver dependency did not propagate to the correct outbounds")
	}
	if quic != nil && get("quic-test") != quic {
		t.Fatal("unrelated resolver replaced numeric Hysteria2 outbound")
	}
	startExplicit = get("explicit")
	numeric["server_port"] = 12346
	apply()
	if get("numeric") == startNumeric || get("detoured") == startDetour || get("explicit") != startExplicit {
		t.Fatal("detour dependency did not propagate independently")
	}
	groupBeforeModeChange := get("vpn-select")
	dnsConfig["direct_mode_server"] = "spare"
	apply()
	if get("vpn-select") == groupBeforeModeChange || get("explicit") != startExplicit {
		t.Fatal("changing the implicit direct-mode resolver did not preserve explicit bindings")
	}
}

func TestDesktopLiveRuleSetSources(t *testing.T) {
	s := newSession(t, nil)
	s.cfg["outbounds"].([]object)[1]["inet4_bind_address"] = "127.0.0.1"
	var downloads atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downloads.Add(1)
		io.WriteString(w, `{"version":3,"rules":[{"domain":["unused.test"]}]}`)
	}))
	defer remote.Close()
	file := filepath.Join(t.TempDir(), "addresses.json")
	writeSet := func(cidr string) {
		t.Helper()
		if err := os.WriteFile(file, []byte(fmt.Sprintf(`{"version":3,"rules":[{"ip_cidr":[%q]}]}`, cidr)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeSet("127.0.0.1/32")
	route := s.cfg["route"].(object)
	remoteSet := object{"tag": "download", "type": "remote", "format": "source", "url": remote.URL + "/v1", "http_client": object{"detour": "a"}}
	localSet := object{"tag": "addresses", "type": "local", "format": "source", "path": file}
	route["rule_set"] = []object{remoteSet, localSet}
	route["rules"] = []object{{"rule_set": "download", "outbound": "direct"}, {"rule_set": "addresses", "outbound": "a"}, {"network": "tcp", "outbound": "b"}}
	apply := func() {
		t.Helper()
		if err := s.apply(t, "a"); err != nil {
			t.Fatal(err)
		}
	}
	apply()
	if n := downloads.Load(); n != 1 {
		t.Fatalf("initial downloads %d", n)
	}
	route["rules"] = append([]object{{"domain": "unused2.test", "outbound": "a"}}, route["rules"].([]object)...)
	apply()
	route["rule_set"] = []object{localSet, remoteSet, {"type": "inline", "tag": "extra", "rules": []object{{"ip_cidr": "127.0.0.1/32"}}}}
	apply()
	if n := downloads.Load(); n != 1 {
		t.Fatalf("unchanged source downloaded %d times", n)
	}
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	match := func() string {
		t.Helper()
		c, _ := s.connection(t, echo.Addr().String())
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		var result [1]byte
		if _, err := io.ReadFull(c, result[:]); err != nil || result[0] != 'x' {
			t.Fatalf("probe failed: %v", err)
		}
		port := uint16(c.LocalAddr().(*net.TCPAddr).Port)
		for _, flow := range s.trackers.Connections() {
			if flow.Metadata.Source.Port == port {
				return flow.Outbound
			}
		}
		t.Fatal("active test connection missing")
		return ""
	}
	if got := match(); got != "a" {
		t.Fatalf("initial matched outbound %q", got)
	}
	working := route["rules"]
	route["rules"] = []object{{"rule_set": "missing", "outbound": "a"}}
	if s.apply(t, "a") == nil {
		t.Fatal("invalid staged rule was accepted")
	}
	route["rules"] = working
	if got := match(); got != "a" {
		t.Fatalf("rollback changed the old rule set: %s", got)
	}
	writeSet("192.0.2.0/24")
	until := time.Now().Add(4 * time.Second)
	for match() != "b" {
		if time.Now().After(until) {
			t.Fatal("shared file watcher did not update the current router")
		}
		time.Sleep(20 * time.Millisecond)
	}
	route["rules"] = append([]object{{"rule_set": "extra", "outbound": "direct"}}, working.([]object)...)
	apply()
	if got := match(); got != "direct" {
		t.Fatalf("previously unused set did not reload: %s", got)
	}
	remoteSet["url"] = remote.URL + "/v2"
	apply()
	if n := downloads.Load(); n != 2 {
		t.Fatalf("changed source downloads %d", n)
	}
}

func TestDesktopLiveLongFlowsReleaseLookupPolicy(t *testing.T) {
	s := newSession(t, nil)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	var flows []net.Conn
	defer func() {
		for _, c := range flows {
			c.Close()
		}
	}()
	echo := func(c net.Conn) {
		t.Helper()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		var reply [1]byte
		if _, err := io.ReadFull(c, reply[:]); err != nil || reply[0] != 'x' {
			t.Fatalf("previous flow failed: %v", err)
		}
	}
	route := s.cfg["route"].(object)
	for i := 0; i < 8; i++ {
		c, _ := s.connection(t, listener.Addr().String())
		flows = append(flows, c)
		echo(c)
		drained := s.core.RoutingPolicyDrainedForTest()
		route["rules"] = []object{{"domain": fmt.Sprintf("unmatched-%d.test", i), "outbound": "b"}}
		if err := s.apply(t, "direct"); err != nil {
			t.Fatal(err)
		}
		select {
		case <-drained:
		case <-time.After(2 * time.Second):
			t.Fatalf("generation %d retained after dispatch", i)
		}
		for _, existing := range flows {
			echo(existing)
		}
	}
}

func TestDesktopRetiredManagersAreCollectible(t *testing.T) {
	s := newSession(t, nil)
	servers := s.cfg["dns"].(object)["servers"].([]object)
	s.cfg["dns"].(object)["servers"] = append(servers, object{"type": "udp", "tag": "changing", "server": "127.0.0.1", "server_port": 53})
	spare := s.cfg["dns"].(object)["servers"].([]object)[1]
	route := s.cfg["route"].(object)
	route["rule_set"] = []object{{"type": "inline", "tag": "kept", "rules": []object{{"domain": []string{"kept.test"}}}}}
	route["rules"] = []object{{"rule_set": "kept", "outbound": "a"}}
	var downloads atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downloads.Add(1)
		io.WriteString(w, `{"version":3,"rules":[{"domain":"remote.test"}]}`)
	}))
	defer remote.Close()
	route["rule_set"] = append(route["rule_set"].([]object), object{"type": "remote", "tag": "remote", "format": "source", "url": remote.URL, "download_detour": "a"})
	route["rules"] = []object{{"rule_set": []string{"kept", "remote"}, "outbound": "a"}}
	obs := append(s.cfg["outbounds"].([]object), object{"type": "vless", "tag": "t", "server": "127.0.0.1", "server_port": 12345, "uuid": "00000000-0000-4000-8000-000000000001"})
	if C.WithQUIC {
		obs = append(obs, object{"type": "hysteria2", "tag": "h", "server": "127.0.0.1", "server_port": 12346, "password": "test-only", "tls": object{"enabled": true, "insecure": true}})
	}
	s.cfg["outbounds"] = obs
	var generations []func() [5]bool
	for i := 0; i < 12; i++ {
		generations = append(generations, s.core.PolicyObjectsForTest())
		spare["server_port"] = 20000 + i
		if err := s.apply(t, "a"); err != nil {
			t.Fatal(err)
		}
	}
	if downloads.Load() != 1 {
		t.Fatalf("unchanged remote list downloaded %d times", downloads.Load())
	}
	var alive [5]int
	for end := time.Now().Add(2 * time.Second); ; {
		runtime.GC() // Only the reachability test requests a collection.
		alive = [5]int{}
		for _, probe := range generations {
			for k, kept := range probe() {
				if kept {
					alive[k]++
				}
			}
		}
		if alive == ([5]int{}) {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("retired router/DNS/outbound/endpoint/transport managers still reachable: %v", alive)
		}
		time.Sleep(10 * time.Millisecond)
	}
	runtime.KeepAlive(s)
}

func TestDesktopLazyDetourKeepsItsSelectedResource(t *testing.T) {
	s := newSession(t, nil)
	manager := service.FromContext[adapter.OutboundManager](s.view)
	old, _ := manager.Outbound("a")
	lazy := dialer.NewDetour(manager, "a", true).(*dialer.DetourDialer)
	for _, ob := range s.cfg["outbounds"].([]object) {
		if ob["tag"] == "a" {
			ob["connect_timeout"] = "3s"
		}
	}
	if err := s.apply(t, "b"); err != nil {
		t.Fatal(err)
	}
	if now, _ := manager.Outbound("a"); now == old {
		t.Fatal("fixture did not replace the outbound")
	}
	if pinned, err := lazy.Dialer(); err != nil || pinned != old {
		t.Fatal("late detour was redirected to another revision", err)
	}
}

func TestDesktopOnlyColdRouterForcesGC(t *testing.T) {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	s := newSession(t, nil)
	runtime.ReadMemStats(&after)
	if after.NumForcedGC <= before.NumForcedGC {
		t.Fatal("cold router did not collect after rule-set cleanup")
	}
	s.cfg["route"].(object)["rules"] = []object{{"domain": "new.test", "outbound": "a"}}
	runtime.ReadMemStats(&before)
	if err := s.apply(t, "a"); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	if after.NumForcedGC != before.NumForcedGC {
		t.Fatalf("hot apply forced %d collections", after.NumForcedGC-before.NumForcedGC)
	}
}

// Hold a background fetch while reusing and then removing the real rule set.
// The old TCP connection must survive both successful and failed refreshes.
func TestDesktopLiveRemoteUpdaterLifetime(t *testing.T) {
	s := newSession(t, nil)
	var calls atomic.Int32
	began := make(chan time.Time, 32)
	blocked, cancelled := make(chan struct{}), make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		began <- time.Now()
		switch n {
		case 1:
			io.WriteString(w, `{"version":3,"rules":[{"domain":"old.test"}]}`)
		case 2, 3:
			http.Error(w, "temporary fixture error", http.StatusServiceUnavailable)
		case 4:
			io.WriteString(w, `{"version":3,"rules":[{"domain":"new.test"}]}`)
		case 5:
			close(blocked)
			select {
			case <-r.Context().Done():
				close(cancelled)
			case <-release:
			}
		default:
			http.Error(w, "extra updater", http.StatusConflict)
		}
	}))
	t.Cleanup(server.Close)
	const interval = 100 * time.Millisecond
	route := s.cfg["route"].(object)
	route["rule_set"] = []object{{"type": "remote", "tag": "changed-list", "format": "source", "url": server.URL, "download_detour": "a", "update_interval": "100ms"}}
	makeRules := func(i int) []object {
		return []object{{"rule_set": "changed-list", "outbound": "b"}, {"domain": fmt.Sprintf("other-%d.test", i), "outbound": "a"}}
	}
	route["rules"] = makeRules(0)
	if err := s.apply(t, "direct"); err != nil {
		t.Fatal(err)
	}
	set, found := s.core.Router().RuleSet("changed-list")
	if !found {
		t.Fatal("missing remote resource")
	}
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		conn, e := echo.Accept()
		if e == nil {
			defer conn.Close()
			io.Copy(conn, conn)
		}
	}()
	c, _ := s.connection(t, echo.Addr().String())
	defer c.Close()
	ping := func() {
		t.Helper()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, e := c.Write([]byte("ok")); e != nil {
			t.Fatal(e)
		}
		var b [2]byte
		if _, e := io.ReadFull(c, b[:]); e != nil || string(b[:]) != "ok" {
			t.Fatal("connection interrupted", e)
		}
	}
	ping()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	select {
	case <-blocked:
	case <-time.After(4 * time.Second):
		t.Fatal("no periodic fetch")
	}
	for i := 0; i < 4; i++ {
		route["rules"] = makeRules(i + 1)
		if err := s.apply(t, "direct"); err != nil {
			t.Fatal(err)
		}
		if next, _ := s.core.Router().RuleSet("changed-list"); next != set {
			t.Fatal("updater resource replaced during reuse")
		}
		ping()
	}
	if !set.Match(&adapter.InboundContext{Domain: "new.test"}) {
		t.Fatal("successful refresh was not installed")
	}
	var previous time.Time
	for i := 0; i < 5; i++ {
		now := <-began
		if i > 0 && now.Sub(previous) < interval*3/4 {
			t.Fatal("retry before next interval", now.Sub(previous))
		}
		previous = now
	}
	time.Sleep(2 * interval)
	if calls.Load() != 5 {
		t.Fatal("more than one updater", calls.Load())
	}
	runtime.ReadMemStats(&after)
	if after.NumForcedGC != before.NumForcedGC {
		t.Errorf("updater forced %d GC cycles", after.NumForcedGC-before.NumForcedGC)
	}
	delete(route, "rule_set")
	route["rules"] = []object{}
	if err := s.apply(t, "direct"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("last release did not cancel HTTP request")
	}
	time.Sleep(2 * interval)
	if calls.Load() != 5 {
		t.Fatal("fetch after last release")
	}
	ping()
}

func TestDesktopSelectedURLTestKeepsItsProbeDependencies(t *testing.T) {
	s := newSession(t, nil)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer peer.Close()
	obs := s.cfg["outbounds"].([]object)
	obs[3]["outbounds"] = []string{"direct", "probes"}
	s.cfg["outbounds"] = append(obs, object{"type": "urltest", "tag": "probes", "outbounds": []string{"a", "b"}, "url": peer.URL, "interval": "1m", "probe_domain_resolvers": object{"a": "resolver", "b": "resolver"}})
	if err := s.apply(t, "probes"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.api.SetClashMode(s.ctx, &daemon.ClashMode{Mode: "Rule"}); err != nil {
		t.Fatal(err)
	}
	long, line := s.connection(t, peer.Listener.Addr().String())
	if !strings.Contains(line, "200") {
		t.Fatal(line)
	}
	// CONNECT can be acknowledged before the outbound has carried data.
	// A successful round trip fixes the observed chain for this open flow.
	if _, err := io.WriteString(long, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	r, err := http.ReadResponse(bufio.NewReader(long), nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusNoContent {
		t.Fatalf("initial response %d", r.StatusCode)
	}
	alternative := ""
	for _, flow := range s.trackers.Connections() {
		if flow.Metadata.Inbound == "proxy" && slices.Contains(flow.Chain, "probes") {
			switch flow.Chain[0] {
			case "a":
				alternative = "b"
			case "b":
				alternative = "a"
			}
		}
	}
	if alternative == "" {
		t.Fatal("missing actual URLTest chain")
	}
	oldAlternative := s.core.OutboundScopeDoneForTest(alternative)
	for _, ob := range obs {
		if ob["tag"] == alternative {
			ob["connect_timeout"] = "4s"
		}
	}
	if err := s.apply(t, "probes"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-oldAlternative:
		t.Fatal("selected URLTest lost an alternative still reachable by its probes")
	default:
	}
	if _, err := io.WriteString(long, "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(long)
	if err != nil || !strings.Contains(string(response), "204 No Content") {
		t.Fatal("old connection failed", err)
	}
	long.Close()
	select {
	case <-oldAlternative:
	case <-time.After(2 * time.Second):
		t.Fatal("retired alternative stayed open after the flow closed")
	}
}

func TestDesktopConcurrentReloadAndShortConnections(t *testing.T) {
	s := newSession(t, nil)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "echo") }))
	defer peer.Close()
	if _, err := s.api.SetClashMode(s.ctx, &daemon.ClashMode{Mode: "Rule"}); err != nil {
		t.Fatal(err)
	}
	s.selectTag(t, "a")
	proxy := &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", fmt.Sprint(s.proxy))}
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: 3 * time.Second}
	var workers sync.WaitGroup
	errors := make(chan error, 4)
	start := make(chan struct{})
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for range 80 {
				r, err := client.Get(peer.URL)
				if err != nil {
					errors <- err
					return
				}
				body, err := io.ReadAll(r.Body)
				r.Body.Close()
				if err != nil || r.StatusCode != 200 || string(body) != "echo" {
					errors <- fmt.Errorf("short flow: status %d, body %q, error %v", r.StatusCode, body, err)
					return
				}
			}
		}()
	}
	close(start)
	defer workers.Wait()
	for i := range 64 {
		s.cfg["outbounds"].([]object)[2]["connect_timeout"] = fmt.Sprintf("%dms", 1500+i)
		if err := s.apply(t, "a"); err != nil {
			t.Fatal(err)
		}
	}
	workers.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}

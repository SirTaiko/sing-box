package box_test

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/common/trafficcontrol"
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
	return &session{trackers: service.PtrFromContext[trafficcontrol.Manager](ctxRegistry), path: path, cfg: cfg, core: instance, ctx: ctx, rpc: daemon.NewRuntimeConfigClient(conn), api: daemon.NewStartedServiceClient(conn), dns: daemon.NewDNSLookupClient(conn), proxy: proxy}
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

package trafficcontrol

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
)

type taggedOutbound struct {
	adapter.Outbound
	tag string
}

func (o taggedOutbound) Tag() string  { return o.tag }
func (o taggedOutbound) Type() string { return "direct" }

func routeMetadata(tags ...string) adapter.InboundContext {
	var metadata adapter.InboundContext
	for _, tag := range tags {
		metadata.OutboundChain = append(metadata.OutboundChain, taggedOutbound{tag: tag})
	}
	return metadata
}

func TestRouteTrafficStreamsAndPackets(t *testing.T) {
	m := NewManager()
	m.EnableRouteTraffic()
	ctx := context.Background()
	app, peer := net.Pipe()
	defer peer.Close()
	peer.SetDeadline(time.Now().Add(5 * time.Second))
	stream := m.RoutedConnection(ctx, app, routeMetadata("mvpn-zapret-test", "vpn-select"), nil, nil)
	stream.SetDeadline(time.Now().Add(5 * time.Second))
	peerResult := make(chan error, 1)
	go func() {
		if _, err := peer.Write([]byte("uplink")); err != nil {
			peerResult <- err
			return
		}
		_, err := io.ReadFull(peer, make([]byte, 4))
		peerResult <- err
	}()
	if _, err := io.ReadFull(stream, make([]byte, 6)); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte("down")); err != nil {
		t.Fatal(err)
	}
	if err := <-peerResult; err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}

	listen := func() *net.UDPConn {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		c.SetDeadline(time.Now().Add(5 * time.Second))
		return c
	}
	local, remote := listen(), listen()
	packet := m.RoutedPacketConnection(ctx, bufio.NewPacketConn(local), routeMetadata("mvpn-zapret-test"), nil, nil)
	if _, err := remote.WriteToUDP([]byte("udp"), local.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	buffer := buf.NewPacket()
	defer buffer.Release()
	if _, err := packet.ReadPacket(buffer); err != nil {
		t.Fatal(err)
	}
	if err := packet.WritePacket(buf.As([]byte("reply")), M.SocksaddrFromNet(remote.LocalAddr())); err != nil {
		t.Fatal(err)
	}
	if n, _, err := remote.ReadFromUDP(make([]byte, 16)); n != 5 || err != nil {
		t.Fatalf("read UDP: %d %v", n, err)
	}
	if err := packet.Close(); err != nil {
		t.Fatal(err)
	}
	want := RouteTrafficTotals{VPNUp: 6, VPNDown: 4, DirectUp: 3, DirectDown: 5}
	if got := m.RouteTrafficTotals(); got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestRouteTrafficSurvivesEvictionAndFinalFlowBytes(t *testing.T) {
	m := NewManager()
	m.EnableRouteTraffic()
	newFlow := func(tags ...string) *flowTracker {
		f := m.RoutedFlow(context.Background(), routeMetadata(tags...), nil, nil).(*flowTracker)
		f.AttachFlow(nil)
		return f
	}
	old := newFlow("direct")
	old.CountForward(5)
	old.CloseFlow(0)
	for i := 0; i <= closedConnectionsLimit; i++ {
		f := newFlow("auto")
		f.CountReverse(3)
		f.CloseFlow(0)
	}
	m.Clear()
	// A final counter callback can finish after the close notification.
	old.CountReverse(7)
	unknown := newFlow("other")
	unknown.CountForward(19)
	unknown.CloseFlow(0)
	want := RouteTrafficTotals{DirectUp: 5, DirectDown: 7, VPNDown: 3 * (closedConnectionsLimit + 1)}
	if got := m.RouteTrafficTotals(); got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestRouteTrafficClassification(t *testing.T) {
	m := NewManager()
	m.EnableRouteTraffic()
	assign := func(tags ...string) {
		flow := m.RoutedFlow(context.Background(), routeMetadata(tags...), nil, nil)
		flow.CountForward(1)
	}
	for _, tag := range []string{"vpn-select", "auto", "vless-reality", "hysteria2", "vless-poland", "hysteria2-poland", "vless-lithuania", "hysteria2-lithuania"} {
		assign("direct", tag)
		assign(tag, "mvpn-zapret-default")
	}
	assign("direct")
	assign("zapret")
	assign("mvpn-zapret-custom")
	assign("other")
	if got := m.RouteTrafficTotals(); got != (RouteTrafficTotals{VPNUp: 16, DirectUp: 3}) {
		t.Fatalf("unexpected classification totals: %+v", got)
	}
}

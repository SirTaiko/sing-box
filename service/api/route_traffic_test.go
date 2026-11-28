package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/daemon"
	"golang.org/x/net/proxy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestRouteTrafficRunningCore(t *testing.T) {
	binary := os.Getenv("MVPN_TEST_CORE")
	if binary == "" {
		t.Skip("set MVPN_TEST_CORE to a built sing-box")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	listen := func() net.Listener {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	listeners := []net.Listener{listen(), listen(), listen()}
	apiAddr, vpnAddr, directAddr := listeners[0].Addr(), listeners[1].Addr(), listeners[2].Addr()
	for _, l := range listeners {
		l.Close()
	}
	var token [24]byte
	if _, err := rand.Read(token[:]); err != nil {
		t.Fatal(err)
	}
	secret := hex.EncodeToString(token[:])
	type object = map[string]any
	inbound := func(tag string, addr net.Addr) object {
		return object{"type": "socks", "tag": tag, "listen": "127.0.0.1", "listen_port": addr.(*net.TCPAddr).Port}
	}
	config, err := json.Marshal(object{
		"log":      object{"disabled": true},
		"services": []object{{"type": "api", "tag": "mvpn-api", "listen": "127.0.0.1", "listen_port": apiAddr.(*net.TCPAddr).Port, "secret": secret}},
		"inbounds": []object{inbound("vpn-test", vpnAddr), inbound("direct-test", directAddr)},
		// Both routes end at a loopback peer. Only outbound-chain accounting is under test.
		"outbounds": []object{{"type": "direct", "tag": "vless-poland"}, {"type": "direct", "tag": "mvpn-zapret-test"}},
		"route":     object{"rules": []object{{"inbound": "vpn-test", "action": "route", "outbound": "vless-poland"}}, "final": "mvpn-zapret-test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, config, 0o600); err != nil {
		t.Fatal(err)
	}
	core := exec.CommandContext(ctx, binary, "run", "-c", path)
	if err := core.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Process.Kill(); core.Wait() })
	channel, err := grpc.NewClient(apiAddr.String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Close()
	client := daemon.NewRouteTrafficClient(channel)
	unauth, err := client.Subscribe(ctx, &emptypb.Empty{}, grpc.WaitForReady(true))
	if err == nil {
		_, err = unauth.Recv()
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated stream returned %v", status.Code(err))
	}
	authorized := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+secret)
	stream, err := client.Subscribe(authorized, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := stream.Recv()
	if err != nil || first.ElapsedNanos != 0 {
		t.Fatalf("invalid initial sample: %v", err)
	}
	legacyCtx, stopLegacy := context.WithCancel(authorized)
	defer stopLegacy()
	legacy, err := daemon.NewStartedServiceClient(channel).SubscribeConnections(legacyCtx,
		&daemon.SubscribeConnectionsRequest{Interval: int64(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	initial, err := legacy.Recv()
	if err != nil || !initial.GetReset_() {
		t.Fatalf("invalid connection baseline: %v", err)
	}
	var legacyBytes atomic.Int64
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for {
			message, err := legacy.Recv()
			if err != nil {
				return
			}
			legacyBytes.Add(int64(proto.Size(message)))
		}
	}()
	defer func() { stopLegacy(); <-drained }()
	compactBytes := 0
	peer := listen()
	defer peer.Close()
	const rounds = 550
	served := make(chan error, 1)
	go func() {
		for i := 0; i < rounds*2; i++ {
			conn, err := peer.Accept()
			if err != nil {
				served <- err
				return
			}
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			_, err = io.ReadFull(conn, make([]byte, 7))
			if err == nil {
				_, err = conn.Write([]byte("reply"))
			}
			conn.Close()
			if err != nil {
				served <- err
				return
			}
		}
		served <- nil
	}()
	for _, address := range []net.Addr{vpnAddr, directAddr} {
		dialer, err := proxy.SOCKS5("tcp", address.String(), nil, &net.Dialer{Timeout: 3 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < rounds; i++ {
			c, err := dialer.Dial("tcp", peer.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			c.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err = c.Write([]byte("request")); err == nil {
				_, err = io.ReadFull(c, make([]byte, 5))
			}
			c.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	for {
		now, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		compactBytes += proto.Size(now)
		if now.VpnUpload == 7*rounds && now.DirectUpload == 7*rounds && now.VpnDownload == 5*rounds && now.DirectDownload == 5*rounds && now.ElapsedNanos > 0 {
			break
		}
	}
	if int64(compactBytes) >= legacyBytes.Load() {
		t.Fatalf("compact subscription %d bytes, connection events %d", compactBytes, legacyBytes.Load())
	}
	t.Logf("%d finished TCP connections, %d bytes of route samples, %d bytes of connection events", rounds*2, compactBytes, legacyBytes.Load())
}

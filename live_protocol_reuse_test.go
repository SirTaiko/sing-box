package box_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/service"
)

func TestDesktopExistingProtocolSessionsSurviveManagerReplacement(t *testing.T) {
	for _, kind := range []string{"vless", "hysteria2"} {
		t.Run(kind, func(t *testing.T) {
			if kind == "hysteria2" && !C.WithQUIC {
				t.Skip("requires QUIC")
			}
			certServer := httptest.NewTLSServer(nil)
			cert := certServer.TLS.Certificates[0]
			certServer.Close()
			key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			trust := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
			port := freePort(t)
			if kind == "hysteria2" {
				socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				port = socket.LocalAddr().(*net.UDPAddr).Port
				socket.Close()
			}
			serverTLS := object{"enabled": true, "certificate": trust, "key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))}
			in := object{"type": kind, "tag": "peer", "listen": "127.0.0.1", "listen_port": port, "tls": serverTLS}
			out := object{"type": kind, "tag": "transport", "server": "127.0.0.1", "server_port": port, "tls": object{"enabled": true, "server_name": "example.com", "certificate": trust}}
			if kind == "vless" {
				const id = "00000000-0000-4000-8000-000000000001"
				in["users"] = []object{{"uuid": id}}
				out["uuid"] = id
			} else {
				in["users"] = []object{{"name": "test", "password": "local-fixture"}}
				out["password"] = "local-fixture"
			}
			pctx := include.Context(context.Background())
			api := freePort(t)
			for api == port {
				api = freePort(t)
			}
			raw, err := json.Marshal(object{"log": object{"disabled": true}, "inbounds": []object{in}, "outbounds": []object{{"type": "direct", "tag": "direct"}}, "services": []object{{"type": "api", "tag": "peer-api", "listen": "127.0.0.1", "listen_port": api, "secret": "local-fixture"}}})
			if err != nil {
				t.Fatal(err)
			}
			var opts option.Options
			if err = sjson.UnmarshalContext(pctx, raw, &opts); err != nil {
				t.Fatal(err)
			}
			peer, err := box.New(box.Options{Context: pctx, Options: opts})
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			if err = peer.Start(); err != nil {
				t.Fatal(err)
			}
			tracker := service.PtrFromContext[trafficcontrol.Manager](pctx)
			ids := func() map[string]string {
				m := map[string]string{}
				for _, flow := range tracker.Connections() {
					if flow.Metadata.Inbound == "peer" {
						m[flow.Metadata.Network] = flow.ID.String()
					}
				}
				return m
			}

			s := newSession(t, nil)
			obs := s.cfg["outbounds"].([]object)
			for _, ob := range obs {
				if ob["tag"] == "vpn-select" {
					ob["outbounds"] = []string{"direct", "transport"}
				}
			}
			s.cfg["outbounds"] = append(obs, out)
			spare := object{"type": "udp", "tag": "spare", "server": "127.0.0.1", "server_port": 21100}
			dns := s.cfg["dns"].(object)
			dns["servers"] = append(dns["servers"].([]object), spare)
			if err = s.apply(t, "transport"); err != nil {
				t.Fatal(err)
			}
			initial, _ := service.FromContext[adapter.OutboundManager](s.view).Outbound("transport")
			tcp, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer tcp.Close()
			go func() {
				conn, e := tcp.Accept()
				if e == nil {
					defer conn.Close()
					io.Copy(conn, conn)
				}
			}()
			u, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer u.Close()
			go func() {
				var b [64]byte
				for {
					n, from, e := u.ReadFrom(b[:])
					if e != nil {
						return
					}
					u.WriteTo(b[:n], from)
				}
			}()
			c, _ := s.connection(t, tcp.Addr().String())
			defer c.Close()
			proxy := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", uint16(s.proxy)), socks.Version5, "", "")
			dest := M.SocksaddrFromNet(u.LocalAddr())
			pc, err := proxy.ListenPacket(s.ctx, dest)
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			echo := func() {
				t.Helper()
				var b [2048]byte
				c.SetDeadline(time.Now().Add(3 * time.Second))
				if _, e := c.Write([]byte("tcp")); e != nil {
					t.Fatal(e)
				}
				if _, e := io.ReadFull(c, b[:3]); e != nil || string(b[:3]) != "tcp" {
					t.Fatalf("TCP echo: %v", e)
				}
				pc.SetDeadline(time.Now().Add(3 * time.Second))
				if _, e := pc.WriteTo([]byte("udp"), dest); e != nil {
					t.Fatal(e)
				}
				n, _, e := pc.ReadFrom(b[:])
				if e != nil || string(b[:n]) != "udp" {
					t.Fatalf("UDP echo: %v", e)
				}
			}
			echo()
			serverFlows := ids()
			if serverFlows["tcp"] == "" || serverFlows["udp"] == "" {
				t.Fatal("protocol peer did not receive both flows")
			}
			for i := 0; i < 32; i++ {
				spare["server_port"] = 21101 + i
				if err = s.apply(t, "transport"); err != nil {
					t.Fatal(err)
				}
				echo()
			}
			if current, _ := service.FromContext[adapter.OutboundManager](s.view).Outbound("transport"); current != initial || !reflect.DeepEqual(ids(), serverFlows) {
				t.Fatal("unrelated changes replaced the live transport or its sessions")
			}
		})
	}
}

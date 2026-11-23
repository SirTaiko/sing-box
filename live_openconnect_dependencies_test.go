//go:build with_openconnect && with_gvisor

package box_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

func TestDesktopLiveOpenConnectDNSFollowsItsEndpoint(t *testing.T) {
	s := newSession(t, nil)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "fixture", http.StatusServiceUnavailable) }))
	defer server.Close()
	endpoint := object{"type": "openconnect", "tag": "work", "system": false, "server": server.URL, "username": "fixture", "domain_resolver": "resolver", "tls": object{"insecure": true}}
	s.cfg["endpoints"] = []object{endpoint}
	dns := s.cfg["dns"].(object)
	servers := append(dns["servers"].([]object), object{"type": "openconnect", "tag": "work-dns", "endpoint": "work", "accept_default_resolvers": true}, object{"type": "udp", "tag": "unused", "server": "127.0.0.1", "server_port": resolver(t, "192.0.2.33")})
	dns["servers"] = servers
	apply := func() {
		t.Helper()
		if err := s.apply(t, "a"); err != nil {
			t.Fatal(err)
		}
	}
	apply()
	endpoints := service.FromContext[adapter.EndpointManager](s.view)
	transports := service.FromContext[adapter.DNSTransportManager](s.view)
	oldEndpoint, ok := endpoints.Get("work")
	if !ok {
		t.Fatal("missing endpoint")
	}
	oldDNS, ok := transports.Transport("work-dns")
	if !ok {
		t.Fatal("missing corporate resolver")
	}
	servers[2]["server_port"] = resolver(t, "192.0.2.34")
	apply()
	if ep, _ := endpoints.Get("work"); ep != oldEndpoint {
		t.Fatal("unrelated DNS edit replaced endpoint")
	}
	if dns, _ := transports.Transport("work-dns"); dns != oldDNS {
		t.Fatal("unrelated DNS edit replaced corporate resolver")
	}
	servers[0]["server_port"] = resolver(t, "192.0.2.35")
	apply()
	if ep, _ := endpoints.Get("work"); ep == oldEndpoint {
		t.Fatal("changed endpoint resolver was not rebound")
	}
	if dns, _ := transports.Transport("work-dns"); dns == oldDNS {
		t.Fatal("corporate resolver still references the previous endpoint")
	}
}

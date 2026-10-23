package desync

// D3 portable capture selector tests: compilation, intersection with the owned
// envelope and runtime dispatch gating. No native capture is opened.

import (
	"net/netip"
	"testing"
)

func TestCaptureSelectorCompileAndValidate(t *testing.T) {
	valid := `{"enabled":true,"capture":{"network":["tcp"],"ip_version":[4],
		"port_range":["443-445"],"port_exclude":[444]},
		"rules":[{"network":["tcp"],"port":[443],"orig":{"ttl":9}}]}`
	config, err := compileCaptureLinux(t, valid)
	if err != nil {
		t.Fatalf("valid portable selectors rejected: %v", err)
	}
	selector := config.Capture.selectors
	if !selector.allows(FamilyIPv4, TransportTCP, 443) {
		t.Fatal("port 443 not allowed")
	}
	if selector.allows(FamilyIPv4, TransportTCP, 444) {
		t.Fatal("excluded port 444 allowed")
	}
	if selector.allows(FamilyIPv6, TransportTCP, 443) {
		t.Fatal("IPv6 allowed despite ip_version [4]")
	}
	if selector.allows(FamilyIPv4, TransportUDP, 443) {
		t.Fatal("UDP allowed despite network [tcp]")
	}
	if selector.allows(FamilyIPv4, TransportTCP, 446) {
		t.Fatal("port outside the range allowed")
	}
	invalid := []string{
		`{"enabled":true,"capture":{"network":["sctp"]},"rules":[{"network":["tcp"],"port":[443],"orig":{"ttl":9}}]}`,
		`{"enabled":true,"capture":{"ip_version":[5]},"rules":[{"network":["tcp"],"port":[443],"orig":{"ttl":9}}]}`,
		`{"enabled":true,"capture":{"port_range":["bad"]},"rules":[{"network":["tcp"],"port":[443],"orig":{"ttl":9}}]}`,
		`{"enabled":true,"capture":{"port_range_exclude":["1-2-3"]},"rules":[{"network":["tcp"],"port":[443],"orig":{"ttl":9}}]}`,
	}
	for _, content := range invalid {
		if _, err := compileCaptureLinux(t, content); err == nil {
			t.Fatalf("invalid selector accepted: %s", content)
		}
	}
	// Absent selectors match every owned family/transport/port.
	var empty captureSelector
	empty.ipv4, empty.ipv6 = true, true
	if !empty.allows(FamilyIPv4, TransportUDP, 53) || !empty.allows(FamilyIPv6, TransportTCP, 1) {
		t.Fatal("empty selector did not match the owned envelope")
	}
}

func TestCaptureSelectorExcludesOwnedTupleAtOpen(t *testing.T) {
	config, err := compileCaptureLinux(t, `{"enabled":true,"capture":{"port":[8443]},
		"rules":[{"network":["tcp"],"port":[443],"orig":{"ttl":9}}]}`)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	source := netip.MustParseAddrPort("192.0.2.10:40000")
	lease, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportTCP,
		Source: source, Destination: netip.MustParseAddrPort("198.51.100.20:443")})
	if err != nil {
		t.Fatal(err)
	}
	lease.SetLocalAddress(source)
	endpoint := lease.Endpoint()
	if config.Capture.selectors.allowsEndpoint(endpoint) {
		t.Fatal("selector allowed the excluded owned tuple")
	}
	// The native backends reject the configuration instead of opening a
	// capture that can never see its own flow (checked without opening one).
	if err = lease.StartCapture(); err == nil {
		t.Fatal("capture started despite an excluding selector")
	}
}

func TestCaptureSelectorGatesRuntimeDispatch(t *testing.T) {
	config, err := compileCaptureLinux(t, `{"enabled":true,"capture":{"port":[8443]},
		"rules":[{"network":["tcp"],"port":[443],"orig":{"ttl":9}}]}`)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	if engine.Config().Capture.selectors.allows(FamilyIPv4, TransportTCP, 443) {
		t.Fatal("selector unexpectedly allows 443")
	}
}

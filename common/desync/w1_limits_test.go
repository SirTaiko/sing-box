package desync

// W1 disposition regressions: the production option path must never produce a
// lease bound that refuses every attempt. A zero-valued LimitSet is a test
// fixture artefact, not a configuration Compile can emit (it starts from
// defaultLimits()), so the native activation-gate test failed on its own
// fixture with "desync: active lease limit reached (0)".
//
// The capture-selection case below is host-agnostic on purpose: the
// capture.windows compiler and the owned-envelope decision are pure code, so
// the non-port-selector F1 regression runs here as well as natively.

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestW1CompiledDefaultLimitsAdmitAttempts(t *testing.T) {
	config, err := Compile(enabledOption(`{"enabled":true,"rules":[
		{"name":"tls","network":["tcp"],"port":[443],"methods":["fake"],
		 "fake":{"repeats":1,"payloads":[{"protocol":"tls","hex":"16030100"}]}}]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	if config.Limits.MaxLeases <= 0 || config.Limits.MaxLeases != defaultLimits().MaxLeases {
		t.Fatalf("compiled max_leases = %d, want the documented default %d",
			config.Limits.MaxLeases, defaultLimits().MaxLeases)
	}
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	lease, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportTCP,
		Source:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Destination: netip.MustParseAddrPort("198.51.100.20:443")})
	if err != nil {
		t.Fatalf("default limits must admit an attempt: %v", err)
	}
	if err = lease.Close(nil); err != nil {
		t.Fatal(err)
	}
	// A zero/omitted limits block is the documented default, never deny-all.
	if _, err = Compile(enabledOption(`{"enabled":true,"limits":{"max_leases":0},"rules":[
		{"name":"tls","network":["tcp"],"port":[443],"methods":["fake"],
		 "fake":{"repeats":1,"payloads":[{"protocol":"tls","hex":"16030100"}]}}]}`), ""); err != nil {
		t.Fatal(err)
	}
}

// TestW1NonPortSelectorKeepsTCPAdmission is the F1 live form: a
// capture.windows block whose only selector is filter_lan must not erase the
// default TCP admission, while an explicit port restriction still refuses the
// excluded owned tuple. The composed filter is still the owned envelope, so
// nothing wider than the owned tuple can be captured.
func TestW1NonPortSelectorKeepsTCPAdmission(t *testing.T) {
	endpoint := Endpoint{
		Family:         FamilyIPv4,
		Transport:      TransportTCP,
		Source:         netip.MustParseAddrPort("192.0.2.10:40000"),
		Destination:    netip.MustParseAddrPort("198.51.100.20:443"),
		InterfaceIndex: 12,
	}
	lan := false
	nonPort, err := compileWindowsCapture(&option.DirectDesyncCaptureWindows{FilterLAN: &lan})
	if err != nil {
		t.Fatal(err)
	}
	if err = nonPort.excludesOwnedEndpoint(endpoint); err != nil {
		t.Fatalf("filter_lan alone must not exclude the owned TCP attempt: %v", err)
	}
	filter, err := nonPort.captureFilter(endpoint, true)
	if err != nil {
		t.Fatal(err)
	}
	expression := filter.Expression()
	for _, fragment := range []string{"198.51.100.20", "40000", "tcp"} {
		if !strings.Contains(expression, fragment) {
			t.Fatalf("composed filter misses the owned tuple fragment %q: %s", fragment, expression)
		}
	}
	if strings.Contains(expression, "0.0.0.0") {
		t.Fatalf("composed filter compares an unspecified address: %s", expression)
	}
	// An explicit single-transport restriction keeps refusing the owned TCP
	// attempt: only omission means "no port clause".
	udpOnly, err := compileWindowsCapture(&option.DirectDesyncCaptureWindows{WFUDP: []string{"443"}})
	if err != nil {
		t.Fatal(err)
	}
	if err = udpOnly.excludesOwnedEndpoint(endpoint); err == nil {
		t.Fatal("wf_udp alone must still exclude the owned TCP attempt")
	}
	// A configured TCP list that does not contain the owned port still refuses.
	wrongPort, err := compileWindowsCapture(&option.DirectDesyncCaptureWindows{WFTCP: []string{"8443"}})
	if err != nil {
		t.Fatal(err)
	}
	if err = wrongPort.excludesOwnedEndpoint(endpoint); err == nil {
		t.Fatal("wf_tcp 8443 must still exclude the owned port 443")
	}
}

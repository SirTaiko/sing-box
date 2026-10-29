package desync

// Hermetic tests for the Windows capture narrowing and the SSID/NLM activation
// gate. They exercise the production compilation/decision code on any host: no
// Windows driver, adapter or COM object is involved.

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/windivert"
	"github.com/sagernet/sing-box/option"
)

type fakeProbe struct {
	ssidMatch bool
	nlmMatch  bool
	ssidErr   error
	nlmErr    error
	ssidCalls int
	nlmCalls  int
	snapshot  WindowsNetworkSnapshot
}

func (p *fakeProbe) MatchSSID(context.Context, []string) (bool, error) {
	p.ssidCalls++
	return p.ssidMatch, p.ssidErr
}

func (p *fakeProbe) MatchNLM(context.Context, []string) (bool, error) {
	p.nlmCalls++
	return p.nlmMatch, p.nlmErr
}

func (p *fakeProbe) Snapshot(context.Context) (WindowsNetworkSnapshot, error) {
	return p.snapshot, nil
}

func windowsEndpoint() Endpoint {
	return Endpoint{
		Family:         FamilyIPv4,
		Transport:      TransportTCP,
		Source:         netip.MustParseAddrPort("192.0.2.10:40000"),
		Destination:    netip.MustParseAddrPort("198.51.100.20:443"),
		InterfaceIndex: 12,
	}
}

// newWindowsTestEngine builds an engine with the hermetic backend seam.
func newWindowsTestEngine(t *testing.T, config *Config) *Engine {
	t.Helper()
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	return engine
}

// captureWindowsConfig compiles a capture.windows block through the production
// option → captureConfig path.
func captureWindowsConfig(t *testing.T, block *option.DirectDesyncCaptureWindows) *windowsCaptureConfig {
	t.Helper()
	capture, err := compileWindowsCapture(block)
	if err != nil {
		t.Fatalf("compile capture.windows: %v", err)
	}
	return capture
}

func TestCaptureWindowsFilterCompositionAndLAN(t *testing.T) {
	lan := false
	capture := captureWindowsConfig(t, &option.DirectDesyncCaptureWindows{
		WFTCP:     []string{"443", "8000-8100", "~8080"},
		FilterLAN: &lan,
	})
	endpoint := windowsEndpoint()
	expression, err := capture.userExpression(endpoint, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"tcp.DstPort == 443", "tcp.DstPort >= 8000", "tcp.DstPort != 8080"} {
		if !strings.Contains(expression, fragment) {
			t.Fatalf("outbound expression %q misses %q", expression, fragment)
		}
	}
	inbound, err := capture.userExpression(endpoint, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(inbound, "tcp.SrcPort") || strings.Contains(inbound, "tcp.DstPort") {
		t.Fatalf("inbound expression is not source-port based: %q", inbound)
	}
	// The composed filter must compile and must be rejected for a foreign
	// interface index.
	filter, err := capture.captureFilter(endpoint, true)
	if err != nil {
		t.Fatal(err)
	}
	if filter.InstructionCount() <= 0 {
		t.Fatal("composed filter has no instructions")
	}
	foreign := endpoint
	foreign.InterfaceIndex = 13
	if err = capture.excludesOwnedEndpoint(foreign); err != nil {
		t.Fatalf("a different iface must be usable when wf_iface is absent: %v", err)
	}
	fixed := captureWindowsConfig(t, &option.DirectDesyncCaptureWindows{WFIface: "12"})
	if err = fixed.excludesOwnedEndpoint(foreign); err == nil {
		t.Fatal("wf_iface 12 must exclude an owned attempt on interface 13")
	}
	if err = fixed.excludesOwnedEndpoint(endpoint); err != nil {
		t.Fatalf("wf_iface must accept the owned interface: %v", err)
	}
	// LAN exclusion is on by default and is direction-specific.
	defaultCapture := captureWindowsConfig(t, &option.DirectDesyncCaptureWindows{})
	if !strings.Contains(defaultCapture.lanExpression(endpoint, true), "ip.DstAddr") {
		t.Fatal("outbound LAN exclusion must test the destination")
	}
	if !strings.Contains(defaultCapture.lanExpression(endpoint, false), "ip.SrcAddr") {
		t.Fatal("inbound LAN exclusion must test the source")
	}
	if expr := defaultCapture.lanExpression(endpoint, true); !strings.Contains(expr, "192.168.0.0") {
		t.Fatalf("LAN exclusion misses private ranges: %q", expr)
	}
	// F1 live regression: a capture block whose only selector is a non-port one
	// (filter_lan) must not erase the default transport admission. Upstream
	// omits the port clause entirely then; the owned envelope still pins the
	// exact tuple, so the owned TCP attempt is captured and nothing wider.
	lanOnly := false
	nonPort := captureWindowsConfig(t, &option.DirectDesyncCaptureWindows{FilterLAN: &lanOnly})
	if err = nonPort.excludesOwnedEndpoint(endpoint); err != nil {
		t.Fatalf("a non-port selector must not exclude the owned TCP attempt: %v", err)
	}
	owned, err := nonPort.captureFilter(endpoint, true)
	if err != nil {
		t.Fatal(err)
	}
	ownedText := owned.Expression()
	for _, fragment := range []string{"198.51.100.20", "40000", "tcp"} {
		if !strings.Contains(ownedText, fragment) {
			t.Fatalf("composed filter %q misses the owned tuple fragment %q", ownedText, fragment)
		}
	}
	if strings.Contains(ownedText, "0.0.0.0") {
		t.Fatalf("composed filter still compares an unspecified address: %q", ownedText)
	}
	// An explicitly configured restriction on the other transport still
	// refuses the owned attempt: the user did narrow transports.
	if err = udpOnlyCapture(t).excludesOwnedEndpoint(endpoint); err == nil {
		t.Fatal("wf_udp alone must still exclude the owned TCP attempt")
	}
}

// udpOnlyCapture is the explicit single-transport restriction used above.
func udpOnlyCapture(t *testing.T) *windowsCaptureConfig {
	t.Helper()
	return captureWindowsConfig(t, &option.DirectDesyncCaptureWindows{WFUDP: []string{"443"}})
}

func TestCaptureWindowsSelectorRefusals(t *testing.T) {
	ipv6Only := captureWindowsConfig(t, &option.DirectDesyncCaptureWindows{WFL3: []string{"ipv6"}})
	if err := ipv6Only.excludesOwnedEndpoint(windowsEndpoint()); err == nil {
		t.Fatal("wf_l3 ipv6 must exclude an owned IPv4 attempt")
	}
	udpOnly := captureWindowsConfig(t, &option.DirectDesyncCaptureWindows{WFUDP: []string{"443"}})
	if err := udpOnly.excludesOwnedEndpoint(windowsEndpoint()); err == nil {
		t.Fatal("wf_udp must exclude an owned TCP attempt")
	}
	tcpWrongPort := captureWindowsConfig(t, &option.DirectDesyncCaptureWindows{WFTCP: []string{"8443"}})
	if err := tcpWrongPort.excludesOwnedEndpoint(windowsEndpoint()); err == nil {
		t.Fatal("wf_tcp 8443 must exclude the owned port 443")
	}
	if _, err := compileWindowsCapture(&option.DirectDesyncCaptureWindows{WFIface: "x"}); err == nil {
		t.Fatal("malformed wf_iface accepted")
	}
	if _, err := compileWindowsCapture(&option.DirectDesyncCaptureWindows{WFL3: []string{"ipx"}}); err == nil {
		t.Fatal("unknown wf_l3 accepted")
	}
	if _, err := compileWindowsCapture(&option.DirectDesyncCaptureWindows{WFTCP: []string{"0"}}); err == nil {
		t.Fatal("port 0 accepted")
	}
	// A 36-character GUID-shaped selector must be a real GUID. The previous
	// literal was 35 characters, so it took the "network name" path and never
	// exercised the validation it claimed to test.
	malformedGUID := "00000000-0000-0000-0000-00000000000Z"
	if len(malformedGUID) != 36 {
		t.Fatalf("fixture %q is not 36 characters", malformedGUID)
	}
	if _, err := compileWindowsCapture(&option.DirectDesyncCaptureWindows{NLMFilter: []string{malformedGUID}}); err == nil {
		t.Fatal("a 36-character non-GUID nlm_filter entry was accepted")
	}
	// Positive controls: a real GUID and an NLM network name are both valid
	// selectors (upstream compares the name first and the GUID second).
	if _, err := compileWindowsCapture(&option.DirectDesyncCaptureWindows{NLMFilter: []string{"6ba7b810-9dad-11d1-80b4-00c04fd430c8"}}); err != nil {
		t.Fatalf("a valid GUID nlm_filter entry was refused: %v", err)
	}
	if _, err := compileWindowsCapture(&option.DirectDesyncCaptureWindows{NLMFilter: []string{"Home Network"}}); err != nil {
		t.Fatalf("an NLM network name was refused: %v", err)
	}
	if _, err := compileWindowsCapture(&option.DirectDesyncCaptureWindows{SSIDFilter: []string{""}}); err == nil {
		t.Fatal("empty SSID accepted")
	}
	if _, err := compileWindowsCapture(&option.DirectDesyncCaptureWindows{WFRawPart: []string{"tcp and ("}}); err == nil {
		t.Fatal("malformed wf_raw_part accepted")
	}
}

func TestCaptureWindowsFilterDumpIsOptIn(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "filter.txt")
	// Compilation with filter_save configured must not write anything.
	capture := captureWindowsConfig(t, &option.DirectDesyncCaptureWindows{
		WFTCP:      []string{"443"},
		FilterSave: path,
	})
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("configuration compilation wrote the filter dump: %v", err)
	}
	// The activation dump writes both directions once, bounded.
	if err := capture.writeFilterDump(windowsEndpoint()); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	if !strings.Contains(text, "# outbound") || !strings.Contains(text, "# inbound") {
		t.Fatalf("dump is missing a direction:\n%s", text)
	}
	if !strings.Contains(text, "ip.SrcAddr") || !strings.Contains(text, "ip.DstAddr") {
		t.Fatalf("dump is missing the composed envelope:\n%s", text)
	}
	if len(text) > windivert.MaxFilterExpressionBytes() {
		t.Fatal("dump exceeded its bound")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("dump mode = %v, want 0600", info.Mode().Perm())
	}
	// No filter_save means no write at activation either.
	plain := captureWindowsConfig(t, &option.DirectDesyncCaptureWindows{WFTCP: []string{"443"}})
	if err = plain.writeFilterDump(windowsEndpoint()); err != nil {
		t.Fatal(err)
	}
}

func TestActivationGateTransitions(t *testing.T) {
	engine := newWindowsTestEngine(t, &Config{Capture: captureConfig{
		windows: &windowsCaptureConfig{ssidFilter: []string{"HomeWifi"}, nlmFilter: []string{"Home"}},
	}})
	probe := &fakeProbe{ssidMatch: true, nlmMatch: true}
	engine.SetNetworkProbe(probe)
	if !engine.activationAllows() {
		t.Fatal("matching SSID and NLM must activate")
	}
	// Rate limiting: a second packet within the interval must not re-query.
	engine.activationAllows()
	if probe.ssidCalls != 1 || probe.nlmCalls != 1 {
		t.Fatalf("gate did not rate limit: ssid=%d nlm=%d", probe.ssidCalls, probe.nlmCalls)
	}
	// After the interval the changed state is observed.
	probe.ssidMatch = false
	engine.SetHoldClock(func() time.Time { return time.Now().Add(2 * activationQueryInterval) })
	if engine.activationAllows() {
		t.Fatal("absent SSID must deactivate")
	}
	// An error deactivates and is reported, keeping every packet passive.
	probe.ssidErr = errInjectedProbe
	engine.SetHoldClock(func() time.Time { return time.Now().Add(4 * activationQueryInterval) })
	if engine.activationAllows() {
		t.Fatal("probe error must deactivate")
	}
	status := engine.ActivationStatus()
	if !status.Configured || status.Active || !strings.Contains(status.LastError, "probe") {
		t.Fatalf("status = %+v", status)
	}
}

func TestActivationGatePerEngineAndPassThrough(t *testing.T) {
	// The fixture must carry the production limit defaults: a zero-valued
	// LimitSet means "no leases admitted", which is not a configuration the
	// option path can produce (Compile starts from defaultLimits()). With the
	// zero value this test failed on NewAttempt before reaching its invariant.
	config := func(ssid string) *Config {
		// compileWindowsCapture is the only production path that builds this
		// struct, and it starts from l3v4/l3v6/filterLAN = true. A zero-valued
		// windowsCaptureConfig therefore does not describe any reachable
		// configuration: it would refuse the owned IPv4 attempt before the gate
		// is ever consulted. Keep the fixture equal to the product defaults.
		return &Config{Limits: defaultLimits(), Capture: captureConfig{windows: &windowsCaptureConfig{
			l3v4: true, l3v6: true, filterLAN: true, ssidFilter: []string{ssid}}}}
	}
	first := newWindowsTestEngine(t, config("First"))
	second := newWindowsTestEngine(t, config("Second"))
	first.SetNetworkProbe(&fakeProbe{ssidMatch: true})
	second.SetNetworkProbe(&fakeProbe{ssidMatch: false})
	if !first.activationAllows() {
		t.Fatal("first engine must be active")
	}
	if second.activationAllows() {
		t.Fatal("second engine must stay inactive; activation state is not shared")
	}
	// A configuration without SSID/NLM filters never queries the probe.
	plain := newWindowsTestEngine(t, &Config{})
	plain.SetNetworkProbe(&fakeProbe{})
	if !plain.activationAllows() {
		t.Fatal("an unconfigured gate must allow")
	}
	// Inactive capture passes packets untouched: the gate is checked before
	// any planner work in Lease.HandlePacket.
	probe := &fakeProbe{ssidMatch: false}
	engine := newWindowsTestEngine(t, config("Home"))
	engine.SetNetworkProbe(probe)
	lease, backendErr := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportTCP,
		Source: netip.MustParseAddrPort("192.0.2.10:40000"), Destination: netip.MustParseAddrPort("198.51.100.20:443")})
	if backendErr != nil {
		t.Fatal(backendErr)
	}
	defer lease.Close(nil)
	if err := lease.StartCapture(); err != nil {
		t.Fatal(err)
	}
	verdict := lease.HandlePacket(buildIPv4TCP(t, nil, 0, tcpFlagSYN).Raw, DirectionOutbound, nil, nil)
	if verdict != VerdictPass {
		t.Fatalf("inactive capture verdict = %v, want pass", verdict)
	}
}

var errInjectedProbe = &probeError{}

type probeError struct{}

func (*probeError) Error() string { return "probe failure injected by test" }

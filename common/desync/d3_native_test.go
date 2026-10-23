package desync

// D3 native capture controls: compile-time validation, mark preservation and
// interface/selector construction. No native/privileged action is performed.

import (
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

func compileCaptureLinux(t *testing.T, content string) (*Config, error) {
	t.Helper()
	var options option.DirectDesyncOptions
	if err := json.Unmarshal([]byte(content), &options); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return Compile(&options, "")
}

func TestCaptureLinuxQnumValidation(t *testing.T) {
	valid := `{"enabled":true,"capture":{"linux":{"qnum":5000,"fwmark":3,"bind_fix4":true,"bind_fix6":false}},
		"rules":[{"network":["tcp"],"port":[443],"orig":{"ttl":9}}]}`
	config, err := compileCaptureLinux(t, valid)
	if err != nil {
		t.Fatalf("valid capture rejected: %v", err)
	}
	if !config.Capture.qnumSet || config.Capture.qnum != 5000 {
		t.Fatalf("qnum not compiled: %+v", config.Capture)
	}
	if !config.Capture.fwmarkSet || config.Capture.fwmark != 3 {
		t.Fatalf("fwmark not compiled: %+v", config.Capture)
	}
	if !config.Capture.bindFix4 || config.Capture.bindFix6 {
		t.Fatalf("bind-fix flags not compiled: %+v", config.Capture)
	}
	// Configuration compilation must not reserve or bind the queue.
	qnumRegistry.mu.Lock()
	_, reserved := qnumRegistry.live[5000]
	qnumRegistry.mu.Unlock()
	if reserved {
		t.Fatal("config compilation reserved a live queue identity")
	}

	cases := []struct {
		name string
		qnum string
	}{
		{"negative", `-1`},
		{"above range", `65536`},
	}
	for _, tc := range cases {
		content := `{"enabled":true,"capture":{"linux":{"qnum":` + tc.qnum + `}},
			"rules":[{"network":["tcp"],"port":[443],"orig":{"ttl":9}}]}`
		if _, err := compileCaptureLinux(t, content); err == nil {
			t.Fatalf("%s qnum %s accepted", tc.name, tc.qnum)
		}
	}
	// An explicit identity inside the managed allocation window is legal
	// (upstream accepts 0..65535); the allocator avoids the reservation.
	if _, err := compileCaptureLinux(t, `{"enabled":true,"capture":{"linux":{"qnum":2000}},
		"rules":[{"network":["tcp"],"port":[443],"orig":{"ttl":9}}]}`); err != nil {
		t.Fatalf("explicit qnum inside the managed window rejected: %v", err)
	}
	if _, err := compileCaptureLinux(t, `{"enabled":true,"capture":{"linux":{"qnum":65535}},
		"rules":[{"network":["tcp"],"port":[443],"orig":{"ttl":9}}]}`); err != nil {
		t.Fatalf("qnum 65535 rejected: %v", err)
	}
}

func TestCaptureQnumReservationCollisionAndRelease(t *testing.T) {
	if err := reserveQnum(7000); err != nil {
		t.Fatalf("first reservation failed: %v", err)
	}
	if err := reserveQnum(7000); err == nil {
		t.Fatal("second reservation of the same identity accepted")
	}
	if err := reserveQnum(7001); err != nil {
		t.Fatalf("different identity rejected: %v", err)
	}
	releaseQnum(7000)
	releaseQnum(7001)
	if err := reserveQnum(7000); err != nil {
		t.Fatalf("released identity not reusable: %v", err)
	}
	releaseQnum(7000)
}

func TestInjectionMarkPreservesRoutingBits(t *testing.T) {
	base := 0x0000_1800
	config := captureConfig{fwmark: 0x0000_0002, fwmarkSet: true}
	got := injectionMark(base, config)
	if got != base|0x2 {
		t.Fatalf("mark = %#x, want %#x", got, base|0x2)
	}
	if got&base != base {
		t.Fatalf("dialer-owned mark bits cleared: %#x", got)
	}
	// An unset fwmark leaves the routing mark untouched.
	if got := injectionMark(base, captureConfig{}); got != base {
		t.Fatalf("unset fwmark changed the mark: %#x", got)
	}
	// An explicit zero is meaningful and still preserves the base mark.
	zero := uint32(0)
	if got := injectionMark(base, captureConfig{fwmark: zero, fwmarkSet: true}); got != base {
		t.Fatalf("explicit zero fwmark changed the mark: %#x", got)
	}
}

func TestBindSourceFamilyGating(t *testing.T) {
	config := captureConfig{bindFix4: true}
	if !bindSource(config, FamilyIPv4) {
		t.Fatal("bind_fix4 not applied to IPv4")
	}
	if bindSource(config, FamilyIPv6) {
		t.Fatal("bind_fix4 leaked into IPv6")
	}
	config = captureConfig{bindFix6: true}
	if !bindSource(config, FamilyIPv6) || bindSource(config, FamilyIPv4) {
		t.Fatal("bind_fix6 family gating wrong")
	}
	if bindSource(captureConfig{}, FamilyIPv4) || bindSource(captureConfig{}, FamilyIPv6) {
		t.Fatal("unset bind-fix applied")
	}
}

func TestCaptureWindowsIsTypedAndValidated(t *testing.T) {
	// capture.windows is now a typed, implemented extension: strict decoding
	// accepts it, configuration compilation validates every selector and stays
	// read-only, and a raw expression is parsed by the WinDivert compiler
	// rather than forwarded as a blob.
	content := `{"enabled":true,"capture":{"windows":{"wf_iface":"1.0","wf_l3":["ipv4"],
		"wf_tcp":["443","~1000-2000"],"filter_lan":true,
		"wf_raw_part":["tcp.Syn or tcp.PayloadLength > 0"]}},
		"rules":[{"network":["tcp"],"port":[443],"orig":{"ttl":9}}]}`
	var options option.DirectDesyncOptions
	if err := json.UnmarshalDisallowUnknownFields([]byte(content), &options); err != nil {
		t.Fatalf("typed capture.windows rejected by strict decoding: %v", err)
	}
	config, err := compileNativeCapture(options.Capture)
	if err != nil {
		t.Fatalf("capture.windows compile: %v", err)
	}
	if config.windows == nil {
		t.Fatal("capture.windows was not compiled")
	}
	if !config.windows.ifaceSet || config.windows.iface != 1 || config.windows.subIfIdx != 0 {
		t.Fatalf("wf_iface parsed as %+v", config.windows)
	}
	if config.windows.filterSave != "" {
		t.Fatal("filter_save must default to no write")
	}
	// An unsupported raw field is an explicit error, never an ignored filter.
	bad := `{"capture":{"windows":{"wf_raw":"frobnicate == 1"}}}`
	var badOptions option.DirectDesyncOptions
	if err = json.UnmarshalDisallowUnknownFields([]byte(bad), &badOptions); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, err = compileNativeCapture(badOptions.Capture); err == nil {
		t.Fatal("unsupported raw expression was accepted")
	}
	// wf_raw replaces the other selectors upstream; a conflicting mix is
	// refused explicitly instead of being silently ignored.
	conflict := `{"capture":{"windows":{"wf_raw":"tcp","wf_tcp":["443"]}}}`
	var conflictOptions option.DirectDesyncOptions
	if err = json.UnmarshalDisallowUnknownFields([]byte(conflict), &conflictOptions); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, err = compileNativeCapture(conflictOptions.Capture); err == nil {
		t.Fatal("wf_raw with wf_tcp was accepted")
	}
}

func TestDomainSetHostnameIsIPExactOnly(t *testing.T) {
	set := &domainSet{entries: []string{"example.com", "203.0.113.7"}}
	if !set.matchesHost("example.com", false) || !set.matchesHost("sub.example.com", false) {
		t.Fatal("name matching must keep suffix semantics")
	}
	if set.matchesHost("sub.203.0.113.7", true) {
		t.Fatal("IP literal matched a subdomain")
	}
	if !set.matchesHost("203.0.113.7", true) {
		t.Fatal("exact IP literal entry did not match")
	}
	if set.matchesHost("203.0.113.8", true) {
		t.Fatal("different IP literal matched")
	}
}

package desync

// D3 capture-policy schema: NFQWS_*_PKT_* packet limits and
// NFQWS_PORTS_*_KEEPALIVE port ranges (U4 section 6). Configuration
// compilation is read-only and never binds a queue or opens a socket.

import (
	"strconv"
	"testing"
)

func TestCapturePacketLimitsCompile(t *testing.T) {
	// Absent packet_limits keeps the previous unlimited capture: no limit is
	// set on any direction.
	config, err := compileCaptureLinux(t, `{"enabled":true,"rules":[{"network":["tcp"],"port":[443],"orig":{"ttl":9}}]}`)
	if err != nil {
		t.Fatalf("absent limits rejected: %v", err)
	}
	for name, limit := range map[string]packetLimit{
		"tcp_out": config.Capture.limits.tcpOut,
		"tcp_in":  config.Capture.limits.tcpIn,
		"udp_out": config.Capture.limits.udpOut,
		"udp_in":  config.Capture.limits.udpIn,
	} {
		if limit.set {
			t.Fatalf("%s set without configuration: %+v", name, limit)
		}
		if !limit.enabled() || limit.bounded() {
			t.Fatalf("%s absent limit must be enabled and unbounded: %+v", name, limit)
		}
	}

	// Explicit values preserve zero (direction disabled) versus a positive
	// inclusive bound.
	config, err = compileCaptureLinux(t, `{"enabled":true,"capture":{"linux":{"packet_limits":{"tcp_out":1,"udp_out":0}}},
		"rules":[{"network":["tcp"],"port":[443],"orig":{"ttl":9}}]}`)
	if err != nil {
		t.Fatalf("valid limits rejected: %v", err)
	}
	if !config.Capture.limits.tcpOut.set || config.Capture.limits.tcpOut.value != 1 {
		t.Fatalf("tcp_out = %+v, want 1", config.Capture.limits.tcpOut)
	}
	if !config.Capture.limits.udpOut.set || config.Capture.limits.udpOut.value != 0 || config.Capture.limits.udpOut.enabled() {
		t.Fatalf("udp_out = %+v, want explicit zero/disabled", config.Capture.limits.udpOut)
	}
	if config.Capture.limits.tcpIn.set || config.Capture.limits.udpIn.set {
		t.Fatal("unconfigured inbound limit compiled as set")
	}

	// Negative values are invalid, not clamped.
	if _, err = compileCaptureLinux(t, `{"enabled":true,"capture":{"linux":{"packet_limits":{"tcp_out":-1}}},
		"rules":[{"network":["tcp"],"port":[443],"orig":{"ttl":9}}]}`); err == nil {
		t.Fatal("negative tcp_out accepted")
	}

	// A positive inbound bound is the reply-direction kernel counter and is
	// accepted; the capture installs it as `ct reply packets 1-N` (verified
	// byte-wise in d3_reply_icmp_linux_test.go). It is never silently matched
	// against the original direction.
	for _, field := range []struct {
		name string
	}{
		{"tcp_in"},
		{"udp_in"},
	} {
		for _, value := range []int{1, 3} {
			content := `{"enabled":true,"capture":{"linux":{"packet_limits":{"` + field.name + `":` + strconv.Itoa(value) + `}}},` +
				`"rules":[{"network":["tcp"],"port":[443],"orig":{"ttl":9}}]}`
			compiled, compileErr := compileCaptureLinux(t, content)
			if compileErr != nil {
				t.Fatalf("%s=%d rejected: %v", field.name, value, compileErr)
			}
			var limit packetLimit
			if field.name == "tcp_in" {
				limit = compiled.Capture.limits.tcpIn
			} else {
				limit = compiled.Capture.limits.udpIn
			}
			if !limit.set || !limit.bounded() || limit.value != value {
				t.Fatalf("%s = %+v, want bounded %d", field.name, limit, value)
			}
		}
		// Zero (direction disabled) stays accepted and is not a bound.
		content := `{"enabled":true,"capture":{"linux":{"packet_limits":{"` + field.name + `":0}}},` +
			`"rules":[{"network":["tcp"],"port":[443],"orig":{"ttl":9}}]}`
		if _, err = compileCaptureLinux(t, content); err != nil {
			t.Fatalf("%s=0 rejected: %v", field.name, err)
		}
	}
}

func TestCaptureFilterTTLExpiredICMPCompile(t *testing.T) {
	// Default false: upstream FILTER_TTL_EXPIRED_ICMP is off unless requested.
	config, err := compileCaptureLinux(t, `{"enabled":true,"rules":[{"network":["tcp"],"port":[443],"orig":{"ttl":9}}]}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if config.Capture.filterTTLExpiredICMP {
		t.Fatal("filter_ttl_expired_icmp enabled by default")
	}
	config, err = compileCaptureLinux(t, `{"enabled":true,"capture":{"filter_ttl_expired_icmp":true},`+
		`"rules":[{"network":["tcp"],"port":[443],"orig":{"ttl":9}}]}`)
	if err != nil {
		t.Fatalf("explicit enable rejected: %v", err)
	}
	if !config.Capture.filterTTLExpiredICMP {
		t.Fatal("explicit filter_ttl_expired_icmp not compiled")
	}
	// Explicit false stays false.
	config, err = compileCaptureLinux(t, `{"enabled":true,"capture":{"filter_ttl_expired_icmp":false},`+
		`"rules":[{"network":["tcp"],"port":[443],"orig":{"ttl":9}}]}`)
	if err != nil {
		t.Fatalf("explicit disable rejected: %v", err)
	}
	if config.Capture.filterTTLExpiredICMP {
		t.Fatal("explicit false compiled as enabled")
	}
}

func TestCaptureKeepalivePortRangesCompile(t *testing.T) {
	config, err := compileCaptureLinux(t, `{"enabled":true,"capture":{"linux":{
		"packet_limits":{"tcp_out":2,"udp_out":4},
		"tcp_keepalive_port_range":["80","1024-2048"],
		"udp_keepalive_port_range":["443"]}},
		"rules":[{"network":["tcp"],"port":[443],"orig":{"ttl":9}}]}`)
	if err != nil {
		t.Fatalf("keepalive ranges rejected: %v", err)
	}
	for _, tc := range []struct {
		transport Transport
		port      uint16
		want      bool
	}{
		{TransportTCP, 80, true},
		{TransportTCP, 1024, true},
		{TransportTCP, 2048, true},
		{TransportTCP, 2049, false},
		{TransportTCP, 443, false},
		{TransportUDP, 443, true},
		{TransportUDP, 80, false},
	} {
		if got := config.Capture.keepalive.contains(tc.transport, tc.port); got != tc.want {
			t.Fatalf("keepalive contains(%v, %d) = %v, want %v", tc.transport, tc.port, got, tc.want)
		}
	}
	// The range grammar is the existing one: malformed input is a
	// configuration error, never ignored.
	for _, content := range []string{
		`{"enabled":true,"capture":{"linux":{"tcp_keepalive_port_range":["2048-1024"]}},
			"rules":[{"network":["tcp"],"port":[443],"orig":{"ttl":9}}]}`,
		`{"enabled":true,"capture":{"linux":{"udp_keepalive_port_range":["not-a-port"]}},
			"rules":[{"network":["tcp"],"port":[443],"orig":{"ttl":9}}]}`,
	} {
		if _, err := compileCaptureLinux(t, content); err == nil {
			t.Fatalf("malformed keepalive range accepted: %s", content)
		}
	}
}

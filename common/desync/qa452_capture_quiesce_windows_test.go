//go:build windows

package desync

// QA452 regression: the default Windows capture configuration leaves the
// optional TTL-expired ICMP handle unopened (capture.filter_ttl_expired_icmp is
// off unless requested) and a capture that failed before its first handle owns
// no handle at all. `windowsCapture.Quiesce` used to call
// `(*windivert.Handle).ShutdownRecv` on every slot unconditionally, so the absent
// slot reached a nil receiver and aborted the process (QA452 D1: nil dereference
// in handle_windows.go:212 from engine.go:1303). These tests keep the absent
// slots in the shipped slot list, require the close path to skip them, and
// require every handle that was actually opened - ICMP included when enabled -
// to be shut down and retired.

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/windivert"
)

// TestQA452QuiesceSkipsAbsentOptionalHandles is the driver-free shape of the
// defect: `handles()` still lists the three fixed slots, two of which are
// legitimately absent on the default configuration, and this capture never
// opened one at all. Quiesce must return normally and must keep its single
// recorded result instead of touching a handle that appeared afterwards.
func TestQA452QuiesceSkipsAbsentOptionalHandles(t *testing.T) {
	capture := &windowsCapture{dispatch: newCaptureDispatchGate()}
	slots := capture.handles()
	if len(slots) != 3 {
		t.Fatalf("handle slots = %d, want the three fixed slots", len(slots))
	}
	for index, handle := range slots {
		if handle != nil {
			t.Fatalf("slot %d = %v, want the legitimately absent nil slot", index, handle)
		}
	}
	for attempt := 0; attempt < 3; attempt++ {
		if err := capture.Quiesce(); err != nil {
			t.Fatalf("Quiesce attempt %d over absent optional handles = %v, want nil", attempt, err)
		}
	}
	// The recorded single shutdown result is authoritative: a handle that
	// becomes visible after the first call must not be shut down again. A
	// zero-value Handle would fault if ShutdownRecv reached it, so this is an
	// observable idempotence proof without a driver.
	capture.outbound = &windivert.Handle{}
	defer func() { capture.outbound = nil }()
	if err := capture.Quiesce(); err != nil {
		t.Fatalf("repeated Quiesce = %v, want the recorded nil result", err)
	}
}

// qa452LocalIPv4 resolves the owned local address of a real capture: the
// operator override first, otherwise the first non-loopback IPv4 address of the
// host so the test needs no lab-specific constant.
func qa452LocalIPv4(t *testing.T) netip.Addr {
	t.Helper()
	if value := os.Getenv("QA452_LOCAL_IP"); value != "" {
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() {
			t.Fatalf("QA452_LOCAL_IP=%q is not an IPv4 address", value)
		}
		return address
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("interface addresses: %v", err)
	}
	for _, entry := range addresses {
		prefix, ok := entry.(*net.IPNet)
		if !ok {
			continue
		}
		address, ok := netip.AddrFromSlice(prefix.IP.To4())
		if !ok {
			continue
		}
		address = address.Unmap()
		if address.IsLoopback() || address.IsLinkLocalUnicast() {
			continue
		}
		return address
	}
	t.Fatal("no non-loopback IPv4 address to own; set QA452_LOCAL_IP")
	return netip.Addr{}
}

// qa452Peer is a documentation-range destination: the capture only needs an
// owned tuple to install its filter, no traffic is sent, and nothing outside the
// TEST-NET-1 block is ever contacted.
func qa452Peer(t *testing.T) netip.AddrPort {
	t.Helper()
	if value := os.Getenv("QA452_PEER"); value != "" {
		peer, err := netip.ParseAddrPort(value)
		if err != nil {
			t.Fatalf("QA452_PEER=%q: %v", value, err)
		}
		return peer
	}
	return netip.MustParseAddrPort("192.0.2.1:443")
}

// qa452CaptureConfig compiles the owned-capture rule set the regression needs;
// filterTTLExpiredICMP is the documented default (off) unless requested.
func qa452CaptureConfig(t *testing.T, peer netip.AddrPort, icmp bool) *Config {
	t.Helper()
	capture := ``
	if icmp {
		capture = `"capture":{"filter_ttl_expired_icmp":true},`
	}
	content := fmt.Sprintf(`{"enabled":true,`+capture+`"limits":{"max_leases":1,`+
		`"hold_timeout":"8s","max_held_packets":8,"max_held_bytes":65536,`+
		`"max_held_bytes_total":262144},`+
		`"rules":[{"network":["tcp"],"port":[%d],"methods":["multisplit"],`+
		`"multisplit":{"split_pos":["5"]}}]}`, peer.Port())
	config, err := Compile(enabledOption(content), "")
	if err != nil {
		t.Fatalf("compile QA452 config: %v", err)
	}
	return config
}

// TestQA452RealCaptureCloseDefaultAndICMP is the native behaviour regression:
// a real WinDivert capture is opened through the shipped lease path with the
// default configuration (ICMP handle absent - the crashing shape) and with
// filter_ttl_expired_icmp enabled (the non-nil positive control), then closed
// through the real Lease.Close. Close must return, every opened handle must be
// shut down and retired, and the admission slot must be released. It needs the
// WinDivert driver and an owned local address, so QA452_REAL_CAPTURE gates it.
func TestQA452RealCaptureCloseDefaultAndICMP(t *testing.T) {
	if os.Getenv("QA452_REAL_CAPTURE") == "" {
		t.Skip("QA452_REAL_CAPTURE not set: needs the WinDivert driver and an owned local address")
	}
	for _, icmpEnabled := range []bool{false, true} {
		name := "default_icmp_absent"
		if icmpEnabled {
			name = "icmp_enabled"
		}
		t.Run(name, func(t *testing.T) {
			localIP := qa452LocalIPv4(t)
			peer := qa452Peer(t)
			config := qa452CaptureConfig(t, peer, icmpEnabled)
			if config.Capture.filterTTLExpiredICMP != icmpEnabled {
				t.Fatalf("compiled filter_ttl_expired_icmp = %v, want %v",
					config.Capture.filterTTLExpiredICMP, icmpEnabled)
			}
			engine, err := NewEngine(config, NewNativeBackend())
			if err != nil {
				t.Fatalf("engine: %v", err)
			}
			defer engine.Close()
			lease, err := engine.NewAttempt(Intent{
				Family:      FamilyIPv4,
				Transport:   TransportTCP,
				Source:      netip.AddrPortFrom(localIP, 0),
				Destination: peer,
			})
			if err != nil {
				t.Fatalf("attempt: %v", err)
			}
			// The owned endpoint needs a real bound port before the capture
			// envelope can be installed; the capture itself owns the tuple and
			// no traffic is required to open or close it.
			listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: localIP.AsSlice(), Port: 0})
			if err != nil {
				t.Fatalf("bind owned port on %s: %v", localIP, err)
			}
			defer listener.Close()
			lease.SetLocalAddress(netip.MustParseAddrPort(listener.LocalAddr().String()))
			if err := lease.StartCapture(); err != nil {
				t.Fatalf("real StartCapture: %v", err)
			}
			lease.mu.Lock()
			capture, _ := lease.capture.(*windowsCapture)
			lease.mu.Unlock()
			if capture == nil {
				t.Fatalf("lease capture = %T, want the shipped *windowsCapture", lease.capture)
			}
			if capture.outbound == nil || capture.inbound == nil {
				t.Fatalf("opened handles: outbound=%v inbound=%v", capture.outbound, capture.inbound)
			}
			if got := capture.icmp != nil; got != icmpEnabled {
				t.Fatalf("opened ICMP handle = %v, want %v", got, icmpEnabled)
			}
			opened := capture.handles()
			if err := lease.Close(nil); err != nil {
				t.Fatalf("real capture close = %v, want success", err)
			}
			if count := engine.ActiveLeases(); count != 0 {
				t.Fatalf("charged leases after the proven close = %d, want 0", count)
			}
			deadline := time.Now().Add(3 * time.Second)
			for _, handle := range opened {
				if handle == nil {
					continue
				}
				select {
				case <-handle.Done():
				case <-time.After(time.Until(deadline)):
					t.Fatal("native handle Done did not close after the real close")
				}
			}
		})
	}
}

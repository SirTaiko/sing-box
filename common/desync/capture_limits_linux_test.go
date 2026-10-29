//go:build linux

package desync

// Hermetic verification that the compiled D3 capture-policy limits become real
// nftables expressions inside the capture-owned chains of the persistent
// anchors (source common/nft.sh: nft_apply_nfqws_in_out). No kernel object is
// touched; the encoded expressions are decoded from the hermetic nft model.

import (
	"fmt"
	"net/netip"
	"testing"
)

// newLinuxCaptureLeaseForCapture builds a lease whose capture.linux block is
// the given extra JSON fields (with a leading comma), plus a fixed queue
// identity.
func newLinuxCaptureLeaseForCapture(t *testing.T, queue int, linuxBody string) (*Engine, *Lease) {
	t.Helper()
	content := fmt.Sprintf(`{"enabled":true,"capture":{"linux":{"qnum":%d%s}},"rules":[{"network":["tcp"],"port":[443],"methods":[]}]}`,
		queue, linuxBody)
	config, err := Compile(enabledOption(content), "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	engine, err := NewEngine(config, linuxBackend{})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	lease, err := engine.NewAttempt(Intent{
		Family:      FamilyIPv4,
		Transport:   TransportTCP,
		Source:      netip.MustParseAddrPort("192.0.2.1:40000"),
		Destination: netip.MustParseAddrPort("198.51.100.7:443"),
	})
	if err != nil {
		t.Fatalf("attempt: %v", err)
	}
	lease.SetLocalAddress(netip.MustParseAddrPort("192.0.2.1:40000"))
	t.Cleanup(func() {
		_ = engine.Close()
		releaseQnum(queue)
	})
	return engine, lease
}

// openLinuxCaptureForRules opens one capture over the hermetic anchor model and
// returns it with the seams.
func openLinuxCaptureForRules(t *testing.T, queue int, linuxBody string) (*linuxCapture, *linuxCaptureSeams) {
	t.Helper()
	data := newFakeNFQueueConn("queue", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	_, lease := newLinuxCaptureLeaseForCapture(t, queue, linuxBody)
	captureHandle, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("open capture: %v", err)
	}
	linux := captureHandle.(*linuxCapture)
	t.Cleanup(func() { _ = captureHandle.Close() })
	return linux, seams
}

// captureRoleRules returns the base/chain rules of one capture by role suffix.
func captureRoleRules(t *testing.T, seams *linuxCaptureSeams, capture *linuxCapture, role string) []*fakeNftRule {
	t.Helper()
	marker := ":" + capture.anchor.capture + ":" + role
	return fakeRulesWithUserdata(seams.anchors, byte(2), anchorTableName, marker)
}

func TestLinuxCaptureOutboundPacketLimitRule(t *testing.T) {
	linux, seams := openLinuxCaptureForRules(t, 15100, `,"packet_limits":{"tcp_out":2}`)
	rules := captureRoleRules(t, seams, linux, "entry-o")
	if len(rules) != 1 {
		t.Fatalf("entry-o rules = %d, want 1", len(rules))
	}
	limit, ok := fakeRuleHasCtPacketsBound(rules[0])
	if !ok || limit != 2 {
		t.Fatalf("outbound packet limit = %d/%v, want 2/true", limit, ok)
	}
	// The inbound direction is untouched (unlimited) and carries no counter.
	queueRules := captureRoleRules(t, seams, linux, "queue-i")
	if len(queueRules) != 1 {
		t.Fatalf("queue-i rules = %d, want 1", len(queueRules))
	}
	if _, ok := fakeRuleHasCtPacketsBound(queueRules[0]); ok {
		t.Fatal("inbound rule carries a packet counter without configuration")
	}
	if queues := fakeRuleQueues(queueRules[0]); len(queues) != 1 || queues[0] != linux.inQueue {
		t.Fatalf("inbound rule queues = %v, want %d", queues, linux.inQueue)
	}
}

func TestLinuxCaptureZeroOutboundLimitDisablesDirection(t *testing.T) {
	linux, seams := openLinuxCaptureForRules(t, 15101, `,"packet_limits":{"tcp_out":0}`)
	if rules := captureRoleRules(t, seams, linux, "entry-o"); len(rules) != 0 {
		t.Fatal("outbound dispatch rule installed although tcp_out is zero")
	}
	if rules := captureRoleRules(t, seams, linux, "queue-o"); len(rules) != 0 {
		t.Fatal("outbound queue rule installed although tcp_out is zero")
	}
	if rules := captureRoleRules(t, seams, linux, "queue-i"); len(rules) != 1 {
		t.Fatal("inbound queue rule removed by an outbound limit")
	}
	// Ownership/cleanup is unaffected: the capture still owns both queues and
	// closes them like any other capture.
	if err := linux.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestLinuxCaptureKeepaliveRemovesOnlyOutboundLimit(t *testing.T) {
	linux, seams := openLinuxCaptureForRules(t, 15102,
		`,"packet_limits":{"tcp_out":2},"tcp_keepalive_port_range":["443"]`)
	rules := captureRoleRules(t, seams, linux, "entry-o")
	if len(rules) != 1 {
		t.Fatal("outbound dispatch rule missing for a keepalive port")
	}
	if _, ok := fakeRuleHasCtPacketsBound(rules[0]); ok {
		t.Fatal("keepalive destination port kept the outgoing packet limit")
	}
	linux2, seams2 := openLinuxCaptureForRules(t, 15103,
		`,"packet_limits":{"tcp_out":2},"tcp_keepalive_port_range":["80"]`)
	rules2 := captureRoleRules(t, seams2, linux2, "entry-o")
	if len(rules2) != 1 {
		t.Fatal("outbound dispatch rule missing")
	}
	if limit, ok := fakeRuleHasCtPacketsBound(rules2[0]); !ok || limit != 2 {
		t.Fatalf("non-keepalive port lost the packet limit: %d/%v", limit, ok)
	}
}

func TestLinuxCaptureNoPacketLimitByDefault(t *testing.T) {
	linux, seams := openLinuxCaptureForRules(t, 15104, "")
	roles := []struct {
		name  string
		queue uint16
	}{
		{"queue-o", linux.queue},
		{"queue-i", linux.inQueue},
	}
	for _, role := range roles {
		rules := captureRoleRules(t, seams, linux, role.name)
		if len(rules) != 1 {
			t.Fatalf("%s rules = %d, want 1", role.name, len(rules))
		}
		if _, ok := fakeRuleHasCtPacketsBound(rules[0]); ok {
			t.Fatalf("%s carries a packet counter without configuration", role.name)
		}
		if queues := fakeRuleQueues(rules[0]); len(queues) != 1 || queues[0] != role.queue {
			t.Fatalf("%s queues = %v, want %d", role.name, queues, role.queue)
		}
	}
}

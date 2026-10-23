//go:build linux

package desync

// Hermetic verification that the compiled D3 capture-policy limits become real
// nftables expressions in the owned queue rules (source
// common/nft.sh: nft_apply_nfqws_in_out). No kernel object is touched.

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"

	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/expr"
)

// newLinuxCaptureLeaseForCapture builds a lease whose capture.linux block is
// the given extra JSON fields (with a leading comma), plus a fixed queue
// identity. The capture always has exactly one owned TCP flow.
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

// ruleWithQueue returns the owned rule that ends in the given NFQUEUE verdict.
func ruleWithQueue(rules []*nftables.Rule, queue uint16) *nftables.Rule {
	for _, rule := range rules {
		for _, expression := range rule.Exprs {
			if verdict, ok := expression.(*expr.Queue); ok && verdict.Num == queue {
				return rule
			}
		}
	}
	return nil
}

// packetLimitValue returns the inclusive conntrack packet bound carried by a
// rule, or 0/false when the rule has no packet counter test.
func packetLimitValue(t *testing.T, rule *nftables.Rule) (uint64, bool) {
	t.Helper()
	if rule == nil {
		t.Fatal("nil rule")
	}
	counter := false
	for _, expression := range rule.Exprs {
		switch value := expression.(type) {
		case *expr.Ct:
			if value.Key == expr.CtKeyPKTS {
				counter = true
			}
		case *expr.Cmp:
			if !counter {
				continue
			}
			if value.Op != expr.CmpOpLte || len(value.Data) != 8 {
				t.Fatalf("unexpected packet counter comparison: op %v len %d", value.Op, len(value.Data))
			}
			return binary.BigEndian.Uint64(value.Data), true
		}
	}
	return 0, false
}

func openLinuxCaptureForRules(t *testing.T, queue int, linuxBody string) (*linuxCapture, *fakeRuleWriter) {
	t.Helper()
	data := newFakeNFQueueConn("queue", 0, nil)
	rules := &fakeRuleWriter{}
	installLinuxCaptureSeams(t, data, rules)
	_, lease := newLinuxCaptureLeaseForCapture(t, queue, linuxBody)
	captureHandle, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("open capture: %v", err)
	}
	linux := captureHandle.(*linuxCapture)
	t.Cleanup(func() { _ = captureHandle.Close() })
	return linux, rules
}

func TestLinuxCaptureOutboundPacketLimitRule(t *testing.T) {
	linux, rules := openLinuxCaptureForRules(t, 15100, `,"packet_limits":{"tcp_out":2}`)
	outbound := ruleWithQueue(rules.rules, linux.queue)
	if outbound == nil {
		t.Fatal("outbound queue rule missing")
	}
	limit, ok := packetLimitValue(t, outbound)
	if !ok || limit != 2 {
		t.Fatalf("outbound packet limit = %d/%v, want 2/true", limit, ok)
	}
	// The inbound direction is untouched (unlimited) and carries no counter.
	inbound := ruleWithQueue(rules.rules, linux.inQueue)
	if inbound == nil {
		t.Fatal("inbound queue rule missing")
	}
	if _, ok := packetLimitValue(t, inbound); ok {
		t.Fatal("inbound rule carries a packet counter without configuration")
	}
}

func TestLinuxCaptureZeroOutboundLimitDisablesDirection(t *testing.T) {
	linux, rules := openLinuxCaptureForRules(t, 15101, `,"packet_limits":{"tcp_out":0}`)
	if outbound := ruleWithQueue(rules.rules, linux.queue); outbound != nil {
		t.Fatal("outbound queue rule installed although tcp_out is zero")
	}
	if inbound := ruleWithQueue(rules.rules, linux.inQueue); inbound == nil {
		t.Fatal("inbound queue rule removed by an outbound limit")
	}
	// Ownership/cleanup is unaffected: the capture still owns both queues and
	// closes them like any other capture.
	if err := linux.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestLinuxCaptureKeepaliveRemovesOnlyOutboundLimit(t *testing.T) {
	linux, rules := openLinuxCaptureForRules(t, 15102,
		`,"packet_limits":{"tcp_out":2},"tcp_keepalive_port_range":["443"]`)
	outbound := ruleWithQueue(rules.rules, linux.queue)
	if outbound == nil {
		t.Fatal("outbound queue rule missing for a keepalive port")
	}
	if _, ok := packetLimitValue(t, outbound); ok {
		t.Fatal("keepalive destination port kept the outgoing packet limit")
	}
	// A different destination port keeps the bound: the same compiled config
	// with port 443 outside the keepalive range.
	linux2, rules2 := openLinuxCaptureForRules(t, 15103,
		`,"packet_limits":{"tcp_out":2},"tcp_keepalive_port_range":["80"]`)
	outbound2 := ruleWithQueue(rules2.rules, linux2.queue)
	if limit, ok := packetLimitValue(t, outbound2); !ok || limit != 2 {
		t.Fatalf("non-keepalive port lost the packet limit: %d/%v", limit, ok)
	}
}

func TestLinuxCaptureNoPacketLimitByDefault(t *testing.T) {
	linux, rules := openLinuxCaptureForRules(t, 15104, "")
	for _, queue := range []uint16{linux.queue, linux.inQueue} {
		rule := ruleWithQueue(rules.rules, queue)
		if rule == nil {
			t.Fatalf("queue %d rule missing", queue)
		}
		if _, ok := packetLimitValue(t, rule); ok {
			t.Fatalf("queue %d carries a packet counter without configuration", queue)
		}
	}
}

package direct

import (
	"context"
	"runtime"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
)

// SEC371-S1 permanent regression: an owned packet UDP endpoint is published as a
// tuple, so it must be exclusive. The public reuse_addr dialer option makes the
// listener socket shareable and is therefore refused for an enabled packet
// configuration, while the disabled/absent and stream-only state paths keep it.
//
// This drives the actual NewOutbound constructor. It creates no socket, capture
// or lease: the refusal is expected before any desync state exists, which is
// what the missing-payload ordering pair below proves.

// sec371PacketRule is one enabled UDP packet rule. The payload is supplied by
// the caller so a case can name a file that cannot be resolved.
func sec371PacketRule(payload option.DirectDesyncPayload) option.DirectDesyncRule {
	return option.DirectDesyncRule{
		Network: []string{"udp"},
		Methods: []string{"fake"},
		Fake: &option.DirectDesyncFakeOptions{
			Payloads: []option.DirectDesyncPayload{payload},
		},
	}
}

func sec371HexRule() option.DirectDesyncRule {
	return sec371PacketRule(option.DirectDesyncPayload{Protocol: "unknown", Hex: "00"})
}

func sec371MissingPayloadRule() option.DirectDesyncRule {
	return sec371PacketRule(option.DirectDesyncPayload{Protocol: "unknown", File: "/nonexistent/sec371-payload.bin"})
}

func sec371Context(t *testing.T) context.Context {
	t.Helper()
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), retainedReportNetwork{})
	return service.ContextWith[adapter.DNSTransportManager](ctx, retainedReportDNS{})
}

// sec371Construct runs the real constructor and releases the engine it returns,
// so a passing control case leaves no owner behind for the test process.
func sec371Construct(t *testing.T, options option.DirectOutboundOptions) (adapter.Outbound, error) {
	t.Helper()
	made, err := NewOutbound(sec371Context(t), nil, logger.NOP(), "sec371-reuse", options)
	if made != nil {
		outbound, ok := made.(*Outbound)
		if !ok {
			t.Fatalf("unexpected outbound type %T", made)
		}
		if outbound.desync != nil {
			engine := outbound.desync
			t.Cleanup(func() { _ = engine.Close() })
		}
	}
	return made, err
}

func TestSec371PacketReuseAdmission(t *testing.T) {
	t.Run("packet-reuse-refused", func(t *testing.T) {
		options := option.DirectOutboundOptions{
			Desync: &option.DirectDesyncOptions{Rules: []option.DirectDesyncRule{sec371HexRule()}},
		}
		options.ReuseAddr = true
		made, err := sec371Construct(t, options)
		if err == nil {
			t.Fatal("SEC371-S1: packet-enabled desync accepts reuse_addr=true although capture has only local-endpoint identity")
		}
		if made != nil {
			t.Fatalf("refused configuration still returned an outbound %T", made)
		}
		for _, want := range []string{"reuse_addr", "packet desync", "exclusive"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("conflict error is not actionable, missing %q: %v", want, err)
			}
		}
		// A refused configuration owns nothing, so neither the ordinary
		// ListenPacket path nor the serial-interface path can be reached and no
		// attempt, capture or admission charge can exist for it.
		if _, again := sec371Construct(t, options); again == nil || !strings.Contains(again.Error(), "reuse_addr") {
			t.Fatalf("repeated refusal is not deterministic: %v", again)
		}
	})

	// The refusal must precede every desync allocation. The same packet rule
	// names a payload file that cannot be resolved, so a run that reached the
	// compile/payload stage would report that file error instead. Both halves
	// are asserted, which makes the ordering a behavioural observation rather
	// than a source-order claim, and proves no capture or charge was created.
	t.Run("packet-reuse-refused-before-payload-resolution", func(t *testing.T) {
		refused := option.DirectOutboundOptions{
			Desync: &option.DirectDesyncOptions{Rules: []option.DirectDesyncRule{sec371MissingPayloadRule()}},
		}
		refused.ReuseAddr = true
		made, err := sec371Construct(t, refused)
		if err == nil || made != nil {
			t.Fatalf("packet+reuse accepted with an unresolvable payload: outbound=%T err=%v", made, err)
		}
		if !strings.Contains(err.Error(), "reuse_addr") {
			t.Fatalf("refusal did not come from the reuse policy: %v", err)
		}
		if strings.Contains(err.Error(), "payload") || strings.Contains(err.Error(), "no such file") {
			t.Fatalf("payload resolution ran before the conflict refusal: %v", err)
		}

		// Control: the identical rules without reuse_addr reach payload
		// resolution and fail there, which is what the refusal above preempted.
		control := option.DirectOutboundOptions{
			Desync: &option.DirectDesyncOptions{Rules: []option.DirectDesyncRule{sec371MissingPayloadRule()}},
		}
		control.ReuseAddr = false
		made, err = sec371Construct(t, control)
		if err == nil {
			t.Fatalf("unresolvable payload unexpectedly accepted: outbound=%T", made)
		}
		if strings.Contains(err.Error(), "reuse_addr") {
			t.Fatalf("control failed on the wrong policy: %v", err)
		}
	})

	t.Run("packet-exclusive-accepted", func(t *testing.T) {
		options := option.DirectOutboundOptions{
			Desync: &option.DirectDesyncOptions{Rules: []option.DirectDesyncRule{sec371HexRule()}},
		}
		made, err := sec371Construct(t, options)
		if err != nil {
			t.Fatalf("ordinary packet-exclusive configuration refused: %v", err)
		}
		outbound, ok := made.(*Outbound)
		if !ok || outbound.desync == nil {
			t.Fatalf("packet engine missing on accepted configuration: %T", made)
		}
		if !outbound.desync.PacketEnabled() {
			t.Fatal("accepted packet configuration is not packet-enabled")
		}
		// The constructor admits no attempt by itself: the refusal above can
		// therefore not have been replaced by a leaked charge.
		if leases := outbound.desync.ActiveLeases(); leases != 0 {
			t.Fatalf("constructor charged %d leases", leases)
		}
	})

	t.Run("state-only-reuse-accepted", func(t *testing.T) {
		options := option.DirectOutboundOptions{
			Desync: &option.DirectDesyncOptions{StreamRules: []option.DirectDesyncStreamRule{testStreamRule(443)}},
		}
		options.ReuseAddr = true
		made, err := sec371Construct(t, options)
		if err != nil {
			t.Fatalf("stream-only state configuration refused its valid reuse_addr: %v", err)
		}
		outbound, ok := made.(*Outbound)
		if !ok || outbound.desync == nil {
			t.Fatalf("state engine missing: %T", made)
		}
		if outbound.desync.PacketEnabled() {
			t.Fatal("stream-only configuration owns a packet backend")
		}
	})

	t.Run("disabled-reuse-accepted", func(t *testing.T) {
		options := option.DirectOutboundOptions{}
		options.ReuseAddr = true
		if _, err := sec371Construct(t, options); err != nil {
			t.Fatalf("absent desync refused its valid reuse_addr: %v", err)
		}
	})

	// A disabled packet rule cannot enable a packet engine, so it does not
	// carry the exclusivity requirement. The enabled stream rule keeps the
	// desync block valid and exercises the actual PacketEnabled decision.
	t.Run("disabled-packet-rule-reuse-accepted", func(t *testing.T) {
		disabledRule := sec371HexRule()
		disabledRule.Disabled = true
		options := option.DirectOutboundOptions{
			Desync: &option.DirectDesyncOptions{
				Rules:       []option.DirectDesyncRule{disabledRule},
				StreamRules: []option.DirectDesyncStreamRule{testStreamRule(443)},
			},
		}
		options.ReuseAddr = true
		made, err := sec371Construct(t, options)
		if err != nil {
			t.Fatalf("disabled packet rule refused its valid reuse_addr: %v", err)
		}
		outbound, ok := made.(*Outbound)
		if !ok || outbound.desync == nil {
			t.Fatalf("state engine missing: %T", made)
		}
		if outbound.desync.PacketEnabled() {
			t.Fatal("disabled packet rule produced a packet backend")
		}
	})
}

// QA375-D1 permanent regression: an explicit desync.enabled=false compiles no
// engine at all (compileDirectDesync returns before any rule, payload or list
// state is touched). The pre-allocation packet-ownership policy must derive its
// eligibility from that same state; otherwise a documented disabled
// configuration is refused reuse_addr/tcp_multipath/bind_address_no_port for
// packet ownership it can never acquire. The enabled rows below keep the
// refusal and its allocation ordering actionable, so this matrix also fails if
// the pre-check is merely deleted.
//
// Constructor-only like the SEC371 matrix above: no socket, capture, payload
// read or lease is involved, and every accepted engine is released.
func qa375Bool(value bool) *bool {
	return &value
}

func qa375DisabledPacketOptions() *option.DirectDesyncOptions {
	return &option.DirectDesyncOptions{
		Enabled: qa375Bool(false),
		Rules:   []option.DirectDesyncRule{sec371HexRule()},
	}
}

func qa375AssertNoDesyncState(t *testing.T, made adapter.Outbound) {
	t.Helper()
	outbound, ok := made.(*Outbound)
	if !ok {
		t.Fatalf("unexpected outbound type %T", made)
	}
	if outbound.desync != nil || outbound.stream != nil {
		t.Fatalf("disabled desync allocated state: engine=%v stream=%v", outbound.desync != nil, outbound.stream != nil)
	}
}

func TestQA375DisabledDesyncKeepsPacketDialerOptions(t *testing.T) {
	t.Run("explicit-false-reuse-accepted", func(t *testing.T) {
		options := option.DirectOutboundOptions{Desync: qa375DisabledPacketOptions()}
		options.ReuseAddr = true
		made, err := sec371Construct(t, options)
		if err != nil {
			t.Fatalf("disabled desync with an enabled packet rule refused reuse_addr although it owns no packet socket: %v", err)
		}
		qa375AssertNoDesyncState(t, made)
	})

	t.Run("explicit-false-tcp-multipath-accepted", func(t *testing.T) {
		options := option.DirectOutboundOptions{Desync: qa375DisabledPacketOptions()}
		options.TCPMultiPath = true
		made, err := sec371Construct(t, options)
		if err != nil {
			t.Fatalf("disabled desync with an enabled packet rule refused tcp_multipath: %v", err)
		}
		qa375AssertNoDesyncState(t, made)
	})

	// bind_address_no_port is a Linux dialer option. On Linux the disabled
	// object must accept it exactly like an absent desync object; on another
	// platform it must not gain or lose applicability relative to that same
	// absent baseline, because the option itself is not a desync policy.
	t.Run("explicit-false-bind-address-no-port-platform-parity", func(t *testing.T) {
		disabled := option.DirectOutboundOptions{Desync: qa375DisabledPacketOptions()}
		disabled.BindAddressNoPort = true
		absent := option.DirectOutboundOptions{}
		absent.BindAddressNoPort = true
		disabledOutbound, disabledErr := sec371Construct(t, disabled)
		_, absentErr := sec371Construct(t, absent)
		if (disabledErr == nil) != (absentErr == nil) {
			t.Fatalf("disabled desync changed bind_address_no_port applicability: disabled=%v absent=%v", disabledErr, absentErr)
		}
		if runtime.GOOS == "linux" {
			if disabledErr != nil {
				t.Fatalf("linux disabled desync refused bind_address_no_port: %v", disabledErr)
			}
			qa375AssertNoDesyncState(t, disabledOutbound)
		}
	})

	// The strongest no-allocation observation: the packet rule names a payload
	// file that cannot be resolved. A predicate that ignored enabled would
	// refuse on reuse_addr, and a compile that ran anyway would fail on the
	// file; only "no packet path at all" accepts this request.
	t.Run("explicit-false-unresolvable-payload-accepted-without-read", func(t *testing.T) {
		options := option.DirectOutboundOptions{Desync: &option.DirectDesyncOptions{
			Enabled: qa375Bool(false),
			Rules:   []option.DirectDesyncRule{sec371MissingPayloadRule()},
		}}
		options.ReuseAddr = true
		made, err := sec371Construct(t, options)
		if err != nil {
			t.Fatalf("disabled desync resolved or refused an unreadable payload: %v", err)
		}
		qa375AssertNoDesyncState(t, made)
	})

	t.Run("explicit-true-packet-reuse-still-refused", func(t *testing.T) {
		options := option.DirectOutboundOptions{Desync: &option.DirectDesyncOptions{
			Enabled: qa375Bool(true),
			Rules:   []option.DirectDesyncRule{sec371HexRule()},
		}}
		options.ReuseAddr = true
		made, err := sec371Construct(t, options)
		if err == nil || made != nil {
			t.Fatalf("explicitly enabled packet desync accepted reuse_addr: outbound=%T err=%v", made, err)
		}
		for _, want := range []string{"reuse_addr", "packet desync", "exclusive"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("conflict error is not actionable, missing %q: %v", want, err)
			}
		}
	})

	t.Run("default-enabled-packet-reuse-still-refused", func(t *testing.T) {
		options := option.DirectOutboundOptions{Desync: &option.DirectDesyncOptions{
			Rules: []option.DirectDesyncRule{sec371HexRule()},
		}}
		options.ReuseAddr = true
		made, err := sec371Construct(t, options)
		if err == nil || made != nil || !strings.Contains(err.Error(), "reuse_addr") {
			t.Fatalf("default-enabled packet desync accepted reuse_addr: outbound=%T err=%v", made, err)
		}
	})

	// The enabled refusal must still precede payload resolution: the
	// conflicting request fails on the conflict, the identical request without
	// reuse_addr reaches the unresolvable payload. Same authority as before the
	// eligibility correction, so enabled security policy is not weakened.
	t.Run("explicit-true-conflict-precedes-payload-read", func(t *testing.T) {
		refused := option.DirectOutboundOptions{Desync: &option.DirectDesyncOptions{
			Enabled: qa375Bool(true),
			Rules:   []option.DirectDesyncRule{sec371MissingPayloadRule()},
		}}
		refused.ReuseAddr = true
		made, err := sec371Construct(t, refused)
		if err == nil || made != nil {
			t.Fatalf("invalid payload + reuse accepted: outbound=%T err=%v", made, err)
		}
		if !strings.Contains(err.Error(), "reuse_addr") {
			t.Fatalf("refusal did not come from the reuse policy: %v", err)
		}
		if strings.Contains(err.Error(), "sec371-payload.bin") {
			t.Fatalf("payload resolution ran before the conflict refusal: %v", err)
		}

		control := option.DirectOutboundOptions{Desync: &option.DirectDesyncOptions{
			Enabled: qa375Bool(true),
			Rules:   []option.DirectDesyncRule{sec371MissingPayloadRule()},
		}}
		made, err = sec371Construct(t, control)
		if err == nil || made != nil {
			t.Fatalf("unresolvable payload accepted without reuse: outbound=%T err=%v", made, err)
		}
		if strings.Contains(err.Error(), "reuse_addr") {
			t.Fatalf("control failed on the wrong policy: %v", err)
		}
		if !strings.Contains(err.Error(), "sec371-payload.bin") {
			t.Fatalf("control did not reach payload resolution: %v", err)
		}
	})

	t.Run("disabled-rules-and-stream-only-controls-retained", func(t *testing.T) {
		disabledRule := sec371HexRule()
		disabledRule.Disabled = true
		options := option.DirectOutboundOptions{Desync: &option.DirectDesyncOptions{
			Rules:       []option.DirectDesyncRule{disabledRule},
			StreamRules: []option.DirectDesyncStreamRule{testStreamRule(443)},
		}}
		options.ReuseAddr = true
		made, err := sec371Construct(t, options)
		if err != nil {
			t.Fatalf("all-packet-rules-disabled configuration refused reuse_addr: %v", err)
		}
		outbound, ok := made.(*Outbound)
		if !ok || outbound.desync == nil || outbound.desync.PacketEnabled() {
			t.Fatalf("all-disabled packet rules produced a packet backend: %T", made)
		}

		streamOnly := option.DirectOutboundOptions{Desync: &option.DirectDesyncOptions{
			StreamRules: []option.DirectDesyncStreamRule{testStreamRule(443)},
		}}
		streamOnly.ReuseAddr = true
		made, err = sec371Construct(t, streamOnly)
		if err != nil {
			t.Fatalf("stream-only configuration refused reuse_addr: %v", err)
		}
		outbound, ok = made.(*Outbound)
		if !ok || outbound.desync == nil || outbound.desync.PacketEnabled() {
			t.Fatalf("stream-only configuration produced a packet backend: %T", made)
		}
	})
}

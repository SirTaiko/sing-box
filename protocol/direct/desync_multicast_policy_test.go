package direct

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/common/desync"
	"github.com/sagernet/sing-box/option"
)

// SEC381-S1 permanent regression: a multicast local bind address makes the
// owned packet endpoint shareable without the public reuse_addr flag. The
// standard library's UDP multicast listen path enables address sharing and
// binds the wildcard address, so an enabled packet configuration that accepted
// such a bind would capture an endpoint some other socket can co-own, while
// tuple capture cannot tell the two apart. Admission therefore refuses a
// multicast inet4_bind_address/inet6_bind_address before any desync state
// exists, and the actual compiled engine's PacketEnabled state refuses the same
// input again on the post-compile path.
//
// Everything here is constructor-only and hermetic: no socket, capture, native
// backend, payload read or lease is created. The accepted rows release every
// engine they obtain. The shared constructor helpers live in
// desync_reuse_policy_test.go.

// sec381PacketRules is one enabled UDP packet rule in the documented JSON form.
const sec381PacketRules = `"rules":[{"network":["udp"],"methods":["fake"],"fake":{"payloads":[{"protocol":"unknown","hex":"00"}]}}]`

// sec381MissingPayloadRules is the same rule with a payload file that cannot be
// resolved, so a run that reached payload compilation reports that file instead
// of the policy conflict.
const sec381MissingPayloadRules = `"rules":[{"network":["udp"],"methods":["fake"],"fake":{"payloads":[{"protocol":"unknown","file":"/nonexistent/sec381-bind-payload.bin"}]}}]`

// sec381DecodeOptions decodes the actual configuration surface of a direct
// outbound, so the matrix cannot pass on hand-built structs that no document
// configuration can produce.
func sec381DecodeOptions(t *testing.T, text string) option.DirectOutboundOptions {
	t.Helper()
	var options option.DirectOutboundOptions
	if err := options.UnmarshalJSONContext(context.Background(), []byte(text)); err != nil {
		t.Fatalf("decode %s: %v", text, err)
	}
	return options
}

// sec381AssertMulticastConflict asserts that an enabled packet configuration
// with a multicast local bind was refused by the named-option policy instead of
// producing an outbound.
func sec381AssertMulticastConflict(t *testing.T, options option.DirectOutboundOptions, field string) {
	t.Helper()
	made, err := sec371Construct(t, options)
	if err == nil {
		t.Fatalf("SEC381-S1: enabled packet desync accepted multicast %s although the endpoint becomes implicitly shareable", field)
	}
	if made != nil {
		t.Fatalf("refused multicast configuration still returned an outbound %T", made)
	}
	for _, want := range []string{field, "packet desync", "multicast", "exclusive", "unicast"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("conflict error is not actionable, missing %q: %v", want, err)
		}
	}
	// A refused configuration owns nothing, so the refusal is repeatable and
	// no attempt, capture or admission charge can exist for it.
	againMade, againErr := sec371Construct(t, options)
	if againMade != nil || againErr == nil || !strings.Contains(againErr.Error(), field) {
		t.Fatalf("repeated multicast refusal is not deterministic: outbound=%T err=%v", againMade, againErr)
	}
}

func TestSec381PacketMulticastBindAdmission(t *testing.T) {
	refused := []struct {
		name    string
		field   string
		address string
	}{
		{name: "ipv4-reuse-omitted", field: "inet4_bind_address", address: "224.0.0.1"},
		{name: "ipv4-reuse-explicit-false", field: "inet4_bind_address", address: "224.0.0.1"},
		{name: "ipv6-reuse-omitted", field: "inet6_bind_address", address: "ff02::1"},
		{name: "ipv6-reuse-explicit-false", field: "inet6_bind_address", address: "ff02::1"},
		// A 4-in-6 spelling is still a multicast IPv4 bind once unmapped, so
		// the classification must be semantic rather than textual.
		{name: "ipv4-mapped-multicast", field: "inet4_bind_address", address: "::ffff:224.0.0.1"},
	}
	for _, testCase := range refused {
		t.Run(testCase.name, func(t *testing.T) {
			reuse := ""
			if strings.HasSuffix(testCase.name, "explicit-false") {
				reuse = `"reuse_addr":false,`
			}
			options := sec381DecodeOptions(t, `{`+reuse+`"`+testCase.field+`":"`+testCase.address+`","desync":{`+sec381PacketRules+`}}`)
			sec381AssertMulticastConflict(t, options, testCase.field)
		})
	}

	// The refusal must precede every desync allocation. Both families carry the
	// same unresolvable payload, so a run that reached the compile/payload
	// stage would report that file instead of the policy conflict.
	for _, testCase := range []struct{ name, field, address, unicast string }{
		{name: "ipv4", field: "inet4_bind_address", address: "224.0.0.1", unicast: "192.0.2.1"},
		{name: "ipv6", field: "inet6_bind_address", address: "ff02::1", unicast: "2001:db8::1"},
	} {
		t.Run("conflict-precedes-payload-read/"+testCase.name, func(t *testing.T) {
			options := sec381DecodeOptions(t, `{"`+testCase.field+`":"`+testCase.address+`","desync":{`+sec381MissingPayloadRules+`}}`)
			made, err := sec371Construct(t, options)
			if err == nil || made != nil {
				t.Fatalf("multicast + unresolvable payload accepted: outbound=%T err=%v", made, err)
			}
			if !strings.Contains(err.Error(), testCase.field) {
				t.Fatalf("refusal did not come from the multicast bind policy: %v", err)
			}
			if strings.Contains(err.Error(), "sec381-bind-payload.bin") {
				t.Fatalf("payload resolution ran before the conflict refusal: %v", err)
			}

			// Control: the identical rule with a unicast bind reaches payload
			// resolution and fails there, which is exactly what the refusal
			// above preempted.
			control := sec381DecodeOptions(t, `{"`+testCase.field+`":"`+testCase.unicast+`","desync":{`+sec381MissingPayloadRules+`}}`)
			made, err = sec371Construct(t, control)
			if err == nil || made != nil {
				t.Fatalf("unresolvable payload accepted with a unicast bind: outbound=%T err=%v", made, err)
			}
			if strings.Contains(err.Error(), "conflicts with enabled packet desync") {
				t.Fatalf("control failed on the packet ownership policy: %v", err)
			}
			if !strings.Contains(err.Error(), "sec381-bind-payload.bin") {
				t.Fatalf("control did not reach payload resolution: %v", err)
			}
		})
	}

	// Ordinary multicast listeners keep their existing behaviour: the guard is
	// a packet-ownership admission rule, not a global restriction on multicast.
	t.Run("ordinary-multicast-accepted", func(t *testing.T) {
		for _, field := range []struct{ name, address string }{
			{name: "inet4_bind_address", address: "224.0.0.1"},
			{name: "inet6_bind_address", address: "ff02::1"},
		} {
			options := sec381DecodeOptions(t, `{"`+field.name+`":"`+field.address+`"}`)
			made, err := sec371Construct(t, options)
			if err != nil {
				t.Fatalf("ordinary multicast listener refused without desync: %v", err)
			}
			qa375AssertNoDesyncState(t, made)
		}
	})

	// Unicast binds remain accepted, so the guard does not narrow the ordinary
	// packet configuration.
	t.Run("unicast-accepted", func(t *testing.T) {
		for _, testCase := range []struct{ name, field, address string }{
			{name: "ipv4", field: "inet4_bind_address", address: "192.0.2.1"},
			{name: "ipv6", field: "inet6_bind_address", address: "2001:db8::1"},
		} {
			options := sec381DecodeOptions(t, `{"`+testCase.field+`":"`+testCase.address+`","desync":{`+sec381PacketRules+`}}`)
			made, err := sec371Construct(t, options)
			if err != nil {
				t.Fatalf("unicast packet configuration refused: %v", err)
			}
			outbound, ok := made.(*Outbound)
			if !ok || outbound.desync == nil || !outbound.desync.PacketEnabled() {
				t.Fatalf("unicast configuration did not produce a packet engine: %T", made)
			}
			if leases := outbound.desync.ActiveLeases(); leases != 0 {
				t.Fatalf("constructor charged %d leases", leases)
			}
		}
	})

	// The explicit sharing policy keeps its own error and is not shadowed by
	// the multicast branch.
	t.Run("explicit-reuse-still-named", func(t *testing.T) {
		options := sec381DecodeOptions(t, `{"inet4_bind_address":"192.0.2.1","reuse_addr":true,"desync":{`+sec381PacketRules+`}}`)
		made, err := sec371Construct(t, options)
		if err == nil || made != nil || !strings.Contains(err.Error(), "reuse_addr") {
			t.Fatalf("packet desync accepted reuse_addr on a unicast bind: outbound=%T err=%v", made, err)
		}
	})

	// Disabled states own no packet endpoint, so they keep the ordinary
	// multicast listener untouched. The unresolvable payload proves no desync
	// read happened on the disabled path.
	t.Run("disabled-multicast-accepted-without-read", func(t *testing.T) {
		options := sec381DecodeOptions(t, `{"inet4_bind_address":"224.0.0.1","reuse_addr":true,"desync":{"enabled":false,`+sec381MissingPayloadRules+`}}`)
		made, err := sec371Construct(t, options)
		if err != nil {
			t.Fatalf("explicitly disabled desync refused its ordinary multicast bind: %v", err)
		}
		qa375AssertNoDesyncState(t, made)
	})

	// Stream-only and all-packet-rules-disabled states have no packet engine, so
	// the multicast bind stays valid for them exactly as before.
	t.Run("state-only-multicast-accepted", func(t *testing.T) {
		streamRule := `"stream_rules":[{"network":["tcp"],"port":[443],"protocol":["tls"],"methods":["tls_record"],"tls_record":{"pos":"host+2"}}]`
		for _, testCase := range []struct{ name, desync string }{
			{name: "stream-only", desync: `{` + streamRule + `}`},
			{name: "all-packet-rules-disabled", desync: `{"rules":[{"network":["udp"],"methods":["fake"],"disabled":true,"fake":{"payloads":[{"protocol":"unknown","hex":"00"}]}}],` + streamRule + `}`},
		} {
			options := sec381DecodeOptions(t, `{"inet6_bind_address":"ff02::1","reuse_addr":true,"desync":`+testCase.desync+`}`)
			made, err := sec371Construct(t, options)
			if err != nil {
				t.Fatalf("%s configuration refused its ordinary multicast bind: %v", testCase.name, err)
			}
			outbound, ok := made.(*Outbound)
			if !ok || outbound.desync == nil {
				t.Fatalf("%s configuration lost its state engine: %T", testCase.name, made)
			}
			if outbound.desync.PacketEnabled() {
				t.Fatalf("%s configuration owns a packet backend", testCase.name)
			}
		}
	})
}

// TestSec381PacketMulticastPostCompileDefense exercises the second application
// of the same policy directly. It is the boundary NewOutbound calls after
// compileDirectDesync, so the guard does not depend on the pre-allocation
// request check having run: an actual compiled packet engine refuses the same
// decoded multicast dialer input on its own, while a stream-only configuration
// keeps it.
func TestSec381PacketMulticastPostCompileDefense(t *testing.T) {
	engine, err := desync.NewEngine(testPacketConfig(t), &countingBackend{})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	if !engine.PacketEnabled() {
		t.Fatal("fixture engine is not packet-enabled")
	}
	streamConfig, err := desync.CompileStream([]option.DirectDesyncStreamRule{testStreamRule(443)}, "")
	if err != nil {
		t.Fatal(err)
	}

	for _, testCase := range []struct{ name, field, address string }{
		{name: "ipv4", field: "inet4_bind_address", address: "224.0.0.1"},
		{name: "ipv6", field: "inet6_bind_address", address: "ff02::1"},
	} {
		t.Run("refused/"+testCase.name, func(t *testing.T) {
			dialerOptions := sec381DecodeOptions(t, `{"`+testCase.field+`":"`+testCase.address+`"}`).DialerOptions
			conflictErr := checkDesyncDialerConflicts(dialerOptions, engine, nil)
			if conflictErr == nil || !strings.Contains(conflictErr.Error(), testCase.field) {
				t.Fatalf("compiled packet engine accepted multicast %s: %v", testCase.field, conflictErr)
			}
		})
	}

	t.Run("accepted/unicast", func(t *testing.T) {
		dialerOptions := sec381DecodeOptions(t, `{"inet4_bind_address":"192.0.2.1"}`).DialerOptions
		if err := checkDesyncDialerConflicts(dialerOptions, engine, nil); err != nil {
			t.Fatalf("compiled packet engine refused a unicast bind: %v", err)
		}
	})

	t.Run("accepted/stream-only", func(t *testing.T) {
		dialerOptions := sec381DecodeOptions(t, `{"inet6_bind_address":"ff02::1"}`).DialerOptions
		if err := checkDesyncDialerConflicts(dialerOptions, nil, streamConfig); err != nil {
			t.Fatalf("stream-only configuration refused its ordinary multicast bind: %v", err)
		}
	})

	t.Run("accepted/no-desync", func(t *testing.T) {
		dialerOptions := sec381DecodeOptions(t, `{"inet4_bind_address":"224.0.0.1"}`).DialerOptions
		if err := checkDesyncDialerConflicts(dialerOptions, nil, nil); err != nil {
			t.Fatalf("absent desync refused an ordinary multicast bind: %v", err)
		}
	})
}

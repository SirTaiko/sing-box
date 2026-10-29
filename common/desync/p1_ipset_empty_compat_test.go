package desync

// P1-IPSET-EMPTY-COMPAT regressions: pinned zapret v72.9 nfq/ipset.c:221-232
// evaluates exclusions first and then says
//
//	// old behavior compat: all include lists are empty means check passes
//
// so a positive IP include collection whose lists are all empty imposes no
// positive-IP restriction. The candidate previously compiled a configured but
// empty ip_cidr/ip_cidr_file source into an always-rejecting restriction, which
// made the converted profiles' catch-all rules unreachable (QA500 captured-IP
// replay selected no rule and injected no fake while the native reference
// selected profile6 and injected 11). These cases pin the pinned semantics on
// the existing option/compile/match/reload/bundle layers and on the captured
// QUIC flight; no mode, schema field or new subsystem is involved.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func p1WriteList(t *testing.T, directory, name, content string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func p1Hex(text string) string {
	return hex.EncodeToString([]byte(text))
}

// p1CompileRule compiles one UDP/443 rule with the supplied list fields. The
// dup stage keeps the rule complete without a fake payload.
func p1CompileRule(t *testing.T, baseDir, fields string) *Rule {
	t.Helper()
	config, err := Compile(enabledOption(`{"enabled":true,"rules":[
		{"network":["udp"],"port":[443],"dup":{"count":1}`+fields+`}]}`), baseDir)
	if err != nil {
		t.Fatalf("compile %s: %v", fields, err)
	}
	if len(config.Rules) != 1 {
		t.Fatalf("compiled rules = %d, want 1", len(config.Rules))
	}
	return config.Rules[0]
}

func TestP1PositiveIPIncludeAggregateSemantics(t *testing.T) {
	directory := t.TempDir()
	empty := p1WriteList(t, directory, "ipset-all.txt", "")
	comments := p1WriteList(t, directory, "ipset-comments.txt",
		"# provider placeholders, no entries\r\n\r\n   \r\n# trailing comment\r\n")
	v4 := p1WriteList(t, directory, "ipset-v4.txt", "203.0.113.0/24\r\n")
	v6 := p1WriteList(t, directory, "ipset-v6.txt", "2001:db8::/32\r\n")
	other := p1WriteList(t, directory, "ipset-other.txt", "192.0.2.0/24\r\n")

	facts := func(family Family, destination string) MatchFacts {
		return o309Facts(family, TransportUDP, destination, 443, ProtocolQUIC)
	}
	v4Inside := facts(FamilyIPv4, "203.0.113.9")
	v4Outside := facts(FamilyIPv4, "198.51.100.7")
	v6Inside := facts(FamilyIPv6, "2001:db8::7")
	v4Other := facts(FamilyIPv4, "192.0.2.9")

	// An omitted positive source is unrestricted (unchanged behaviour).
	if rule := p1CompileRule(t, directory, ""); !rule.Matches(v4Inside) ||
		!rule.Matches(v4Outside) || !rule.Matches(v6Inside) {
		t.Fatal("an omitted positive IP source must stay unrestricted")
	}
	// A really empty and a comment-only include impose no positive restriction,
	// for both families.
	for name, path := range map[string]string{"empty": empty, "comment-only": comments} {
		rule := p1CompileRule(t, directory, `,"ip_cidr_file":[`+jsonPath(t, path)+`]`)
		if !rule.Matches(v4Inside) || !rule.Matches(v4Outside) || !rule.Matches(v6Inside) {
			t.Fatalf("%s positive include must impose no positive-IP restriction", name)
		}
	}
	// A nonempty union keeps the OR membership test and the family behaviour.
	v4Rule := p1CompileRule(t, directory, `,"ip_cidr_file":[`+jsonPath(t, v4)+`]`)
	if !v4Rule.Matches(v4Inside) {
		t.Fatal("a nonempty positive include must select its own address")
	}
	if v4Rule.Matches(v4Outside) {
		t.Fatal("a nonempty positive include must reject other addresses")
	}
	if v4Rule.Matches(v6Inside) {
		t.Fatal("an IPv4-only positive include must reject an IPv6 destination")
	}
	// Empty and nonempty includes are one ORed aggregate: the nonempty member
	// supplies the restriction, the empty member adds nothing.
	combined := p1CompileRule(t, directory,
		`,"ip_cidr_file":[`+jsonPath(t, empty)+`,`+jsonPath(t, other)+`]`)
	if !combined.Matches(v4Other) {
		t.Fatal("the nonempty member of a mixed include must still match")
	}
	if combined.Matches(v4Inside) || combined.Matches(v6Inside) {
		t.Fatal("the nonempty member of a mixed include must still restrict other destinations")
	}
	// Mixed IPv4/IPv6 includes cover both families.
	mixed := p1CompileRule(t, directory,
		`,"ip_cidr_file":[`+jsonPath(t, v4)+`,`+jsonPath(t, v6)+`]`)
	if !mixed.Matches(v4Inside) || !mixed.Matches(v6Inside) {
		t.Fatal("mixed IPv4/IPv6 includes must match both families")
	}
	if mixed.Matches(v4Other) {
		t.Fatal("mixed IPv4/IPv6 includes must reject an address outside both")
	}
	// Inline entries and files share the same aggregate.
	inlinePlusEmpty := p1CompileRule(t, directory,
		`,"ip_cidr":["203.0.113.0/24"],"ip_cidr_file":[`+jsonPath(t, empty)+`]`)
	if !inlinePlusEmpty.Matches(v4Inside) || inlinePlusEmpty.Matches(v4Outside) {
		t.Fatal("inline prefixes must keep restricting alongside an empty file")
	}
}

func TestP1EmptyPositiveIPIncludeKeepsExclusionsLoadBearing(t *testing.T) {
	directory := t.TempDir()
	empty := p1WriteList(t, directory, "ipset-all.txt", "")
	excludeFile := p1WriteList(t, directory, "ipset-exclude.txt", "142.251.153.0/24\r\n")
	excluded := o309Facts(FamilyIPv4, TransportUDP, "142.251.153.4", 443, ProtocolQUIC)
	allowed := o309Facts(FamilyIPv4, TransportUDP, "198.51.100.7", 443, ProtocolUnknown)

	inlineExclude := p1CompileRule(t, directory,
		`,"ip_cidr_file":[`+jsonPath(t, empty)+`],"ip_cidr_exclude":["142.251.153.0/24"]`)
	if inlineExclude.Matches(excluded) {
		t.Fatal("an exclusion must win over an all-empty positive include set")
	}
	if !inlineExclude.Matches(allowed) {
		t.Fatal("an unrelated destination must still match an all-empty positive include set")
	}
	fileExclude := p1CompileRule(t, directory,
		`,"ip_cidr_file":[`+jsonPath(t, empty)+`],"ip_cidr_exclude_file":[`+jsonPath(t, excludeFile)+`]`)
	if fileExclude.Matches(excluded) {
		t.Fatal("an exclusion file must win over an all-empty positive include set")
	}
	if !fileExclude.Matches(allowed) {
		t.Fatal("an unrelated destination must still match with an exclusion file")
	}
	anyExclude := p1CompileRule(t, directory,
		`,"ip_cidr_file":[`+jsonPath(t, empty)+`],"ip_cidr_exclude":["any"]`)
	if anyExclude.Matches(allowed) || anyExclude.Matches(excluded) {
		t.Fatal("a negative any must exclude every destination")
	}
	// The other predicates keep bounding the rule: the empty include set does
	// not turn it into a blanket rule.
	wrongPort := excluded
	wrongPort.Port = 8443
	if inlineExclude.Matches(wrongPort) {
		t.Fatal("port predicates must stay load-bearing with an all-empty include set")
	}
	wrongTransport := excluded
	wrongTransport.Transport = TransportTCP
	if inlineExclude.Matches(wrongTransport) {
		t.Fatal("network predicates must stay load-bearing with an all-empty include set")
	}
}

func TestP1EmptyPositiveIPIncludeReloadTransitions(t *testing.T) {
	directory := t.TempDir()
	list := p1WriteList(t, directory, "ipset-all.txt", "142.251.153.0/24\r\n")
	config, err := Compile(enabledOption(`{"enabled":true,"rules":[
		{"network":["udp"],"port":[443],"ip_cidr_file":["ipset-all.txt"],"dup":{"count":1}}]}`), directory)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	inside := o309Facts(FamilyIPv4, TransportUDP, "142.251.153.4", 443, ProtocolQUIC)
	outside := o309Facts(FamilyIPv4, TransportUDP, "198.51.100.7", 443, ProtocolQUIC)
	if !engine.Config().Rules[0].Matches(inside) {
		t.Fatal("the initial nonempty include must match its own prefix")
	}
	if engine.Config().Rules[0].Matches(outside) {
		t.Fatal("the initial nonempty include must restrict other addresses")
	}

	// Reload to a genuinely empty file: the rule stops being IP-restricted.
	if err = os.WriteFile(list, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := engine.ReloadListsContext(context.Background())
	if err != nil {
		t.Fatalf("reload to empty list: %v", err)
	}
	if !changed {
		t.Fatal("reload to an empty list must publish a changed digest")
	}
	if !engine.Config().Rules[0].Matches(inside) || !engine.Config().Rules[0].Matches(outside) {
		t.Fatal("after reloading an empty list the rule must not be IP-restricted")
	}

	// Reload back to a nonempty list: the restriction returns.
	if err = os.WriteFile(list, []byte("203.0.113.0/24\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = engine.ReloadListsContext(context.Background()); err != nil {
		t.Fatalf("reload to nonempty list: %v", err)
	}
	if engine.Config().Rules[0].Matches(inside) {
		t.Fatal("after reloading a nonempty list the old destination must be rejected")
	}
	reloaded := o309Facts(FamilyIPv4, TransportUDP, "203.0.113.9", 443, ProtocolQUIC)
	if !engine.Config().Rules[0].Matches(reloaded) {
		t.Fatal("after reloading a nonempty list its own prefix must match")
	}

	// A malformed reload keeps the last-good snapshot.
	if err = os.WriteFile(list, []byte("not-an-address\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = engine.ReloadLists(); err == nil {
		t.Fatal("malformed list reload must fail")
	}
	if !engine.Config().Rules[0].Matches(reloaded) {
		t.Fatal("a failed reload must keep the last-good restriction")
	}
	if engine.Config().Rules[0].Matches(inside) {
		t.Fatal("a failed reload must not widen the last-good restriction")
	}
}

func TestP1PositiveIPIncludeAggregateWithBundleDataset(t *testing.T) {
	directory := t.TempDir()
	empty := p1WriteList(t, directory, "ipset-all.txt", "")
	bundleRoot := t.TempDir()
	buildLocalBundle(t, bundleRoot, map[string]string{"ip4": "192.0.2.0/24\r\n"})
	manifest := filepath.Join(bundleRoot, "current.json")
	selector := `"list_bundle":{"manifest":` + jsonPath(t, manifest) + `,"ip_cidr":["ip4"]}`

	// A nonempty bundle dataset and an empty legacy file are one aggregate: the
	// bundle dataset supplies the restriction.
	rule := p1CompileRule(t, directory, `,`+selector+`,"ip_cidr_file":[`+jsonPath(t, empty)+`]`)
	if !rule.IPs.restricts() {
		t.Fatal("a nonempty bundle IP dataset must compile into an active restriction")
	}
	if !rule.Matches(o309Facts(FamilyIPv4, TransportUDP, "192.0.2.9", 443, ProtocolQUIC)) {
		t.Fatal("the bundle IP dataset must match its own prefix")
	}
	if rule.Matches(o309Facts(FamilyIPv4, TransportUDP, "198.51.100.7", 443, ProtocolQUIC)) {
		t.Fatal("a nonempty bundle IP dataset must reject other addresses")
	}

	// An empty bundle IP dataset adds no restriction, exactly like an empty
	// legacy include file.
	emptyBundleRoot := t.TempDir()
	buildLocalBundle(t, emptyBundleRoot, map[string]string{"ip4": ""})
	emptyManifest := filepath.Join(emptyBundleRoot, "current.json")
	emptySelector := `"list_bundle":{"manifest":` + jsonPath(t, emptyManifest) + `,"ip_cidr":["ip4"]}`
	emptyRule := p1CompileRule(t, directory, `,`+emptySelector)
	if emptyRule.IPs.restricts() {
		t.Fatal("an empty bundle IP dataset must not compile into a positive-IP restriction")
	}
	if !emptyRule.Matches(o309Facts(FamilyIPv4, TransportUDP, "198.51.100.7", 443, ProtocolQUIC)) {
		t.Fatal("an empty bundle IP dataset must not restrict a destination")
	}
}

func TestP1CapturedQUICFlightSelectsConvertedEmptyIncludeRule(t *testing.T) {
	directory := t.TempDir()
	empty := p1WriteList(t, directory, "ipset-all.txt", "")
	convertedMarker := []byte("P1EMPTYINCLUDEFAKE")
	fallbackMarker := []byte("P1LATERFALLBACK")
	config, err := Compile(enabledOption(`{"enabled":true,"rules":[
		{"name":"host-tcp","network":["tcp"],"port":[443],"domain":["www.youtube.com"],
		 "dup":{"count":1}},
		{"name":"converted-udp443-empty-include","network":["udp"],"port":[443],
		 "ip_cidr_file":[`+jsonPath(t, empty)+`],
		 "methods":["fake"],"fake":{"repeats":11,
		   "payloads":[{"protocol":"quic","hex":"`+p1Hex(string(convertedMarker))+`"}]}},
		{"name":"later-nonempty-include","network":["udp"],"port_range":["1024-65535"],
		 "any_protocol":true,"ip_cidr":["198.51.100.0/24"],"methods":["fake"],
		 "fake":{"repeats":1,
		   "payloads":[{"protocol":"quic","hex":"`+p1Hex(string(fallbackMarker))+`"}]}}]}`), directory)
	if err != nil {
		t.Fatal(err)
	}
	facts := MatchFacts{Family: FamilyIPv4, Transport: TransportUDP,
		Destination: netip.MustParseAddr("198.51.100.7"), Port: 443, Protocol: ProtocolQUIC}
	if config.Rules[0].Matches(facts) {
		t.Fatal("the TCP host rule must not match a UDP datagram")
	}
	if !config.Rules[1].Matches(facts) {
		t.Fatal("the converted empty-include rule must match the QUIC datagram")
	}

	data, err := os.ReadFile(filepath.Join("testdata", "quic-initial-linux.json"))
	if err != nil {
		t.Fatal(err)
	}
	var encoded []string
	if err = json.Unmarshal(data, &encoded); err != nil {
		t.Fatal(err)
	}
	if len(encoded) != 10 {
		t.Fatalf("captured flight has %d datagrams, want 10", len(encoded))
	}

	source := netip.MustParseAddrPort("192.0.2.1:40000")
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { engine.Close() })
	lease, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportUDP,
		Source: source, Destination: netip.MustParseAddrPort("198.51.100.7:443")})
	if err != nil {
		t.Fatal(err)
	}
	lease.SetLocalAddress(source)
	if err = lease.StartCapture(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lease.Close(nil) })

	capture := &o2bCapture{}
	// Under the delayed-replay ownership a queued Initial returns VerdictHold
	// and its captured bytes are delivered exactly once through the Completer;
	// an immediately answered datagram owns its disposition in the caller.
	completions := make([]int, len(encoded))
	held := make([]bool, len(encoded))
	for index, raw := range encoded {
		payload, decodeErr := hex.DecodeString(raw)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		packet := buildIPv4UDP(t, payload, 443)
		verdict := lease.HandlePacket(packet.Raw, DirectionOutbound, capture.inject,
			func(completion Verdict, reason string, modified []byte) {
				completions[index]++
				if completion != VerdictPass {
					t.Errorf("captured datagram %d completed with verdict %d, want the captured bytes unchanged", index, completion)
				}
			})
		switch verdict {
		case VerdictHold:
			held[index] = true
		case VerdictPass:
		default:
			t.Fatalf("captured datagram %d verdict = %d", index, verdict)
		}
		switch index {
		case 0:
			// The first Initial carries only a partial CRYPTO prefix: pinned
			// delays it, so the repaired admission emits no fake unit yet.
			if got := capture.containing(convertedMarker); got != 0 {
				t.Fatalf("partial-prefix fake injections = %d, want 0", got)
			}
			if got := capture.containing(fallbackMarker); got != 0 {
				t.Fatalf("later-rule fake injections = %d, want 0", got)
			}
		case 1:
			// The second Initial completes the ClientHello: exactly one burst
			// belongs to the cycle, from the converted empty-include rule, and
			// it is injected before the first held original is completed.
			if got := capture.containing(convertedMarker); got != 11 {
				t.Fatalf("converted-rule fake injections = %d, want the configured 11", got)
			}
			if got := capture.containing(fallbackMarker); got != 0 {
				t.Fatalf("later-rule fake injections = %d, want 0 after the converted rule wins", got)
			}
			if completions[0] != 1 || completions[1] != 1 {
				t.Fatalf("completed cycle deliveries = %v, want both held originals released once", completions[:2])
			}
		}
	}
	for index := range encoded {
		if held[index] && completions[index] != 1 {
			t.Fatalf("captured datagram %d: held original completions = %d, want exactly 1", index, completions[index])
		}
		if !held[index] && completions[index] != 0 {
			t.Fatalf("captured datagram %d: immediately answered original also completed", index)
		}
	}
	if got := capture.containing(convertedMarker); got != 55 {
		t.Fatalf("converted-rule fake injections in the captured flight = %d, want 5 completed cycles x 11", got)
	}
	if got := capture.containing(fallbackMarker); got != 0 {
		t.Fatalf("later-rule fake injections in the captured flight = %d, want 0", got)
	}
	if len(lease.udpFlows) != 1 {
		t.Fatalf("captured flight created %d UDP flows, want 1", len(lease.udpFlows))
	}
	for _, flow := range lease.udpFlows {
		if flow.rule != config.Rules[1] {
			t.Fatalf("captured flight selected rule %v, want the converted empty-include rule", flow.rule)
		}
		if flow.quic == nil {
			t.Fatal("captured flight has no QUIC reassembler")
		}
		if flow.host != "www.youtube.com" || !flow.facts.HostKnown || flow.facts.Host != "www.youtube.com" {
			t.Fatalf("captured CRYPTO fact host=%q known=%v, want www.youtube.com", flow.host, flow.facts.HostKnown)
		}
	}
	t.Logf("captured flight injected %d fake packets in total", len(capture.packets))
}

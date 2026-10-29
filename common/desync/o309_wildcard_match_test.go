package desync

// O309-1 regressions: the operator `ip_cidr: ["any"]` wildcard (inline or read
// from a list file) removes only the positive IP restriction. Every other
// predicate and the negative lists stay load-bearing, and a negative "any"
// excludes every destination. The cases below exercise the real option decoder,
// Compile, Rule.Matches, StreamConfig selection and Engine/Lease.HandlePacket
// effects; no case asserts an internal flag alone.

import (
	"compress/gzip"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func compileO309(t *testing.T, rules string) *Config {
	t.Helper()
	config, err := Compile(enabledOption(`{"enabled":true,"rules":`+rules+`}`), "")
	if err != nil {
		t.Fatalf("compile %s: %v", rules, err)
	}
	if len(config.Rules) != 1 {
		t.Fatalf("compiled rules = %d, want 1", len(config.Rules))
	}
	return config
}

func o309Facts(family Family, transport Transport, destination string, port uint16, protocol Protocol) MatchFacts {
	return MatchFacts{Family: family, Transport: transport,
		Destination: netip.MustParseAddr(destination), Port: port, Protocol: protocol}
}

func TestO309OrdinarySelectorControls(t *testing.T) {
	// Ordinary selector controls: the wildcard fix must not change any of
	// these. They stay green under the old-guard mutant, which is how the
	// nonvacuous RED is distinguished from a build/scope break.
	prefix := compileO309(t, `[{"network":["udp"],"ip_cidr":["203.0.113.0/24"],"dup":{"count":1}}]`).Rules[0]
	if !prefix.Matches(o309Facts(FamilyIPv4, TransportUDP, "203.0.113.9", 10000, ProtocolUnknown)) {
		t.Fatal("explicit prefix must match its own address")
	}
	if prefix.Matches(o309Facts(FamilyIPv4, TransportUDP, "198.51.100.7", 10000, ProtocolUnknown)) {
		t.Fatal("explicit prefix must not match another address")
	}
	exclusion := compileO309(t, `[{"network":["udp"],"ip_cidr_exclude":["203.0.113.0/24"],"dup":{"count":1}}]`).Rules[0]
	if exclusion.Matches(o309Facts(FamilyIPv4, TransportUDP, "203.0.113.9", 10000, ProtocolUnknown)) {
		t.Fatal("explicit negative prefix must exclude its address")
	}
	if !exclusion.Matches(o309Facts(FamilyIPv4, TransportUDP, "198.51.100.7", 10000, ProtocolUnknown)) {
		t.Fatal("explicit negative prefix must not exclude another address")
	}
	portAndHost := compileO309(t, `[{"network":["tcp"],"port":[443],"ip_cidr":["203.0.113.0/24"],"domain":["example.com"],"dup":{"count":1}}]`).Rules[0]
	host := o309Facts(FamilyIPv4, TransportTCP, "203.0.113.9", 443, ProtocolTLS)
	host.Host, host.HostKnown = "www.example.com", true
	if !portAndHost.Matches(host) {
		t.Fatal("ordinary port/prefix/host control must match")
	}
	wrongPort := host
	wrongPort.Port = 8443
	if portAndHost.Matches(wrongPort) {
		t.Fatal("ordinary port control must keep rejecting another port")
	}
	wrongPrefix := host
	wrongPrefix.Destination = netip.MustParseAddr("198.51.100.7")
	if portAndHost.Matches(wrongPrefix) {
		t.Fatal("ordinary prefix control must keep rejecting another address")
	}
}

func TestO309MalformedIPEntriesStillFailClosed(t *testing.T) {
	for _, rules := range []string{
		`[{"network":["udp"],"ip_cidr":["definitely-not-an-ip"]}]`,
		`[{"network":["udp"],"ip_cidr_exclude":["300.1.1.1"]}]`,
		`[{"network":["udp"],"ip_cidr":["any","10.0.0.0/33"]}]`,
	} {
		if _, err := Compile(enabledOption(`{"enabled":true,"rules":`+rules+`}`), ""); err == nil {
			t.Fatalf("malformed IP entry accepted: %s", rules)
		}
	}
}

func TestO309AnyPositiveSelectorMatchesIPv4AndIPv6(t *testing.T) {
	// Exact operator shape reproduced by the O309-1 security probe.
	rule := compileO309(t, `[{"network":["udp"],"ip_cidr":["any"],"dup":{"count":1}}]`).Rules[0]
	ipv4 := o309Facts(FamilyIPv4, TransportUDP, "198.51.100.7", 10000, ProtocolUnknown)
	if !rule.Matches(ipv4) {
		t.Fatal("pre-existing any positive selector rejects IPv4; explicit /0 control matched")
	}
	ipv6 := o309Facts(FamilyIPv6, TransportUDP, "2001:db8::7", 10000, ProtocolUnknown)
	if !rule.Matches(ipv6) {
		t.Fatal("any positive selector rejects IPv6")
	}

	// Explicit prefixes keep the pre-existing IPv4/IPv6 controls working.
	ipv4Control := compileO309(t, `[{"network":["udp"],"ip_cidr":["0.0.0.0/0"],"dup":{"count":1}}]`).Rules[0]
	if !ipv4Control.Matches(ipv4) {
		t.Fatal("explicit 0.0.0.0/0 control no longer matches IPv4")
	}
	ipv6Control := compileO309(t, `[{"network":["udp"],"ip_cidr":["::/0"],"dup":{"count":1}}]`).Rules[0]
	if !ipv6Control.Matches(ipv6) {
		t.Fatal("explicit ::/0 control no longer matches IPv6")
	}
	prefix := compileO309(t, `[{"network":["udp"],"ip_cidr":["203.0.113.0/24"],"dup":{"count":1}}]`).Rules[0]
	if prefix.Matches(ipv4) {
		t.Fatal("an explicit prefix must still restrict IPv4")
	}
	if !prefix.Matches(o309Facts(FamilyIPv4, TransportUDP, "203.0.113.9", 10000, ProtocolUnknown)) {
		t.Fatal("an explicit prefix must still match its own addresses")
	}
	if prefix.Matches(o309Facts(FamilyIPv6, TransportUDP, "2001:db8::7", 10000, ProtocolUnknown)) {
		t.Fatal("an IPv4 prefix must not match an IPv6 destination")
	}
}

func TestO309AnyUnionKeepsOtherPredicatesLoadBearing(t *testing.T) {
	// The wildcard union is additive: an IP outside every explicit prefix and
	// both families still match.
	union := compileO309(t, `[{"network":["udp","tcp"],"ip_cidr":["203.0.113.0/24","any"],"dup":{"count":1}}]`).Rules[0]
	if !union.Matches(o309Facts(FamilyIPv4, TransportTCP, "198.51.100.7", 443, ProtocolUnknown)) {
		t.Fatal("wildcard plus explicit prefix must match an IPv4 outside the prefix")
	}
	if !union.Matches(o309Facts(FamilyIPv6, TransportUDP, "2001:db8::7", 443, ProtocolUnknown)) {
		t.Fatal("wildcard plus explicit prefix must match IPv6")
	}
	if !union.Matches(o309Facts(FamilyIPv4, TransportUDP, "203.0.113.9", 443, ProtocolUnknown)) {
		t.Fatal("wildcard plus explicit prefix must keep matching the prefix")
	}

	// The negative IP list still wins with a positive wildcard.
	excluded := compileO309(t, `[{"network":["udp"],"ip_cidr":["any"],"ip_cidr_exclude":["198.51.100.0/24","2001:db8::/32"],"dup":{"count":1}}]`).Rules[0]
	if excluded.Matches(o309Facts(FamilyIPv4, TransportUDP, "198.51.100.7", 10000, ProtocolUnknown)) {
		t.Fatal("IPv4 ip_cidr_exclude must win over the positive wildcard")
	}
	if excluded.Matches(o309Facts(FamilyIPv6, TransportUDP, "2001:db8::7", 10000, ProtocolUnknown)) {
		t.Fatal("IPv6 ip_cidr_exclude must win over the positive wildcard")
	}
	if !excluded.Matches(o309Facts(FamilyIPv4, TransportUDP, "203.0.113.7", 10000, ProtocolUnknown)) {
		t.Fatal("unexcluded IPv4 must still match")
	}
	if !excluded.Matches(o309Facts(FamilyIPv6, TransportUDP, "2001:db9::7", 10000, ProtocolUnknown)) {
		t.Fatal("unexcluded IPv6 must still match")
	}

	domainFacts := func(host string, known bool) MatchFacts {
		facts := o309Facts(FamilyIPv4, TransportTCP, "198.51.100.7", 443, ProtocolTLS)
		facts.Host, facts.HostKnown = host, known
		return facts
	}
	cases := []struct {
		name  string
		rules string
		facts MatchFacts
		want  bool
	}{
		{"network", `[{"network":["tcp"],"ip_cidr":["any"]}]`,
			o309Facts(FamilyIPv4, TransportUDP, "198.51.100.7", 443, ProtocolUnknown), false},
		{"ip_version-4", `[{"network":["udp"],"ip_version":[4],"ip_cidr":["any"]}]`,
			o309Facts(FamilyIPv6, TransportUDP, "2001:db8::7", 443, ProtocolUnknown), false},
		{"ip_version-6", `[{"network":["udp"],"ip_version":[6],"ip_cidr":["any"]}]`,
			o309Facts(FamilyIPv4, TransportUDP, "198.51.100.7", 443, ProtocolUnknown), false},
		{"port", `[{"network":["udp"],"port":[443],"ip_cidr":["any"]}]`,
			o309Facts(FamilyIPv4, TransportUDP, "198.51.100.7", 10000, ProtocolUnknown), false},
		{"port-range", `[{"network":["udp"],"port_range":["10000-10100"],"ip_cidr":["any"]}]`,
			o309Facts(FamilyIPv4, TransportUDP, "198.51.100.7", 10000, ProtocolUnknown), true},
		{"port-exclude", `[{"network":["udp"],"port_exclude":[443],"ip_cidr":["any"]}]`,
			o309Facts(FamilyIPv4, TransportUDP, "198.51.100.7", 443, ProtocolUnknown), false},
		{"protocol", `[{"network":["tcp"],"protocol":["tls"],"ip_cidr":["any"]}]`,
			o309Facts(FamilyIPv4, TransportTCP, "198.51.100.7", 443, ProtocolHTTP), false},
		{"skip-no-sni", `[{"network":["tcp"],"protocol":["tls"],"ip_cidr":["any"]}]`,
			o309Facts(FamilyIPv4, TransportTCP, "198.51.100.7", 443, ProtocolUnknown), false},
		{"domain-unknown-host", `[{"network":["tcp"],"domain":["example.com"],"ip_cidr":["any"]}]`,
			domainFacts("", false), false},
		{"domain-match", `[{"network":["tcp"],"domain":["example.com"],"ip_cidr":["any"]}]`,
			domainFacts("www.example.com", true), true},
		{"domain-exclude", `[{"network":["tcp"],"domain":["example.com"],"domain_exclude":["ads.example.com"],"ip_cidr":["any"]}]`,
			domainFacts("ads.example.com", true), false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			rule := compileO309(t, testCase.rules).Rules[0]
			if got := rule.Matches(testCase.facts); got != testCase.want {
				t.Fatalf("Matches = %v, want %v", got, testCase.want)
			}
		})
	}
}

func TestO309AnyNegativeWildcardExcludesEveryDestination(t *testing.T) {
	both := compileO309(t, `[{"network":["udp"],"ip_cidr":["any"],"ip_cidr_exclude":["any"],"dup":{"count":1}}]`).Rules[0]
	if both.Matches(o309Facts(FamilyIPv4, TransportUDP, "198.51.100.7", 10000, ProtocolUnknown)) {
		t.Fatal("negative any must exclude a valid IPv4 destination")
	}
	if both.Matches(o309Facts(FamilyIPv6, TransportUDP, "2001:db8::7", 10000, ProtocolUnknown)) {
		t.Fatal("negative any must exclude a valid IPv6 destination")
	}

	onlyExclude := compileO309(t, `[{"network":["udp"],"ip_cidr_exclude":["any"],"dup":{"count":1}}]`).Rules[0]
	if onlyExclude.Matches(o309Facts(FamilyIPv4, TransportUDP, "198.51.100.7", 10000, ProtocolUnknown)) {
		t.Fatal("a rule whose negative list is any must not match IPv4")
	}
	if onlyExclude.Matches(o309Facts(FamilyIPv6, TransportUDP, "2001:db8::7", 10000, ProtocolUnknown)) {
		t.Fatal("a rule whose negative list is any must not match IPv6")
	}

	mixed := compileO309(t, `[{"network":["udp"],"ip_cidr_exclude":["any","203.0.113.0/24"],"dup":{"count":1}}]`).Rules[0]
	if mixed.Matches(o309Facts(FamilyIPv4, TransportUDP, "198.51.100.7", 10000, ProtocolUnknown)) {
		t.Fatal("negative any must not become a no-op when prefixes are also present")
	}

	// Ordinary negative prefixes keep exactly their previous scope.
	prefix := compileO309(t, `[{"network":["udp"],"ip_cidr_exclude":["203.0.113.0/24"],"dup":{"count":1}}]`).Rules[0]
	if prefix.Matches(o309Facts(FamilyIPv4, TransportUDP, "203.0.113.9", 10000, ProtocolUnknown)) {
		t.Fatal("an ordinary negative prefix must still exclude its addresses")
	}
	if !prefix.Matches(o309Facts(FamilyIPv4, TransportUDP, "198.51.100.7", 10000, ProtocolUnknown)) {
		t.Fatal("an ordinary negative prefix must not exclude unrelated addresses")
	}
	if !prefix.Matches(o309Facts(FamilyIPv6, TransportUDP, "2001:db8::7", 10000, ProtocolUnknown)) {
		t.Fatal("an IPv4 negative prefix must not exclude IPv6 addresses")
	}
}

func TestO309AnyEnginePacketEffects(t *testing.T) {
	t.Run("ipv4-dup-effect", func(t *testing.T) {
		h := newHeldHarness(t, `[{"network":["tcp"],"ip_cidr":["any"],"dup":{"count":1}}]`, "")
		if verdict := h.capture([]byte("data"), 7000); verdict != VerdictPass {
			t.Fatalf("wildcard dup verdict = %d, want pass", verdict)
		}
		if len(h.injected) != 1 {
			t.Fatalf("wildcard dup injected = %d, want 1", len(h.injected))
		}
	})
	t.Run("ipv4-union-effect", func(t *testing.T) {
		h := newHeldHarness(t, `[{"network":["tcp"],"ip_cidr":["203.0.113.0/24","any"],"dup":{"count":1}}]`, "")
		if verdict := h.capture([]byte("data"), 7000); verdict != VerdictPass {
			t.Fatalf("wildcard union verdict = %d, want pass", verdict)
		}
		if len(h.injected) != 1 {
			t.Fatalf("wildcard union injected = %d, want 1", len(h.injected))
		}
	})
	t.Run("ipv4-explicit-prefix-control", func(t *testing.T) {
		h := newHeldHarness(t, `[{"network":["tcp"],"ip_cidr":["203.0.113.0/24"],"dup":{"count":1}}]`, "")
		if verdict := h.capture([]byte("data"), 7000); verdict != VerdictPass {
			t.Fatalf("prefix control verdict = %d, want pass", verdict)
		}
		if len(h.injected) != 0 {
			t.Fatalf("mismatched explicit prefix injected = %d, want 0", len(h.injected))
		}
	})
	t.Run("ipv4-negative-exclusion-effect", func(t *testing.T) {
		h := newHeldHarness(t, `[{"network":["tcp"],"ip_cidr":["any"],"ip_cidr_exclude":["198.51.100.0/24"],"dup":{"count":1}}]`, "")
		if verdict := h.capture([]byte("data"), 7000); verdict != VerdictPass {
			t.Fatalf("excluded wildcard verdict = %d, want pass", verdict)
		}
		if len(h.injected) != 0 {
			t.Fatalf("excluded wildcard injected = %d, want 0", len(h.injected))
		}
	})
	t.Run("ipv6-dup-effect", func(t *testing.T) {
		h := newHeldHarnessIPv6(t, `[{"network":["tcp"],"ip_cidr":["any"],"orig":{"ttl":7},"dup":{"count":1}}]`)
		packet := buildIPv6TCP(t, []byte("data"), 13000, tcpFlagACK|tcpFlagPSH)
		verdict := h.lease.HandlePacket(packet.Raw, DirectionOutbound, func(replacement []byte) error {
			h.injected = append(h.injected, append([]byte(nil), replacement...))
			return nil
		}, nil)
		if verdict != VerdictModify {
			t.Fatalf("IPv6 wildcard verdict = %d, want modify", verdict)
		}
		if len(h.injected) != 1 {
			t.Fatalf("IPv6 wildcard dup injected = %d, want 1", len(h.injected))
		}
	})
	t.Run("ipv6-family-control", func(t *testing.T) {
		h := newHeldHarnessIPv6(t, `[{"network":["tcp"],"ip_version":[4],"ip_cidr":["any"],"orig":{"ttl":7},"dup":{"count":1}}]`)
		packet := buildIPv6TCP(t, []byte("data"), 13000, tcpFlagACK|tcpFlagPSH)
		verdict := h.lease.HandlePacket(packet.Raw, DirectionOutbound, func(replacement []byte) error {
			h.injected = append(h.injected, append([]byte(nil), replacement...))
			return nil
		}, nil)
		if verdict != VerdictPass {
			t.Fatalf("IPv4-only wildcard rule transformed IPv6: verdict = %d", verdict)
		}
		if len(h.injected) != 0 {
			t.Fatalf("IPv4-only wildcard rule injected %d IPv6 packets", len(h.injected))
		}
	})
	t.Run("udp-dup-effect", func(t *testing.T) {
		h := newHeldHarnessUDP(t, `[{"network":["udp"],"ip_cidr":["any"],"any_protocol":true,"orig":{"ttl":9},"dup":{"count":1}}]`)
		packet := buildUDP4(t, []byte("QUIC-like payload"))
		verdict := h.lease.HandlePacket(packet.Raw, DirectionOutbound, func(replacement []byte) error {
			h.injected = append(h.injected, append([]byte(nil), replacement...))
			return nil
		}, nil)
		if verdict != VerdictModify {
			t.Fatalf("UDP wildcard verdict = %d, want modify", verdict)
		}
		if len(h.injected) != 1 {
			t.Fatalf("UDP wildcard dup injected = %d, want 1", len(h.injected))
		}
	})
}

func TestO309AnyListFileReloadAndEmptyPositiveSemantics(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "ips.txt")
	if err := os.WriteFile(list, []byte("203.0.113.0/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := Compile(enabledOption(`{"enabled":true,"rules":[{"network":["udp"],"ip_cidr_file":["ips.txt"],"dup":{"count":1}}]}`), dir)
	if err != nil {
		t.Fatal(err)
	}
	rule := config.Rules[0]
	if rule.Matches(o309Facts(FamilyIPv4, TransportUDP, "198.51.100.7", 10000, ProtocolUnknown)) {
		t.Fatal("a prefix list file must restrict the rule")
	}
	if !rule.Matches(o309Facts(FamilyIPv4, TransportUDP, "203.0.113.9", 10000, ProtocolUnknown)) {
		t.Fatal("a prefix list file must match its own addresses")
	}

	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	// The same "any" entry read through the file path must be a wildcard in
	// the reloaded snapshot, for both families.
	if err = os.WriteFile(list, []byte("any\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := engine.ReloadListsContext(context.Background())
	if err != nil {
		t.Fatalf("reload to any: %v", err)
	}
	if !changed {
		t.Fatal("reload to any must report a changed list digest")
	}
	reloaded := engine.Config().Rules[0]
	if !reloaded.Matches(o309Facts(FamilyIPv4, TransportUDP, "198.51.100.7", 10000, ProtocolUnknown)) {
		t.Fatal("file wildcard must match IPv4 after reload")
	}
	if !reloaded.Matches(o309Facts(FamilyIPv6, TransportUDP, "2001:db8::7", 10000, ProtocolUnknown)) {
		t.Fatal("file wildcard must match IPv6 after reload")
	}

	// A failed reload keeps the last-good wildcard snapshot.
	if err = os.WriteFile(list, []byte("not-an-address\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = engine.ReloadLists(); err == nil {
		t.Fatal("malformed list file reload must fail")
	}
	if !engine.Config().Rules[0].Matches(o309Facts(FamilyIPv4, TransportUDP, "198.51.100.7", 10000, ProtocolUnknown)) {
		t.Fatal("failed reload must keep the last-good wildcard snapshot")
	}

	// A positive IP file that resolves to no entries imposes no positive-IP
	// restriction (pinned zapret v72.9 ipset.c: all include lists empty means
	// check passes), for both families. The rule is still bounded by its other
	// predicates and its exclusions.
	if err = os.WriteFile(list, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = engine.ReloadListsContext(context.Background()); err != nil {
		t.Fatalf("reload to empty list: %v", err)
	}
	if !engine.Config().Rules[0].Matches(o309Facts(FamilyIPv4, TransportUDP, "198.51.100.7", 10000, ProtocolUnknown)) {
		t.Fatal("an all-empty positive IP include set must not restrict IPv4")
	}
	if !engine.Config().Rules[0].Matches(o309Facts(FamilyIPv6, TransportUDP, "2001:db8::7", 10000, ProtocolUnknown)) {
		t.Fatal("an all-empty positive IP include set must not restrict IPv6")
	}

	// An omitted positive list stays unrestricted.
	omitted := compileO309(t, `[{"network":["udp"],"dup":{"count":1}}]`).Rules[0]
	if !omitted.Matches(o309Facts(FamilyIPv4, TransportUDP, "198.51.100.7", 10000, ProtocolUnknown)) {
		t.Fatal("an omitted positive list must stay unrestricted")
	}

	// Compressed list files go through the same set builder.
	gzPath := filepath.Join(dir, "ips.txt.gz")
	file, err := os.Create(gzPath)
	if err != nil {
		t.Fatal(err)
	}
	writer := gzip.NewWriter(file)
	if _, err = writer.Write([]byte("any\n")); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	gzConfig, err := Compile(enabledOption(`{"enabled":true,"rules":[{"network":["udp"],"ip_cidr_file":["ips.txt.gz"],"dup":{"count":1}}]}`), dir)
	if err != nil {
		t.Fatal(err)
	}
	if !gzConfig.Rules[0].Matches(o309Facts(FamilyIPv4, TransportUDP, "198.51.100.7", 10000, ProtocolUnknown)) {
		t.Fatal("gzip list wildcard must match IPv4")
	}
	if !gzConfig.Rules[0].Matches(o309Facts(FamilyIPv6, TransportUDP, "2001:db8::7", 10000, ProtocolUnknown)) {
		t.Fatal("gzip list wildcard must match IPv6")
	}
}

func TestO309AnyStreamSelectionUsesSameMatcher(t *testing.T) {
	streamRule := func(cidr, exclude []string) option.DirectDesyncStreamRule {
		return option.DirectDesyncStreamRule{
			DirectDesyncStreamMatch: option.DirectDesyncStreamMatch{
				IPCIDR:        badoption.Listable[string](cidr),
				IPCIDRExclude: badoption.Listable[string](exclude),
			},
			Methods: badoption.Listable[string]{"split"},
			Split:   &option.DirectDesyncStreamSplit{SplitPos: badoption.Listable[string]{"1"}},
		}
	}
	ipv4 := o309Facts(FamilyIPv4, TransportTCP, "198.51.100.7", 443, ProtocolTLS)
	ipv6 := o309Facts(FamilyIPv6, TransportTCP, "2001:db8::7", 443, ProtocolTLS)

	wildcard, err := CompileStream([]option.DirectDesyncStreamRule{streamRule([]string{"any"}, nil)}, "")
	if err != nil {
		t.Fatal(err)
	}
	if wildcard.selectRule(ipv4) == nil {
		t.Fatal("stream wildcard rule must select an IPv4 flow")
	}
	if wildcard.selectRule(ipv6) == nil {
		t.Fatal("stream wildcard rule must select an IPv6 flow")
	}
	excluded, err := CompileStream([]option.DirectDesyncStreamRule{streamRule([]string{"any"}, []string{"198.51.100.0/24"})}, "")
	if err != nil {
		t.Fatal(err)
	}
	if excluded.selectRule(ipv4) != nil {
		t.Fatal("stream wildcard must not override an IP exclusion")
	}
	prefix, err := CompileStream([]option.DirectDesyncStreamRule{streamRule([]string{"203.0.113.0/24"}, nil)}, "")
	if err != nil {
		t.Fatal(err)
	}
	if prefix.selectRule(ipv4) != nil {
		t.Fatal("stream explicit prefix must still restrict IPv4")
	}
	if prefix.selectRule(o309Facts(FamilyIPv4, TransportTCP, "203.0.113.9", 443, ProtocolTLS)) == nil {
		t.Fatal("stream explicit prefix must select its own addresses")
	}
}

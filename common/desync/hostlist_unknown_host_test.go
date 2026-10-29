package desync

// Submission17 regressions: pinned zapret v72.9 makes a regular (non-auto)
// hostlist in EITHER collection block a profile while the hostname is unknown.
//
//	nfq/desync.c:253-256   bHostlistsEmpty = PROFILE_HOSTLISTS_EMPTY(dp);
//	                       if (!dp->hostlist_auto && !hostname && !bHostlistsEmpty)
//	                           return false;  // "profile cannot win"
//	nfq/params.h:191       PROFILE_HOSTLISTS_EMPTY(dp) = is_empty(hl_collection) &&
//	                                                      is_empty(hl_collection_exclude)
//	nfq/pools.c:263-273    hostlist_collection_is_empty(): a collected file counts
//	                       only while it holds parsed entries
//	nfq/hostlist.c:234-254 HostlistCheck_ for a KNOWN host: exclusions win, an
//	                       all-empty include collection passes, a nonempty one
//	                       requires membership
//
// Pinned source: zapret c849e55ef0f1c244206f5a05ff7b1ab41a3824ee. The captured
// inputs are the QA504 raw off-arm PCAP packets of TCP-HIGH-N4-LINUX/WINDOWS:
// an unknown payload to 1.1.1.1:8443 followed by five further 28-byte records.
// The matched native reference selects the any-protocol cutoff n4 profile
// (candidate rule-7, pinned zapret profile8) and emits 11x4 B + 11x661 B
// unknown fake packets, not the earlier web rule with its hostlist exclusions.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// pinnedHostlistExclude is the hostlist fixture of the selection table: two
// effective entries (one apex entry, one subdomain-only entry) plus a comment
// line, in the upstream list syntax.
const pinnedHostlistExclude = "# pinned hostlist exclusion fixture\nblocked.example\n.ads.example\n"

// Captured QA504 fixtures, copied byte-identically from
// desync-network-repair-artifacts/t_07b244b7/fixtures/.
const (
	qa504LinuxFixture   = "high-tcp-linux.packets.json"
	qa504WindowsFixture = "high-tcp-windows.packets.json"
	qa504LinuxSHA256    = "bedd1ffa634e88929789a7eefba1cd65bcd6719165bc9677247f0a787c22a7f7"
	qa504WindowsSHA256  = "e5eec831a9b2b70880d251777906825455fd95c47f0bd054856b9d67ffd03135"
)

func writeHostlistFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func compileHostlistRule(t *testing.T, dir, ruleJSON string) *Rule {
	t.Helper()
	config, err := Compile(enabledOption(`{"enabled":true,"rules":[`+ruleJSON+`]}`), dir)
	if err != nil {
		t.Fatalf("compile %s: %v", ruleJSON, err)
	}
	if len(config.Rules) != 1 {
		t.Fatalf("compiled rules = %d, want 1", len(config.Rules))
	}
	return config.Rules[0]
}

func hostlistFacts(host string, known bool) MatchFacts {
	facts := MatchFacts{Family: FamilyIPv4, Transport: TransportTCP,
		Destination: netip.MustParseAddr("198.51.100.7"), Port: 443, Protocol: ProtocolUnknown}
	facts.Host, facts.HostKnown = host, known
	return facts
}

func hostlistFactsIPv6(host string, known bool) MatchFacts {
	facts := MatchFacts{Family: FamilyIPv6, Transport: TransportTCP,
		Destination: netip.MustParseAddr("2001:db8::7"), Port: 443, Protocol: ProtocolUnknown}
	facts.Host, facts.HostKnown = host, known
	return facts
}

// TestUnknownHostHostlistReachability is the source-level half of the defect:
// rule predicates, not only the flow caller, must apply pinned reachability.
func TestUnknownHostHostlistReachability(t *testing.T) {
	dir := t.TempDir()
	writeHostlistFile(t, dir, "exclude.txt", pinnedHostlistExclude)
	writeHostlistFile(t, dir, "empty.txt", "")
	writeHostlistFile(t, dir, "comment.txt", "# nothing but a comment\n")
	writeHostlistFile(t, dir, "positive.txt", "example.com\n")

	excludeOnly := `{"network":["tcp"],"port":[443],"domain_exclude_file":["exclude.txt"]}`
	positiveAndExclude := `{"network":["tcp"],"port":[443],"domain":["example.com","blocked.example"],"domain_exclude_file":["exclude.txt"]}`
	catchAll := `{"network":["tcp"],"port":[443],"any_protocol":true}`
	learningExclude := `{"network":["tcp"],"port":[443],"any_protocol":true,"learning":{"fail_threshold":3},"domain_exclude_file":["exclude.txt"]}`
	emptyPositive := `{"network":["tcp"],"port":[443],"domain_file":["empty.txt"]}`
	emptyExclude := `{"network":["tcp"],"port":[443],"domain_exclude_file":["empty.txt"]}`
	commentExclude := `{"network":["tcp"],"port":[443],"domain_exclude_file":["comment.txt"]}`
	unionPositive := `{"network":["tcp"],"port":[443],"domain_file":["empty.txt","positive.txt"]}`
	// The empty positive-IP compatibility of submission16 must stay intact,
	// and it must not resurrect the exclusion-only rule for an unknown host.
	emptyIPWithExclude := `{"network":["tcp"],"port":[443],"ip_cidr_file":["empty.txt"],"domain_exclude_file":["exclude.txt"]}`

	cases := []struct {
		name  string
		rules string
		facts MatchFacts
		want  bool
	}{
		{"exclusion-only/unknown-host", excludeOnly, hostlistFacts("", false), false},
		{"exclusion-only/known-allowed-host", excludeOnly, hostlistFacts("allowed.example", true), true},
		{"exclusion-only/known-excluded-host", excludeOnly, hostlistFacts("blocked.example", true), false},
		{"exclusion-only/known-excluded-subdomain", excludeOnly, hostlistFacts("cdn.blocked.example", true), false},
		{"exclusion-only/suffix-entry-excludes-subdomain", excludeOnly, hostlistFacts("a.ads.example", true), false},
		{"exclusion-only/suffix-entry-keeps-apex-host", excludeOnly, hostlistFacts("ads.example", true), true},
		{"positive-and-exclusion/unknown-host", positiveAndExclude, hostlistFacts("", false), false},
		{"positive-and-exclusion/known-positive-host", positiveAndExclude, hostlistFacts("www.example.com", true), true},
		{"positive-and-exclusion/exclusion-wins-over-positive", positiveAndExclude, hostlistFacts("blocked.example", true), false},
		{"no-hostlist/catch-all-unknown-host", catchAll, hostlistFacts("", false), true},
		{"configured-empty-positive/unknown-host", emptyPositive, hostlistFacts("", false), false},
		{"configured-empty-positive/known-host", emptyPositive, hostlistFacts("example.com", true), false},
		{"configured-empty-exclude/unknown-host", emptyExclude, hostlistFacts("", false), true},
		{"comment-only-exclude/unknown-host", commentExclude, hostlistFacts("", false), true},
		{"nonempty-union/unknown-host", unionPositive, hostlistFacts("", false), false},
		{"nonempty-union/known-member", unionPositive, hostlistFacts("www.example.com", true), true},
		{"nonempty-union/known-nonmember", unionPositive, hostlistFacts("other.example", true), false},
		{"learning/unknown-host", learningExclude, hostlistFacts("", false), true},
		{"learning/known-excluded-host", learningExclude, hostlistFacts("blocked.example", true), false},
		{"empty-positive-ip-with-exclusion/unknown-host", emptyIPWithExclude, hostlistFacts("", false), false},
		{"empty-positive-ip-with-exclusion/known-allowed-host", emptyIPWithExclude, hostlistFacts("allowed.example", true), true},
		{"ipv4-only-exclusion/ipv6-known-allowed-host", `{"network":["tcp"],"ip_version":[4],"domain_exclude_file":["exclude.txt"]}`, hostlistFactsIPv6("allowed.example", true), false},
		{"ipv6-exclusion/ipv6-known-allowed-host", `{"network":["tcp"],"ip_version":[6],"domain_exclude_file":["exclude.txt"]}`, hostlistFactsIPv6("allowed.example", true), true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			rule := compileHostlistRule(t, dir, testCase.rules)
			if got := rule.Matches(testCase.facts); got != testCase.want {
				t.Fatalf("Matches = %v, want %v for %s", got, testCase.want, testCase.rules)
			}
		})
	}
}

// hostlistFlow is one lease plus the recorded injections of a packet-mode flow.
type hostlistFlow struct {
	lease    *Lease
	injected [][]byte
}

func newHostlistFlow(t *testing.T, config *Config, destination netip.AddrPort) *hostlistFlow {
	t.Helper()
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { engine.Close() })
	source := netip.MustParseAddrPort("192.0.2.10:40000")
	lease, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportTCP,
		Source: source, Destination: destination})
	if err != nil {
		t.Fatal(err)
	}
	lease.SetLocalAddress(source)
	if err = lease.StartCapture(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lease.Close(nil) })
	return &hostlistFlow{lease: lease}
}

func (f *hostlistFlow) inject(raw []byte) error {
	f.injected = append(f.injected, append([]byte(nil), raw...))
	return nil
}

func (f *hostlistFlow) countContaining(marker []byte) int {
	count := 0
	for _, raw := range f.injected {
		if bytes.Contains(raw, marker) {
			count++
		}
	}
	return count
}

func (f *hostlistFlow) reset() { f.injected = nil }

// TestUnknownHostExclusionRuleDoesNotPreemptCatchAll is the flow half: an
// unknown-host TCP flow must not be captured by a rule whose only host filter
// is a nonempty exclusion hostlist, while a revealed host keeps the pinned
// exclusion semantics (allowed host wins the earlier rule, excluded host
// falls through to the later catch-all).
func TestUnknownHostExclusionRuleDoesNotPreemptCatchAll(t *testing.T) {
	dir := t.TempDir()
	writeHostlistFile(t, dir, "exclude.txt", pinnedHostlistExclude)
	writeHostlistFile(t, dir, "empty.txt", "")
	rules := `[
		{"name":"web-host-exclude","network":["tcp"],"port":[443],
		 "domain_exclude_file":["exclude.txt"],"ip_cidr_file":["empty.txt"],
		 "methods":["fake"],
		 "fake":{"repeats":3,"payloads":[{"protocol":"tls","hex":"574542484f5354"}]}},
		{"name":"catch-all","network":["tcp"],"port_range":["1-65535"],"any_protocol":true,
		 "cutoff":"n4","methods":["fake"],
		 "fake":{"repeats":2,"payloads":[
			{"protocol":"tls","hex":"4341544348544c53"},
			{"protocol":"unknown","hex":"4341544348554e4b"}]}}]`
	config, err := Compile(enabledOption(`{"enabled":true,"rules":`+rules+`}`), dir)
	if err != nil {
		t.Fatal(err)
	}
	webMarker := []byte("WEBHOST")
	catchTLSMarker := []byte("CATCHTLS")
	catchUnknownMarker := []byte("CATCHUNK")

	t.Run("unknown-host-selects-later-catch-all", func(t *testing.T) {
		flow := newHostlistFlow(t, config, netip.MustParseAddrPort("198.51.100.20:443"))
		if verdict := flow.lease.HandlePacket(buildIPv4TCP(t, nil, 100, tcpFlagSYN).Raw, DirectionOutbound, flow.inject, nil); verdict != VerdictPass {
			t.Fatalf("SYN verdict = %d", verdict)
		}
		if len(flow.injected) != 0 {
			t.Fatalf("SYN must not emit a first-stage fake: %d packets", len(flow.injected))
		}
		// The captured QA504 payload shape: unknown protocol, no hostname.
		if verdict := flow.lease.HandlePacket(buildIPv4TCP(t, []byte("QA504WIRE-0-abcd"), 101, tcpFlagACK|tcpFlagPSH).Raw, DirectionOutbound, flow.inject, nil); verdict != VerdictPass {
			t.Fatalf("unknown payload verdict = %d", verdict)
		}
		if got := flow.countContaining(webMarker); got != 0 {
			t.Fatalf("exclusion-only rule injected %d fakes for an unknown host, want 0", got)
		}
		if got := flow.countContaining(catchUnknownMarker); got != 2 {
			t.Fatalf("catch-all unknown fakes = %d, want the configured 2 (injected=%d)", got, len(flow.injected))
		}
		if got := flow.countContaining(catchTLSMarker); got != 0 {
			t.Fatalf("catch-all TLS fakes = %d, want 0 for an unknown protocol payload", got)
		}
		if flow.lease.tcpFlow.rule == nil || flow.lease.tcpFlow.rule.Name != "catch-all" {
			t.Fatalf("unknown-host flow selected %v, want catch-all", flow.lease.tcpFlow.rule)
		}
	})

	t.Run("known-allowed-host-keeps-earlier-exclusion-rule", func(t *testing.T) {
		flow := newHostlistFlow(t, config, netip.MustParseAddrPort("198.51.100.21:443"))
		if verdict := flow.lease.HandlePacket(buildIPv4TCP(t, nil, 200, tcpFlagSYN).Raw, DirectionOutbound, flow.inject, nil); verdict != VerdictPass {
			t.Fatalf("SYN verdict = %d", verdict)
		}
		hello := buildClientHello("allowed.example")
		if verdict := flow.lease.HandlePacket(buildIPv4TCP(t, hello, 201, tcpFlagACK|tcpFlagPSH).Raw, DirectionOutbound, flow.inject, nil); verdict != VerdictPass {
			t.Fatalf("ClientHello verdict = %d", verdict)
		}
		if got := flow.countContaining(webMarker); got != 3 {
			t.Fatalf("earlier exclusion-only rule fakes = %d, want the configured 3", got)
		}
		if got := flow.countContaining(catchTLSMarker); got != 0 {
			t.Fatalf("catch-all fakes = %d, want 0 once the allowed host rule wins", got)
		}
		if flow.lease.tcpFlow.rule == nil || flow.lease.tcpFlow.rule.Name != "web-host-exclude" {
			t.Fatalf("allowed-host flow selected %v, want web-host-exclude", flow.lease.tcpFlow.rule)
		}
	})

	t.Run("known-excluded-host-falls-through-to-catch-all", func(t *testing.T) {
		flow := newHostlistFlow(t, config, netip.MustParseAddrPort("198.51.100.22:443"))
		if verdict := flow.lease.HandlePacket(buildIPv4TCP(t, nil, 300, tcpFlagSYN).Raw, DirectionOutbound, flow.inject, nil); verdict != VerdictPass {
			t.Fatalf("SYN verdict = %d", verdict)
		}
		hello := buildClientHello("blocked.example")
		if verdict := flow.lease.HandlePacket(buildIPv4TCP(t, hello, 301, tcpFlagACK|tcpFlagPSH).Raw, DirectionOutbound, flow.inject, nil); verdict != VerdictPass {
			t.Fatalf("ClientHello verdict = %d", verdict)
		}
		if got := flow.countContaining(webMarker); got != 0 {
			t.Fatalf("excluded host still reached the web rule: %d fakes", got)
		}
		if got := flow.countContaining(catchTLSMarker); got != 2 {
			t.Fatalf("catch-all TLS fakes = %d, want the configured 2", got)
		}
		if flow.lease.tcpFlow.rule == nil || flow.lease.tcpFlow.rule.Name != "catch-all" {
			t.Fatalf("excluded-host flow selected %v, want catch-all", flow.lease.tcpFlow.rule)
		}
	})
}

// TestCapturedHighTCPUnknownHostSelectsCatchAll replays the exact QA504 raw
// packets of both operating systems through the real caller and requires the
// reference-equivalent selection: the any-protocol cutoff n4 rule and 22
// (11x4 B + 11x661 B) unknown fakes instead of the earlier web rule.
func TestCapturedHighTCPUnknownHostSelectsCatchAll(t *testing.T) {
	cases := []struct {
		platform string
		fixture  string
		sha256   string
	}{
		{"linux", qa504LinuxFixture, qa504LinuxSHA256},
		{"windows", qa504WindowsFixture, qa504WindowsSHA256},
	}
	for _, testCase := range cases {
		t.Run(testCase.platform, func(t *testing.T) {
			encoded, err := os.ReadFile(filepath.Join("testdata", "qa504", testCase.fixture))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(encoded)
			if got := hex.EncodeToString(sum[:]); got != testCase.sha256 {
				t.Fatalf("captured fixture sha256 = %s, want %s (packet content must not be rewritten)", got, testCase.sha256)
			}
			var packets []string
			if err = json.Unmarshal(encoded, &packets); err != nil {
				t.Fatal(err)
			}
			if len(packets) < 3 {
				t.Fatalf("captured fixture has %d packets, want the full QA504 sequence", len(packets))
			}
			dir := t.TempDir()
			writeHostlistFile(t, dir, "list-exclude.txt", pinnedHostlistExclude)
			// Corrected18 shape: the positive IP aggregate resolves to no
			// entries (submission16 compatibility) while the hostlist and IP
			// exclusions are nonempty.
			writeHostlistFile(t, dir, "ipset-all.txt", "")
			writeHostlistFile(t, dir, "ipset-exclude.txt", "10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16\n")
			fake661 := make([]byte, 661)
			for index := range fake661 {
				fake661[index] = 0x5a
			}
			if err = os.WriteFile(filepath.Join(dir, "fake661.bin"), fake661, 0o600); err != nil {
				t.Fatal(err)
			}
			rules := `[
				{"name":"rule-6","network":["tcp"],"port":[80,443,8443],
				 "domain_exclude_file":["list-exclude.txt"],
				 "ip_cidr_file":["ipset-all.txt"],"ip_cidr_exclude_file":["ipset-exclude.txt"],
				 "methods":["fake"],
				 "fake":{"repeats":11,"payloads":[{"protocol":"tls","hex":"00000000"}]}},
				{"name":"rule-7","network":["tcp"],"port_range":["1024-65535"],
				 "ip_cidr_file":["ipset-all.txt"],"ip_cidr_exclude_file":["ipset-exclude.txt"],
				 "cutoff":"n4","any_protocol":true,"methods":["fake"],
				 "fake":{"repeats":11,"payloads":[
					{"protocol":"unknown","hex":"00000000"},
					{"protocol":"unknown","file":"fake661.bin"}]}}]`
			config, err := Compile(enabledOption(`{"enabled":true,"rules":`+rules+`}`), dir)
			if err != nil {
				t.Fatal(err)
			}
			first, err := hex.DecodeString(packets[0])
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParsePacket(first)
			if err != nil {
				t.Fatal(err)
			}
			if !parsed.Dst.Is4() || parsed.Dst.String() != "1.1.1.1" || parsed.DstPort != 8443 {
				t.Fatalf("captured destination = %s:%d, want 1.1.1.1:8443", parsed.Dst, parsed.DstPort)
			}
			flow := newHostlistFlow(t, config, netip.AddrPortFrom(parsed.Dst, parsed.DstPort))
			sizes := make(map[int]int)
			injections := 0
			selected := ""
			payloadSeen := false
			for index, item := range packets {
				raw, decodeErr := hex.DecodeString(item)
				if decodeErr != nil {
					t.Fatalf("packet %d hex: %v", index, decodeErr)
				}
				packet, parseErr := ParsePacket(raw)
				if parseErr != nil {
					t.Fatalf("packet %d parse: %v", index, parseErr)
				}
				counted := func(replacement []byte) error {
					generated, buildErr := ParsePacket(replacement)
					if buildErr != nil {
						return buildErr
					}
					sizes[len(generated.Payload)]++
					injections++
					return nil
				}
				verdict := flow.lease.HandlePacket(raw, DirectionOutbound, counted, nil)
				if verdict != VerdictPass {
					t.Fatalf("packet %d verdict = %d", index, verdict)
				}
				if len(packet.Payload) > 0 && !payloadSeen {
					payloadSeen = true
					if flow.lease.tcpFlow.rule != nil {
						selected = flow.lease.tcpFlow.rule.Name
					}
				}
			}
			if !payloadSeen {
				t.Fatal("captured fixture carried no payload packet")
			}
			if selected != "rule-7" {
				t.Fatalf("unknown-host flow selected %q, want rule-7 (pinned native reference profile8)", selected)
			}
			if sizes[4] != 11 || sizes[661] != 11 || injections != 22 {
				t.Fatalf("fake multiplicity = %d packets %v, want 22 packets {4:11,661:11} as in the pinned reference", injections, sizes)
			}
		})
	}
}

// TestUnknownHostHostlistReachabilitySurvivesReload keeps the reload/last-good
// contract in the same scope: the published selection semantics follow the
// re-read lists and a failed reload leaves the last-good snapshot in force.
func TestUnknownHostHostlistReachabilitySurvivesReload(t *testing.T) {
	dir := t.TempDir()
	excludePath := writeHostlistFile(t, dir, "exclude.txt", pinnedHostlistExclude)
	config, err := Compile(enabledOption(`{"enabled":true,"rules":[
		{"name":"exclude-only","network":["tcp"],"port":[443],"domain_exclude_file":["exclude.txt"],
		 "methods":["fake"],"fake":{"repeats":1,"payloads":[{"protocol":"tls","hex":"00"}]}},
		{"name":"catch-all","network":["tcp"],"port_range":["1-65535"],"any_protocol":true,
		 "methods":["fake"],"fake":{"repeats":1,"payloads":[{"protocol":"unknown","hex":"00"}]}}]}`), dir)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	selected := func() string {
		t.Helper()
		facts := hostlistFacts("", false)
		facts.Port = 443
		for _, rule := range engine.Config().Rules {
			if rule.Matches(facts) {
				return rule.Name
			}
		}
		return ""
	}
	if got := selected(); got != "catch-all" {
		t.Fatalf("initial unknown-host selection = %q, want catch-all", got)
	}
	// An emptied exclusion list carries no entries, so pinned
	// hostlist_collection_is_empty stays true and the earlier rule wins again.
	writeHostlistFile(t, dir, "exclude.txt", "# reloaded, no entries\n")
	if err = engine.ReloadLists(); err != nil {
		t.Fatal(err)
	}
	if got := selected(); got != "exclude-only" {
		t.Fatalf("unknown-host selection after emptying the exclusion list = %q, want exclude-only", got)
	}
	// Restoring entries restores the pinned reachability gate.
	writeHostlistFile(t, dir, "exclude.txt", pinnedHostlistExclude)
	if err = engine.ReloadLists(); err != nil {
		t.Fatal(err)
	}
	if got := selected(); got != "catch-all" {
		t.Fatalf("unknown-host selection after restoring the exclusion list = %q, want catch-all", got)
	}
	// A failed reload must keep the last-good snapshot, not widen selection.
	if err = os.Remove(excludePath); err != nil {
		t.Fatal(err)
	}
	if err = engine.ReloadLists(); err == nil {
		t.Fatal("reload with a missing list file must fail")
	}
	if got := selected(); got != "catch-all" {
		t.Fatalf("unknown-host selection after a failed reload = %q, want the last-good catch-all", got)
	}
}

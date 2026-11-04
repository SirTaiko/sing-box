//go:build linux

package desync

// Offline MODEL only: delegates to the existing nftables model. No socket,
// socketpair, namespace switch, process/fork or product/network execution.
import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type fastpathEvent struct {
	Method       string
	Family       byte
	Type         uint16
	Table, Chain string
	Flags        netlink.HeaderFlags
	Batch        int
	Data         string
	Replies      []string
	Generation   uint32
}
type fastpathLedger struct {
	mu      sync.Mutex
	events  []fastpathEvent
	batches int
}

func (l *fastpathLedger) add(e fastpathEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}
func (l *fastpathLedger) trace(t *testing.T) {
	t.Helper()
	b, err := json.Marshal(l.events)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("MODEL request-attempt ledger: %s", b)
}
func (l *fastpathLedger) counts() (d, g, b, fixed int) {
	for _, e := range l.events {
		switch e.Method {
		case "dump":
			d++
		case "generation":
			g++
		case "batch":
			b++
		case "request":
			if e.Type&0xff == unix.NFT_MSG_NEWCHAIN && e.Table == anchorTableName && (e.Chain == anchorBaseInputName || e.Chain == anchorBaseOutputName) {
				fixed++
			}
		}
	}
	return
}

type fastpathSession struct {
	anchorSession
	ledger *fastpathLedger
}

// Preserve the existing optional in-memory cleanup transport as well; embedding
// only anchorSession would erase this capability and break ordinary Close.
func (s *fastpathSession) sendRaw(data []byte) error {
	return s.anchorSession.(rawNetlinkSession).sendRaw(data)
}
func (s *fastpathSession) recvRaw() ([]byte, *unix.SockaddrNetlink, error) {
	return s.anchorSession.(rawNetlinkSession).recvRaw()
}

func (s *fastpathSession) generation(f byte) (uint32, error) {
	g, err := s.anchorSession.generation(f)
	s.ledger.add(fastpathEvent{Method: "generation", Family: f, Generation: g})
	return g, err
}
func (s *fastpathSession) dump(typ uint16, f byte, attrs []netlink.Attribute) ([]nftReply, error) {
	table, _ := fakeAttrString(attrs, unix.NFTA_RULE_TABLE)
	chain, _ := fakeAttrString(attrs, unix.NFTA_RULE_CHAIN)
	rs, err := s.anchorSession.dump(typ, f, attrs)
	e := fastpathEvent{Method: "dump", Family: f, Type: typ, Table: table, Chain: chain}
	for _, r := range rs {
		e.Replies = append(e.Replies, hex.EncodeToString(r.data))
	}
	s.ledger.add(e)
	return rs, err
}
func (s *fastpathSession) batch(rs []nftRequest) ([]nftReply, error) {
	s.ledger.batches++
	id := s.ledger.batches
	s.ledger.add(fastpathEvent{Method: "batch", Batch: id})
	for _, r := range rs {
		f, attrs, err := nftMessageData(nftReply{data: r.data})
		if err != nil {
			return nil, err
		}
		table, _ := fakeAttrString(attrs, unix.NFTA_CHAIN_TABLE)
		chain := ""
		if r.typ&0xff == unix.NFT_MSG_NEWCHAIN {
			chain, _ = fakeAttrString(attrs, unix.NFTA_CHAIN_NAME)
		} else if r.typ&0xff == unix.NFT_MSG_NEWRULE || r.typ&0xff == unix.NFT_MSG_DELRULE {
			chain, _ = fakeAttrString(attrs, unix.NFTA_RULE_CHAIN)
		}
		s.ledger.add(fastpathEvent{Method: "request", Family: f, Type: r.typ, Table: table, Chain: chain, Flags: r.flags, Batch: id, Data: hex.EncodeToString(r.data)})
	}
	return s.anchorSession.batch(rs)
}

const fastpathEpoch = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

func fastpathFixture(t *testing.T, family Family, bases int) *fakeAnchorSession {
	t.Helper()
	name, f, _ := anchorFamilyNames(family)
	s := &fakeAnchorSession{namespace: newFakeNftNamespace(), port: 0x40000040}
	rs := []nftRequest{nftTableMessage(f, anchorTableName, nil), nftRegularChainMessage(f, anchorTableName, anchorMarkerChainName)}
	for _, u := range []string{anchorMarkerUserdata(name, fastpathEpoch), anchorTagUserdata(fastpathEpoch, uint64(anchorTagInitial))} {
		r, err := nftRuleMessage(f, anchorTableName, anchorMarkerChainName, nil, []byte(u))
		if err != nil {
			t.Fatal(err)
		}
		rs = append(rs, r)
	}
	for i, n := range []string{anchorBaseInputName, anchorBaseOutputName} {
		if bases&(1<<i) != 0 {
			hook := unix.NF_INET_LOCAL_IN
			if i == 1 {
				hook = unix.NF_INET_LOCAL_OUT
			}
			rs = append(rs, nftBaseChainMessage(f, anchorTableName, n, "filter", hook, anchorBaseHookPriority, []byte(anchorBaseUserdata(fastpathEpoch, n))))
		}
	}
	if _, err := s.batch(rs); err != nil {
		t.Fatal(err)
	}
	return s
}
func fastpathImage(n *fakeNftNamespace) *fakeNftNamespace {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.clone()
}

// FP01 intentionally uses ONLY Source39 API/types. Identical bytes must compile
// and functionally succeed on 39, then fail the NEW optimization budget.
func TestAnchorExistingFastpathWarmBudget(t *testing.T) {
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			s := fastpathFixture(t, family, 3)
			before := fastpathImage(s.namespace)
			for i := 0; i < 3; i++ {
				l := &fastpathLedger{}
				fresh := &fakeAnchorSession{namespace: s.namespace, port: uint32(0x40000040 + i)}
				err := ensureAnchorFamily(&fastpathSession{anchorSession: fresh, ledger: l}, family, true)
				if err != nil {
					t.Fatalf("MODEL functional ensure failed: %v", err)
				}
				t.Logf("MODEL functional ensure succeeded family=%d invocation=%d", family, i)
				l.trace(t)
				if !reflect.DeepEqual(before, fastpathImage(s.namespace)) {
					t.Fatal("warm ensure changed object bytes/handles/epoch/tag/generation")
				}
				d, g, b, fixed := l.counts()
				if d != 6 || g != 2 || b != 0 || fixed != 0 {
					t.Errorf("OPTIMIZATION-BUDGET RED: D/G/B=%d/%d/%d fixed-attempts=%d want 6/2/0 fixed=0", d, g, b, fixed)
				}
			}
		})
	}
}

// FP02: complete only missing fixed bases, preserving every surviving object.
func TestAnchorExistingFastpathCompletionMatrix(t *testing.T) {
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		for _, mask := range []int{-1, 0, 1, 2, 3} {
			for _, needCreate := range []bool{false, true} {
				t.Run(fmt.Sprintf("family%d/mask%d/create%v", family, mask, needCreate), func(t *testing.T) {
					_, f, _ := anchorFamilyNames(family)
					s := &fakeAnchorSession{namespace: newFakeNftNamespace(), port: 0x40000040}
					if mask >= 0 {
						s = fastpathFixture(t, family, mask)
					}
					before := fastpathImage(s.namespace)
					if mask >= 0 && mask != 3 {
						if _, err := readAnchorFamilyState(s, family); err == nil {
							t.Fatal("strict wrapper accepted missing base")
						}
					}
					l := &fastpathLedger{}
					err := ensureAnchorFamily(&fastpathSession{anchorSession: s, ledger: l}, family, needCreate)
					l.trace(t)
					if mask < 0 && !needCreate {
						if err == nil || !strings.Contains(err.Error(), "absent") {
							t.Fatalf("absent table precondition: %v", err)
						}
						d, g, b, fixed := l.counts()
						if d != 1 || g != 0 || b != 0 || fixed != 0 {
							t.Fatalf("absent precondition mutated: %d/%d/%d fixed%d", d, g, b, fixed)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					wantD, wantB := 6, 0
					var wantNames []string
					switch mask {
					case -1:
						wantD, wantB = 6, 3
						wantNames = []string{anchorBaseInputName, anchorBaseOutputName}
					case 0:
						wantD, wantB = 4, 2
						wantNames = []string{anchorBaseInputName, anchorBaseOutputName}
					case 1:
						wantD, wantB = 5, 1
						wantNames = []string{anchorBaseOutputName}
					case 2:
						wantD, wantB = 5, 1
						wantNames = []string{anchorBaseInputName}
					}
					d, g, b, fixed := l.counts()
					if d != wantD || g != 2 || b != wantB || fixed != len(wantNames) {
						t.Fatalf("recipe %d/%d/%d fixed%d, want %d/2/%d fixed%d", d, g, b, fixed, wantD, wantB, len(wantNames))
					}
					var names []string
					requestCounts := map[int]int{}
					for _, e := range l.events {
						if e.Method != "request" {
							continue
						}
						requestCounts[e.Batch]++
						if e.Type&0xff == unix.NFT_MSG_NEWCHAIN && (e.Chain == anchorBaseInputName || e.Chain == anchorBaseOutputName) {
							names = append(names, e.Chain)
							if e.Flags&netlink.Excl == 0 || e.Flags&netlink.Create == 0 {
								t.Fatal("fixed creation lost EXCL/CREATE")
							}
						}
						if mask < 0 && e.Batch == 1 && e.Type&0xff == unix.NFT_MSG_NEWCHAIN {
							_, as, parseErr := nftMessageData(nftReply{data: mustFastpathHex(t, e.Data)})
							if parseErr != nil {
								t.Fatal(parseErr)
							}
							if _, hook := nftAttrBytes(as, unix.NFTA_CHAIN_HOOK); hook {
								t.Fatal("initial atomic marker batch has a hook")
							}
						}
					}
					if !reflect.DeepEqual(names, wantNames) {
						t.Fatalf("fixed creation order %v want %v", names, wantNames)
					}
					for id, n := range requestCounts {
						want := 1
						if mask < 0 && id == 1 {
							want = 4
						}
						if n != want {
							t.Fatalf("batch%d has %d requests want%d", id, n, want)
						}
					}
					if mask < 0 {
						var types []uint16
						for _, e := range l.events {
							if e.Method == "request" && e.Batch == 1 {
								types = append(types, e.Type&0xff)
							}
						}
						if !reflect.DeepEqual(types, []uint16{unix.NFT_MSG_NEWTABLE, unix.NFT_MSG_NEWCHAIN, unix.NFT_MSG_NEWRULE, unix.NFT_MSG_NEWRULE}) {
							t.Fatalf("initial batch recipe: %v", types)
						}
					}
					after := fastpathImage(s.namespace)
					if mask >= 0 {
						for n, c := range before.tables[f][anchorTableName].chains {
							if !reflect.DeepEqual(c, after.tables[f][anchorTableName].chains[n]) {
								t.Fatalf("surviving object %s changed", n)
							}
						}
					}
					state, err := readAnchorFamilyState(s, family)
					if err != nil {
						t.Fatal(err)
					}
					if mask >= 0 && state.epoch != fastpathEpoch {
						t.Fatal("completion changed epoch")
					}
				})
			}
		}
	}
}
func mustFastpathHex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

// FP04: the GETCHAIN data really includes foreign colliding names. The model's
// usual table filtering alone would make this attribution test vacuous.
type fastpathAttributionSession struct {
	anchorSession
	foreign []nftReply
	flags   byte
}

func (s *fastpathAttributionSession) dump(typ uint16, f byte, attrs []netlink.Attribute) ([]nftReply, error) {
	rs, err := s.anchorSession.dump(typ, f, attrs)
	if err != nil || typ != unix.NFT_MSG_GETCHAIN {
		return rs, err
	}
	for i, r := range rs {
		_, as, e := nftMessageData(r)
		if e != nil {
			return nil, e
		}
		n, _ := fakeAttrString(as, unix.NFTA_CHAIN_NAME)
		if n != anchorBaseInputName && n != anchorBaseOutputName {
			continue
		}
		for j := range as {
			if as[j].Type&0x3fff == nftAttrChainFlags {
				as[j].Data = []byte{0, 0, 0, s.flags}
			}
		}
		b, e := netlink.MarshalAttributes(as)
		if e != nil {
			return nil, e
		}
		rs[i].data = append(nfgenmsg(f, 0), b...)
	}
	return append(rs, s.foreign...), nil
}
func TestAnchorExistingFastpathAttributionCompatibility(t *testing.T) {
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		for _, flags := range []byte{0, 1} {
			for _, mask := range []int{1, 3} {
				t.Run(fmt.Sprintf("family%d/flags%d/mask%d", family, flags, mask), func(t *testing.T) {
					s := fastpathFixture(t, family, mask)
					_, f, _ := anchorFamilyNames(family)
					// Positive grammar control: queue zero, canonical numbers, m without p.
					process, capture := "11111111111111111111111111111111", "cccccccccccccccccccccccccccccccc"
					m, err := nftRuleMessage(f, anchorTableName, anchorMarkerChainName, nil, []byte(anchorManifestUserdata(fastpathEpoch, process, capture, anchorQueuePorts{out: 0, in: 1, pidnsDev: 1, pidnsIno: 2, tgid: 3, startTicks: 4})))
					if err != nil {
						t.Fatal(err)
					}
					if _, err = s.batch([]nftRequest{m}); err != nil {
						t.Fatal(err)
					}
					complete := fastpathFreeze(t, fastpathFixture(t, family, 3), family)
					var foreign []nftReply
					for _, r := range complete.dumps[snapshotDumpKey(unix.NFT_MSG_GETCHAIN, nil)] {
						_, as, e := nftMessageData(r)
						if e != nil {
							t.Fatal(e)
						}
						n, _ := fakeAttrString(as, unix.NFTA_CHAIN_NAME)
						if n == anchorBaseInputName || n == anchorBaseOutputName {
							foreign = append(foreign, fastpathEditReply(t, r, func(as []netlink.Attribute) []netlink.Attribute {
								for i := range as {
									if as[i].Type&0x3fff == unix.NFTA_CHAIN_TABLE {
										as[i].Data = []byte("unrelated\x00")
									}
								}
								return as
							}))
						}
					}
					if len(foreign) != 2 {
						t.Fatal("foreign collision fixture empty")
					}
					foreignBefore := fmt.Sprintf("%#v", foreign)
					attributed := &fastpathAttributionSession{anchorSession: s, foreign: foreign, flags: flags}
					l := &fastpathLedger{}
					if err = ensureAnchorFamily(&fastpathSession{anchorSession: attributed, ledger: l}, family, true); err != nil {
						t.Fatal(err)
					}
					l.trace(t)
					_, _, b, fixed := l.counts()
					want := 0
					if mask == 1 {
						want = 1
					}
					if b != want || fixed != want {
						t.Fatalf("foreign name used as own presence: batches%d fixed%d want%d", b, fixed, want)
					}
					for _, e := range l.events {
						if e.Method == "request" && (e.Table != anchorTableName || e.Chain != anchorBaseOutputName) {
							t.Fatalf("mutated wrong identity: %+v", e)
						}
					}
					if fmt.Sprintf("%#v", foreign) != foreignBefore {
						t.Fatal("foreign bytes mutated")
					}
					state, err := readAnchorFamilyState(attributed, family)
					if err != nil {
						t.Fatal(err)
					}
					record := state.captures[captureKey(process, capture)]
					if record == nil || record.port != nil || record.record.ports.out != 0 {
						t.Fatal("metadata-only m/queue0 rejected or rewritten")
					}
				})
			}
		}
	}
}

// FP05: successful immutable generation/dump scripts only; not ACK loss,
// concurrent writer scheduling or recovery/fault injection.
func TestAnchorExistingFastpathCoherence(t *testing.T) {
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		for _, kind := range []string{"discard-absent", "discard-present", "three-changes", "invalid-immediate"} {
			t.Run(fmt.Sprintf("family%d/%s", family, kind), func(t *testing.T) {
				stableMask, firstMask := 3, 0
				if kind == "discard-present" {
					stableMask, firstMask = 0, 3
				}
				stable := fastpathFixture(t, family, stableMask)
				first := fastpathFreeze(t, fastpathFixture(t, family, firstMask), family)
				first.anchorSession = stable
				first.next = fastpathFreeze(t, stable, family)
				first.generations = []uint32{1, 2, 3, 3}
				if kind == "three-changes" {
					first.generations = []uint32{1, 2, 3, 4, 5, 6}
				}
				if kind == "invalid-immediate" {
					first.generations = []uint32{1}
					key := snapshotDumpKey(unix.NFT_MSG_GETCHAIN, nil)
					first.dumps[key] = append(first.dumps[key], first.dumps[key][0])
				}
				before := fakeAnchorFingerprint(stable.namespace)
				l := &fastpathLedger{}
				err := ensureAnchorFamily(&fastpathSession{anchorSession: first, ledger: l}, family, true)
				l.trace(t)
				_, g, b, fixed := l.counts()
				switch kind {
				case "three-changes":
					if err == nil || !strings.Contains(err.Error(), "generation changed") || g != 6 || b != 0 || fixed != 0 || before != fakeAnchorFingerprint(stable.namespace) {
						t.Fatalf("three-attempt bound: err=%v G/B/fixed=%d/%d/%d", err, g, b, fixed)
					}
				case "invalid-immediate":
					if err == nil || !strings.Contains(err.Error(), "duplicate anchor chain") || g != 1 || b != 0 || fixed != 0 {
						t.Fatalf("invalid data retried: err=%v G/B/fixed=%d/%d/%d", err, g, b, fixed)
					}
				default:
					want := 0
					if stableMask == 0 {
						want = 2
					}
					if err != nil || g != 4 || b != want || fixed != want {
						t.Fatalf("stable decision: err=%v G/B/fixed=%d/%d/%d want4/%d/%d", err, g, b, fixed, want, want)
					}
					seenGenerations := 0
					for _, e := range l.events {
						if e.Method == "generation" {
							seenGenerations++
						}
						if e.Method == "batch" && seenGenerations != 4 {
							t.Fatal("mutation before coherent snapshot")
						}
					}
					if want == 0 && before != fakeAnchorFingerprint(stable.namespace) {
						t.Fatal("discarded absence caused writes")
					}
					if _, err := readAnchorFamilyState(stable, family); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}

// FP06: actual production open composition over the existing closed MODEL
// seams. Cold and later warm success retain independent strict/o/w/final reads.
func TestAnchorExistingFastpathSuccessfulComposition(t *testing.T) {
	seams := installLinuxCaptureSeams(t, nil)
	previous := openAnchorSession
	l := &fastpathLedger{}
	openAnchorSession = func() (anchorSession, error) {
		s, err := previous()
		if err != nil {
			return nil, err
		}
		return &fastpathSession{anchorSession: s, ledger: l}, nil
	}
	t.Cleanup(func() { openAnchorSession = previous })
	for _, warm := range []bool{false, true} {
		l.events = nil
		l.batches = 0
		engine, lease := newForkDefaultLease(t)
		if err := lease.StartCapture(); err != nil {
			t.Fatal(err)
		}
		c := lease.capture.(*linuxCapture)
		if !c.outWitnessed || !c.started {
			t.Fatal("capture did not publish witness/start")
		}
		l.trace(t)
		d, g, b, fixed := l.counts()
		t.Logf("MODEL successful composition warm=%v D/G/B=%d/%d/%d fixed-attempts=%d", warm, d, g, b, fixed)
		wantFixed := 4
		if warm {
			wantFixed = 0
		}
		if fixed != wantFixed {
			t.Fatalf("warm%v fixed attempts%d want%d", warm, fixed, wantFixed)
		}
		// Ordinary no-retry IPv4 default, two queues: exact production recipe.
		wantD, wantG, wantB := 49, 18, 3
		if !warm {
			wantD, wantG, wantB = 49, 18, 9
		}
		// Cold includes initial table marker validation but lacks two base-rule dumps
		// per family in the bootstrap snapshot: those cancel in dump count.
		if d != wantD || g != wantG || b != wantB {
			t.Fatalf("MODEL warm%v D/G/B=%d/%d/%d want%d/%d/%d", warm, d, g, b, wantD, wantG, wantB)
		}
		familyGenerations := map[byte]int{}
		for _, e := range l.events {
			if e.Method == "generation" {
				familyGenerations[e.Family]++
			}
		}
		if familyGenerations[unix.NFPROTO_IPV4] != 12 || familyGenerations[unix.NFPROTO_IPV6] != 6 {
			t.Fatalf("lost both-family/strict/o/w/final reads: %v", familyGenerations)
		}
		for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
			s := &fakeAnchorSession{namespace: seams.anchors, port: 0x40000042}
			if _, err := readAnchorFamilyState(s, family); err != nil {
				t.Fatal(err)
			}
		}
		for i := 0; i < 2; i++ {
			if err := lease.Close(nil); err != nil {
				t.Fatal(err)
			}
			if err := lease.WaitCaptureRetired(); err != nil {
				t.Fatal(err)
			}
			if err := engine.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// Immutable successful wire inputs, not transport faults or a concurrent writer.
type fastpathStaticSession struct {
	anchorSession
	dumps           map[string][]nftReply
	generations     []uint32
	generationReads int
	next            *fastpathStaticSession
}

func (s *fastpathStaticSession) dump(typ uint16, f byte, attrs []netlink.Attribute) ([]nftReply, error) {
	chosen := s
	if s.next != nil && s.generationReads >= 3 {
		chosen = s.next
	}
	return chosen.dumps[snapshotDumpKey(typ, attrs)], nil
}
func (s *fastpathStaticSession) generation(byte) (uint32, error) {
	s.generationReads++
	if len(s.generations) > 0 {
		return s.generations[s.generationReads-1], nil
	}
	return 7, nil
}
func fastpathFreeze(t *testing.T, s *fakeAnchorSession, family Family) *fastpathStaticSession {
	t.Helper()
	_, f, _ := anchorFamilyNames(family)
	out := &fastpathStaticSession{anchorSession: s, dumps: map[string][]nftReply{}}
	for _, typ := range []uint16{unix.NFT_MSG_GETTABLE, unix.NFT_MSG_GETCHAIN, unix.NFT_MSG_GETRULE} {
		chains := []string{""}
		if typ == unix.NFT_MSG_GETRULE {
			chains = []string{anchorMarkerChainName, anchorBaseInputName, anchorBaseOutputName}
		}
		for _, chain := range chains {
			attrs := []netlink.Attribute{{Type: unix.NFTA_RULE_TABLE, Data: []byte(anchorTableName + "\x00")}}
			if chain != "" {
				attrs = append(attrs, netlink.Attribute{Type: unix.NFTA_RULE_CHAIN, Data: []byte(chain + "\x00")})
			}
			rs, err := s.dump(typ, f, attrs)
			if err != nil {
				t.Fatal(err)
			}
			out.dumps[snapshotDumpKey(typ, attrs)] = rs
		}
	}
	return out
}
func fastpathEditReply(t *testing.T, r nftReply, edit func([]netlink.Attribute) []netlink.Attribute) nftReply {
	t.Helper()
	f, as, err := nftMessageData(r)
	if err != nil {
		t.Fatal(err)
	}
	as = edit(as)
	// Decoded attributes retain their old Length. Recompute it after editing
	// data, or a one-byte malformed flag would become padded four-byte data.
	for i := range as {
		as[i].Length = 0
	}
	data, err := netlink.MarshalAttributes(as)
	if err != nil {
		t.Fatal(err)
	}
	r.data = append(nfgenmsg(f, 0), data...)
	return r
}
func fastpathEditChain(t *testing.T, s *fastpathStaticSession, name string, edit func([]netlink.Attribute) []netlink.Attribute) {
	t.Helper()
	key := snapshotDumpKey(unix.NFT_MSG_GETCHAIN, nil)
	for i, r := range s.dumps[key] {
		_, as, err := nftMessageData(r)
		if err != nil {
			t.Fatal(err)
		}
		n, _ := fakeAttrString(as, unix.NFTA_CHAIN_NAME)
		if n == name {
			s.dumps[key][i] = fastpathEditReply(t, r, edit)
			return
		}
	}
	t.Fatalf("fixture chain %s missing", name)
}

// FP03: fixtures are finalized before ensure; no injected ACK or syscall errors.
func TestAnchorExistingFastpathRejectsBeforeWrite(t *testing.T) {
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		for _, kind := range []string{"missing-marker", "marker-flags", "missing-a", "missing-t", "bad-grammar", "mixed-epoch", "duplicate-chain", "unknown-chain", "orphan-chain", "ambiguous-token", "base-hook", "base-priority", "base-type", "base-policy", "base-userdata", "base-flags", "missing-input-invalid-output", "missing-output-invalid-input", "base-rule", "malformed-flags", "duplicate-flags", "missing-table-identity", "duplicate-table-identity", "target-family"} {
			t.Run(fmt.Sprintf("family%d/%s", family, kind), func(t *testing.T) {
				mask := 3
				if kind == "missing-input-invalid-output" {
					mask = 2
				}
				if kind == "missing-output-invalid-input" {
					mask = 1
				}
				s := fastpathFixture(t, family, mask)
				_, f, _ := anchorFamilyNames(family)
				table := s.namespace.tableLocked(f, anchorTableName)
				base := table.chains[anchorBaseOutputName]
				switch kind {
				case "missing-marker":
					delete(table.chains, anchorMarkerChainName)
				case "marker-flags":
					table.chains[anchorMarkerChainName].flags = 1
				case "missing-a":
					table.chains[anchorMarkerChainName].rules = table.chains[anchorMarkerChainName].rules[1:]
				case "missing-t":
					table.chains[anchorMarkerChainName].rules = table.chains[anchorMarkerChainName].rules[:1]
				case "bad-grammar":
					table.chains[anchorMarkerChainName].rules[1].userdata = []byte("sbds:1:t:" + fastpathEpoch + ":01")
				case "mixed-epoch":
					table.chains[anchorMarkerChainName].rules[1].userdata = []byte(anchorTagUserdata("dddddddddddddddddddddddddddddddd", uint64(anchorTagInitial)))
				case "unknown-chain":
					table.chains["unknown"] = &fakeNftChain{name: "unknown"}
				case "orphan-chain":
					n := anchorChainPrefix + "cccccccccccccccccccccccccccccccc_o"
					table.chains[n] = &fakeNftChain{name: n}
				case "ambiguous-token":
					for _, p := range []string{"11111111111111111111111111111111", "22222222222222222222222222222222"} {
						table.chains[anchorMarkerChainName].rules = append(table.chains[anchorMarkerChainName].rules, &fakeNftRule{handle: uint64(200 + len(table.chains[anchorMarkerChainName].rules)), userdata: []byte(anchorManifestUserdata(fastpathEpoch, p, "cccccccccccccccccccccccccccccccc", anchorQueuePorts{out: 0, in: 1, pidnsDev: 1, pidnsIno: 2, tgid: 3, startTicks: 4}))})
					}
				case "base-hook":
					base.hooknum = unix.NF_INET_LOCAL_IN
				case "base-priority":
					base.priority++
				case "base-type":
					base.kind = "route"
				case "base-policy":
					base.policy = 0
				case "base-userdata":
					base.userdata = []byte(anchorBaseUserdata("dddddddddddddddddddddddddddddddd", anchorBaseOutputName))
				case "base-flags", "missing-input-invalid-output":
					base.flags = 2
				case "missing-output-invalid-input":
					table.chains[anchorBaseInputName].flags = 2
				case "base-rule":
					base.rules = []*fakeNftRule{{handle: 300}}
				}
				frozen := fastpathFreeze(t, s, family)
				key := snapshotDumpKey(unix.NFT_MSG_GETCHAIN, nil)
				switch kind {
				case "duplicate-chain":
					frozen.dumps[key] = append(frozen.dumps[key], frozen.dumps[key][0])
				case "malformed-flags", "duplicate-flags", "missing-table-identity", "duplicate-table-identity":
					fastpathEditChain(t, frozen, anchorBaseOutputName, func(as []netlink.Attribute) []netlink.Attribute {
						switch kind {
						case "malformed-flags":
							for i := range as {
								if as[i].Type&0x3fff == nftAttrChainFlags {
									as[i].Data = []byte{1}
								}
							}
						case "duplicate-flags":
							as = append(as, netlink.Attribute{Type: nftAttrChainFlags, Data: []byte{0, 0, 0, 1}})
						case "missing-table-identity":
							var keep []netlink.Attribute
							for _, a := range as {
								if a.Type&0x3fff != unix.NFTA_CHAIN_TABLE {
									keep = append(keep, a)
								}
							}
							as = keep
						case "duplicate-table-identity":
							as = append(as, netlink.Attribute{Type: unix.NFTA_CHAIN_TABLE, Data: []byte(anchorTableName + "\x00")})
						}
						return as
					})
				case "target-family":
					rs := frozen.dumps[key]
					rs[0].data = append([]byte(nil), rs[0].data...)
					rs[0].data[0] = byte(unix.NFPROTO_INET)
				}
				before := fakeAnchorFingerprint(s.namespace)
				l := &fastpathLedger{}
				err := ensureAnchorFamily(&fastpathSession{anchorSession: frozen, ledger: l}, family, true)
				l.trace(t)
				if err == nil {
					t.Fatal("static invalid snapshot accepted")
				}
				want := map[string]string{
					"missing-marker": "marker chain is absent", "marker-flags": "carries flags",
					"missing-a": "a/t record pair", "missing-t": "a/t record pair", "bad-grammar": "non-canonical numeric",
					"mixed-epoch": "epoch mismatch", "duplicate-chain": "duplicate anchor chain", "unknown-chain": "unknown anchor chain",
					"orphan-chain": "has no manifest", "ambiguous-token": "ambiguous capture token", "base-hook": "no matching hook",
					"base-priority": "has priority", "base-type": "not a filter chain", "base-policy": "not accept", "base-userdata": "foreign userdata",
					"base-flags": "hardware offloaded", "missing-input-invalid-output": "hardware offloaded", "missing-output-invalid-input": "hardware offloaded",
					"base-rule": "untagged rule", "malformed-flags": "want 4", "duplicate-flags": "duplicate NFTA_CHAIN_FLAGS",
					"missing-table-identity": "without a table identity", "duplicate-table-identity": "duplicate nftables table identity", "target-family": "has family",
				}[kind]
				if want == "" || !strings.Contains(err.Error(), want) {
					t.Fatalf("fixture %s expected semantic category %q, got %v", kind, want, err)
				}
				t.Logf("MODEL fixture=%s semantic rejection=%v", kind, err)
				_, _, b, fixed := l.counts()
				if b != 0 || fixed != 0 || fakeAnchorFingerprint(s.namespace) != before {
					t.Fatal("invalid snapshot caused a premature write")
				}
			})
		}
	}
}

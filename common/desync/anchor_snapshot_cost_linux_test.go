//go:build linux

package desync

// Pure offline snapshot validation/benchmarks. All dumps below are immutable
// in-memory wire records. No socket, namespace, process or packet operation.
import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type offlineAnchorSnapshot struct {
	*fakeAnchorSession
	dumps           map[string][]nftReply
	generationReads int
	changing        bool
}

func snapshotDumpKey(typ uint16, attrs []netlink.Attribute) string {
	chain, _ := fakeAttrString(attrs, unix.NFTA_RULE_CHAIN)
	return fmt.Sprintf("%d/%s", typ, chain)
}
func (s *offlineAnchorSnapshot) dump(typ uint16, f byte, attrs []netlink.Attribute) ([]nftReply, error) {
	r, ok := s.dumps[snapshotDumpKey(typ, attrs)]
	if !ok {
		return nil, fmt.Errorf("MODEL: unexpected dump")
	}
	return r, nil
}
func (s *offlineAnchorSnapshot) generation(byte) (uint32, error) {
	s.generationReads++
	if s.changing {
		return uint32(s.generationReads), nil
	}
	return 7, nil
}

func source37Snapshot(tb testing.TB, n int) (*fakeAnchorSession, string) {
	tb.Helper()
	s := &fakeAnchorSession{namespace: newFakeNftNamespace(), port: 0x40000035}
	epoch := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	req := []nftRequest{nftTableMessage(2, anchorTableName, nil), nftRegularChainMessage(2, anchorTableName, anchorMarkerChainName)}
	addRule := func(chain string, userdata string) {
		r, err := nftRuleMessage(2, anchorTableName, chain, nil, []byte(userdata))
		if err != nil {
			tb.Fatal(err)
		}
		req = append(req, r)
	}
	addRule(anchorMarkerChainName, anchorMarkerUserdata("ip", epoch))
	addRule(anchorMarkerChainName, anchorTagUserdata(epoch, uint64(anchorTagInitial)+uint64(n)+1))
	req = append(req, nftBaseChainMessage(2, anchorTableName, anchorBaseInputName, "filter", int(unix.NF_INET_LOCAL_IN), anchorBaseHookPriority, []byte(anchorBaseUserdata(epoch, anchorBaseInputName))), nftBaseChainMessage(2, anchorTableName, anchorBaseOutputName, "filter", int(unix.NF_INET_LOCAL_OUT), anchorBaseHookPriority, []byte(anchorBaseUserdata(epoch, anchorBaseOutputName))))
	for i := 0; i < n; i++ {
		p, c := fmt.Sprintf("%032x", i+1), fmt.Sprintf("%032x", i+100000)
		ports := anchorQueuePorts{out: uint16(i * 3), in: uint16(i*3 + 1), icmp: uint16(i*3 + 2), icmpSet: true, pidnsDev: 1, pidnsIno: 2, tgid: uint64(i + 1), startTicks: 99}
		addRule(anchorMarkerChainName, anchorManifestUserdata(epoch, p, c, ports))
		u, err := anchorPortUserdata(epoch, p, c, uint32(0x80000001+i), "w", uint32(anchorTagInitial)+uint32(i))
		if err != nil {
			tb.Fatal(err)
		}
		addRule(anchorMarkerChainName, u)
		// A valid detached/retiring snapshot: m+p and regular chains remain;
		// no base entry may still enqueue traffic.
		for _, role := range []string{"o", "i", "e"} {
			req = append(req, nftRegularChainMessage(2, anchorTableName, anchorChainPrefix+c+"_"+role))
		}
	}
	if _, err := s.batch(req); err != nil {
		tb.Fatal(err)
	}
	return s, epoch
}
func source37ImmutableSnapshot(tb testing.TB, n int) *offlineAnchorSnapshot {
	tb.Helper()
	s, _ := source37Snapshot(tb, n)
	frozen := &offlineAnchorSnapshot{fakeAnchorSession: s, dumps: make(map[string][]nftReply)}
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
			r, err := s.dump(typ, 2, attrs)
			if err != nil {
				tb.Fatal(err)
			}
			frozen.dumps[snapshotDumpKey(typ, attrs)] = r
		}
	}
	return frozen
}

func TestSource37SnapshotTokenValidation(t *testing.T) {
	for _, kind := range []string{"valid", "duplicate-token", "unknown-token", "generation-change"} {
		t.Run(kind, func(t *testing.T) {
			s, epoch := source37Snapshot(t, 2)
			if kind == "duplicate-token" {
				p, c := "ffffffffffffffffffffffffffffffff", fmt.Sprintf("%032x", 100000)
				r, err := nftRuleMessage(2, anchorTableName, anchorMarkerChainName, nil, []byte(anchorManifestUserdata(epoch, p, c, anchorQueuePorts{out: 16000, in: 16001, pidnsDev: 1, pidnsIno: 2, tgid: 900, startTicks: 99})))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.batch([]nftRequest{r}); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "unknown-token" {
				if _, err := s.batch([]nftRequest{nftRegularChainMessage(2, anchorTableName, anchorChainPrefix+"cccccccccccccccccccccccccccccccc_o")}); err != nil {
					t.Fatal(err)
				}
			}
			var session anchorSession = s
			if kind == "generation-change" {
				f := source37ImmutableSnapshot(t, 2)
				f.changing = true
				session = f
			}
			state, err := readAnchorFamilyState(session, FamilyIPv4)
			if kind == "valid" {
				if err != nil || len(state.captures) != 2 || len(state.chains) != 2 {
					t.Fatalf("MODEL valid snapshot: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("MODEL: %s snapshot accepted", kind)
			}
		})
	}
}

func BenchmarkSource37Snapshot(b *testing.B) {
	for _, n := range []int{1, 64, 512, 2048} {
		b.Run(fmt.Sprintf("captures-%d", n), func(b *testing.B) {
			s := source37ImmutableSnapshot(b, n)
			if state, err := readAnchorFamilyState(s, FamilyIPv4); err != nil || len(state.captures) != n || len(state.chains) != n {
				b.Fatalf("invalid benchmark input: %v", err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				state, err := readAnchorFamilyState(s, FamilyIPv4)
				if err != nil || len(state.chains) != n {
					b.Fatal(err)
				}
			}
		})
	}
}

// Parser/control costs only, not Recvfrom/Receive nor whole CPU performance.
func BenchmarkSource37DatagramParse(b *testing.B) {
	for _, n := range []int{127, 4095, 65535} {
		b.Run(fmt.Sprintf("bytes-%d", n), func(b *testing.B) {
			data := nativeQueueDatagram(n, 42)
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m, err := parseNetlinkDatagram(data)
				if err != nil || len(m) != 1 || len(m[0].Data) != n-16 {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestSource37OfflineDatagramOwnership(t *testing.T) {
	fixture, err := os.ReadFile("testdata/native-nfq-packet127.bin")
	if err != nil {
		t.Fatal(err)
	}
	if len(fixture) != 127 {
		t.Fatal("wrong immutable fixture")
	}
	scratch := append([]byte(nil), fixture...)
	held, err := parseNetlinkDatagram(scratch)
	if err != nil {
		t.Fatal(err)
	}
	for i := range scratch {
		scratch[i] = 0
	}
	if !bytes.Equal(held[0].Data, fixture[16:]) {
		t.Fatal("MODEL: held message aliases scratch")
	}
	for _, n := range []int{16, 17, 18, 19, 127, 65535} {
		data := nativeQueueDatagram(n, byte(n))
		m, err := parseNetlinkDatagram(data)
		if err != nil || len(m) != 1 || !bytes.Equal(m[0].Data, data[16:]) {
			t.Fatalf("valid %d: %v", n, err)
		}
	}
	for _, data := range [][]byte{nil, fixture[:126], append(append([]byte(nil), fixture...), 0, 0), make([]byte, 16)} {
		if _, err := parseNetlinkDatagram(data); err == nil {
			t.Fatal("MODEL: malformed/truncated/padding accepted")
		}
	}
	// Decoding a later datagram cannot change an already decoded packet id.
	before := binary.BigEndian.Uint32(held[0].Data[8:12])
	if _, err := parseNetlinkDatagram(nativeQueueDatagram(127, 0xff)); err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(held[0].Data[8:12]) != before {
		t.Fatal("MODEL: packet id changed")
	}
}

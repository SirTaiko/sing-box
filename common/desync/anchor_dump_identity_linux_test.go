//go:build linux

package desync

// Permanent regression for QA622-FOREIGN-CHAIN-DUMP (submission34).
//
// Provenance of the captured fixtures
// -----------------------------------
//   - Captured by the independent QA622 attribution run (artifact t_fd57936f,
//     lab/linux/attribution/{ip,ip6}-exact-request-dump.log) on the target
//     Ubuntu 6.8.0-146-generic (6.8.12) kernel, in the ordinary deployment
//     namespace, with the uninstrumented candidate33 smoke binary
//     sha256 405a192b57af7b5c0c7eb7b6bb6fe311186aea65e25a55a13624fdb4af8bbf9f.
//   - Each family has one 484-byte NFNL_SUBSYS_NFTABLES datagram carrying the
//     four NFT_MSG_NEWCHAIN replies of the real GETCHAIN dump (sb_desync
//     __sbds_v1/input/output plus the unrelated qa622_attribution/output), and
//     the 20-byte NLMSG_DONE of the same sequence. The request datagram is the
//     exact GETCHAIN DUMP production emits.
//   - The unrelated table attribute is explicit in the kernel bytes
//     ("qa622_attribution" appears verbatim), which is exactly the native
//     observation: the target kernel's GETCHAIN dump filters only by family
//     (nf_tables_dump_chains compares nfmsg->nfgen_family with table->family)
//     and ignores the requested NFTA_CHAIN_TABLE, so readAnchorChains received
//     a foreign chain and attributed it to the requested anchor table. Both
//     product processes failed activation with
//     `duplicate anchor chain "output"` before any queue original was touched.
//   - These are model tests: the captured bytes drive the production
//     dump -> readAnchorChains -> validator path. No kernel object, queue,
//     packet or network is used. The unrelated table is replayed data only; no
//     foreign object is created, mutated or deleted here.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strings"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	// qa622AttributionTable is the unrelated regular table of the native
	// attribution. Its chain is named "output", i.e. it collides with the
	// fixed output base chain without sharing the anchor table.
	qa622AttributionTable = "qa622_attribution"

	// The request/two-reply datagrams are verbatim from the QA622 attribution.
	qa622IpRequest  = "24000000040a01030100000000000000020000000e00010073625f646573796e63000000"
	qa622IpDump     = "48000000030a020001000000680c0040020015e40e00010073625f646573796e630000000e0003005f5f736264735f76310000000c00020000000000000000010800060000000002a8000000030a020001000000680c0040020015e40e00010073625f646573796e630000000a000300696e7075740000000c000200000000000000000414000400080001000000000108000200ffffff6a08000500000000010b00070066696c746572000008000a0000000001080006000000000033000c00736264733a313a623a31383466376134633864653735316462643231363864303862393035613863643a696e70757400a8000000030a020001000000680c0040020015e40e00010073625f646573796e630000000b0003006f757470757400000c000200000000000000000514000400080001000000000308000200ffffff6a08000500000000010b00070066696c746572000008000a0000000001080006000000000034000c00736264733a313a623a31383466376134633864653735316462643231363864303862393035613863643a6f75747075744c000000030a020001000000680c0040020015e41600010071613632325f6174747269627574696f6e0000000b0003006f757470757400000c00020000000000000000010800060000000000"
	qa622IpDone     = "140000000300020001000000680c004000000000"
	qa622Ip6Request = "24000000040a010301000000000000000a0000000e00010073625f646573796e63000000"
	qa622Ip6Dump    = "48000000030a020001000000680c00400a0015f50e00010073625f646573796e630000000e0003005f5f736264735f76310000000c00020000000000000000010800060000000002a8000000030a020001000000680c00400a0015f50e00010073625f646573796e630000000a000300696e7075740000000c000200000000000000000414000400080001000000000108000200ffffff6a08000500000000010b00070066696c746572000008000a0000000001080006000000000033000c00736264733a313a623a31636631316233393766383238376333353666646233653134633331343037383a696e70757400a8000000030a020001000000680c00400a0015f50e00010073625f646573796e630000000b0003006f757470757400000c000200000000000000000514000400080001000000000308000200ffffff6a08000500000000010b00070066696c746572000008000a0000000001080006000000000034000c00736264733a313a623a31636631316233393766383238376333353666646233653134633331343037383a6f75747075744c000000030a020001000000680c00400a0015f51600010071613632325f6174747269627574696f6e0000000b0003006f757470757400000c00020000000000000000010800060000000000"
	qa622Ip6Done    = "140000000300020001000000680c004000000000"
	// qa622Port is the bound metadata port of the captured replies and
	// qa622Seq the dump sequence the probe used.
	qa622Port = uint32(1073745000)
	qa622Seq  = uint32(1)
)

// qa622NativeSession replays one captured both-family dump exactly once.
func qa622NativeSession(t *testing.T, dump, done string) (*nftScriptedDatagram, *nftNetlink) {
	t.Helper()
	scripted := &nftScriptedDatagram{steps: []nftScriptedRecv{
		nftScriptedDatagramStep(t, dump, nftKernelPeer()),
		nftScriptedDatagramStep(t, done, nftKernelPeer()),
	}}
	return scripted, newNftScriptedSession(qa622Port, qa622Seq-1, scripted)
}

// qa622Fixture is one captured family.
type qa622Fixture struct {
	name       string
	family     byte
	familyName string
	request    string
	dump       string
	done       string
}

func qa622Fixtures() []qa622Fixture {
	return []qa622Fixture{
		{name: "ip", family: byte(unix.NFPROTO_IPV4), familyName: "ip", request: qa622IpRequest, dump: qa622IpDump, done: qa622IpDone},
		{name: "ip6", family: byte(unix.NFPROTO_IPV6), familyName: "ip6", request: qa622Ip6Request, dump: qa622Ip6Dump, done: qa622Ip6Done},
	}
}

// qa622OwnChainNames is the exact own chain set of both captured dumps.
func qa622OwnChainNames() []string {
	names := []string{anchorBaseInputName, anchorBaseOutputName, anchorMarkerChainName}
	sort.Strings(names)
	return names
}

// TestAnchorForeignTableChainDumpIsNotAdopted replays the authentic both-family
// QA622 dump: only the chains of the requested own table may be returned, the
// unrelated table's "output" chain must not be recorded as an anchor chain, and
// the production request must still be the captured GETCHAIN DUMP shape.
func TestAnchorForeignTableChainDumpIsNotAdopted(t *testing.T) {
	for _, fixture := range qa622Fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			captured := mustNftBytes(t, fixture.dump)
			// Non-vacuity: the replayed kernel bytes themselves name the
			// unrelated table; the fixture would prove nothing otherwise.
			if !bytes.Contains(captured, []byte(qa622AttributionTable)) {
				t.Fatalf("captured dump does not carry the unrelated table")
			}
			scripted, session := qa622NativeSession(t, fixture.dump, fixture.done)
			chains, err := readAnchorChains(session, fixture.family, anchorTableName)
			if err != nil {
				t.Fatalf("native chain dump: %v", err)
			}
			if len(scripted.steps) != 0 {
				t.Fatalf("unread native reply steps = %d", len(scripted.steps))
			}
			names := make([]string, 0, len(chains))
			for _, chain := range chains {
				if chain.table != anchorTableName {
					t.Fatalf("chain %q recorded under table %q, want %q", chain.name, chain.table, anchorTableName)
				}
				if chain.family != fixture.family {
					t.Fatalf("chain %q family = %d, want %d", chain.name, chain.family, fixture.family)
				}
				names = append(names, chain.name)
			}
			sort.Strings(names)
			if strings.Join(names, ",") != strings.Join(qa622OwnChainNames(), ",") {
				t.Fatalf("selected own chains = %v, want %v", names, qa622OwnChainNames())
			}
			// The production request is byte-identical to the qualified
			// captured GETCHAIN DUMP apart from its own sequence and port.
			if len(scripted.sends) != 1 {
				t.Fatalf("sent dump datagrams = %d, want 1", len(scripted.sends))
			}
			sent := scripted.sends[0]
			request := mustNftBytes(t, fixture.request)
			if len(sent) != len(request) {
				t.Fatalf("dump request length = %d, want %d", len(sent), len(request))
			}
			if !bytes.Equal(sent[4:8], request[4:8]) || !bytes.Equal(sent[16:], request[16:]) {
				t.Fatalf("dump request differs from the captured shape:\nsent     %s\ncaptured %s",
					hex.EncodeToString(sent), fixture.request)
			}
			// Selection is driven by the returned identity, not by a
			// hard-coded anchor table name: asking for the unrelated table
			// returns exactly that chain.
			_, foreignSession := qa622NativeSession(t, fixture.dump, fixture.done)
			foreign, err := readAnchorChains(foreignSession, fixture.family, qa622AttributionTable)
			if err != nil {
				t.Fatalf("unrelated table readback: %v", err)
			}
			if len(foreign) != 1 || foreign[0].table != qa622AttributionTable || foreign[0].name != anchorBaseOutputName {
				t.Fatalf("unrelated table selection = %+v, want one %q/%q record",
					foreign, qa622AttributionTable, anchorBaseOutputName)
			}
		})
	}
}

// TestAnchorForeignTableDumpKeepsStrictOwnShape runs the unchanged production
// validators over the selected own records of both captured families: the
// intrinsic base flag, the fixed hook/priority/policy/type and the epoch
// userdata must all still be accepted, while any deviation is still refused.
func TestAnchorForeignTableDumpKeepsStrictOwnShape(t *testing.T) {
	hooks := map[string]uint32{
		anchorBaseInputName:  uint32(unix.NF_INET_LOCAL_IN),
		anchorBaseOutputName: uint32(unix.NF_INET_LOCAL_OUT),
	}
	for _, fixture := range qa622Fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			_, session := qa622NativeSession(t, fixture.dump, fixture.done)
			chains, err := readAnchorChains(session, fixture.family, anchorTableName)
			if err != nil {
				t.Fatalf("native chain dump: %v", err)
			}
			byName := make(map[string]nftChainRecord, len(chains))
			for _, chain := range chains {
				byName[chain.name] = chain
			}
			marker, ok := byName[anchorMarkerChainName]
			if !ok {
				t.Fatalf("captured own set has no marker chain: %v", byName)
			}
			if err := validateAnchorRegularChain(marker, "anchor marker chain"); err != nil {
				t.Errorf("production rejected its own captured marker chain: %v", err)
			}
			for _, name := range []string{anchorBaseInputName, anchorBaseOutputName} {
				record, found := byName[name]
				if !found {
					t.Fatalf("captured own set has no %q base chain", name)
				}
				// The captured record must really be the native base-chain
				// shape, otherwise this replay would not exercise it.
				if record.flags != nftChainFlagBase || !record.hasHook || !record.hasType ||
					record.kind != "filter" || record.policy != nftVerdictAccept ||
					record.priority != anchorBaseHookPriority {
					t.Fatalf("captured base chain %q shape = %+v, want the native base-chain shape", name, record)
				}
				epoch, ok := qa622BaseEpoch(record)
				if !ok {
					t.Fatalf("captured base chain %q userdata is not an own b record: %q", name, record.userdata)
				}
				if err := validateAnchorBaseChain(record, fixture.familyName, fixture.family, name, hooks[name], epoch); err != nil {
					t.Errorf("production rejected its own captured base chain %q: %v", name, err)
				}
				// Strictness is preserved: a foreign epoch or family is refused
				// exactly as before.
				foreignEpoch := record
				foreignEpoch.userdata = []byte(anchorBaseUserdata(strings.Repeat("0", len(epoch)), name))
				if err := validateAnchorBaseChain(foreignEpoch, fixture.familyName, fixture.family, name, hooks[name], epoch); err == nil {
					t.Errorf("base chain %q accepted a foreign epoch", name)
				}
				foreignFamily := record
				if fixture.family == byte(unix.NFPROTO_IPV4) {
					foreignFamily.family = byte(unix.NFPROTO_IPV6)
				} else {
					foreignFamily.family = byte(unix.NFPROTO_IPV4)
				}
				if err := validateAnchorBaseChain(foreignFamily, fixture.familyName, fixture.family, name, hooks[name], epoch); err == nil {
					t.Errorf("base chain %q accepted a foreign family", name)
				}
			}
		})
	}
}

// qa622BaseEpoch extracts the epoch of one captured own b record.
func qa622BaseEpoch(record nftChainRecord) (string, bool) {
	fields := strings.Split(string(record.userdata), ":")
	if len(fields) != 5 || fields[2] != "b" || fields[4] != record.name || fields[3] == "" {
		return "", false
	}
	return fields[3], true
}

// qa622ChainDumpDatagram builds one chain dump datagram from explicit
// attributes plus the terminating DONE, so malformed identity shapes can be
// driven through production parsing.
func qa622ChainDumpDatagram(t *testing.T, family byte, attributes []netlink.Attribute) string {
	t.Helper()
	payload, err := netlink.MarshalAttributes(attributes)
	if err != nil {
		t.Fatalf("marshal chain record: %v", err)
	}
	datagram := appendNetlinkMessage(nil, uint16(unix.NFNL_SUBSYS_NFTABLES<<8)|uint16(unix.NFT_MSG_NEWCHAIN),
		netlink.Multi, qa622Seq, append(nfgenmsg(family, 0), payload...))
	datagram = appendNetlinkMessage(datagram, unix.NLMSG_DONE, netlink.Multi, qa622Seq, nil)
	return hex.EncodeToString(datagram)
}

// TestAnchorChainDumpIdentityMustBeWellFormed drives hand-built chain dump
// records through production parsing: a missing, empty or repeated table
// identity is a visible readback error and is never silently attributed to the
// requested table, while a chain of another table is skipped untouched.
func TestAnchorChainDumpIdentityMustBeWellFormed(t *testing.T) {
	table := func(name string) netlink.Attribute {
		return netlink.Attribute{Type: unix.NFTA_CHAIN_TABLE, Data: []byte(name + "\x00")}
	}
	name := netlink.Attribute{Type: unix.NFTA_CHAIN_NAME, Data: []byte(anchorBaseOutputName + "\x00")}
	cases := []struct {
		name    string
		family  byte
		attrs   []netlink.Attribute
		wantErr string
		want    int
	}{
		{name: "own identity", family: byte(unix.NFPROTO_IPV4), attrs: []netlink.Attribute{table(anchorTableName), name}, want: 1},
		{name: "foreign identity", family: byte(unix.NFPROTO_IPV4), attrs: []netlink.Attribute{table(qa622AttributionTable), name}, want: 0},
		{name: "foreign without name", family: byte(unix.NFPROTO_IPV4), attrs: []netlink.Attribute{table(qa622AttributionTable)}, want: 0},
		{name: "duplicate identity", family: byte(unix.NFPROTO_IPV4), attrs: []netlink.Attribute{table(qa622AttributionTable), table(anchorTableName), name}, wantErr: "duplicate nftables table identity"},
		{name: "missing identity", family: byte(unix.NFPROTO_IPV4), attrs: []netlink.Attribute{name}, wantErr: "without a table identity"},
		{name: "empty identity", family: byte(unix.NFPROTO_IPV4), attrs: []netlink.Attribute{{Type: unix.NFTA_CHAIN_TABLE, Data: []byte{0}}, name}, wantErr: "without a table identity"},
		{name: "own identity without name", family: byte(unix.NFPROTO_IPV4), attrs: []netlink.Attribute{table(anchorTableName)}, wantErr: "without a name"},
		{name: "contradicting family", family: byte(unix.NFPROTO_IPV6), attrs: []netlink.Attribute{table(anchorTableName), name}, wantErr: "has family"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			datagram := qa622ChainDumpDatagram(t, testCase.family, testCase.attrs)
			scripted := &nftScriptedDatagram{steps: []nftScriptedRecv{nftScriptedDatagramStep(t, datagram, nftKernelPeer())}}
			session := newNftScriptedSession(qa622Port, qa622Seq-1, scripted)
			chains, err := readAnchorChains(session, byte(unix.NFPROTO_IPV4), anchorTableName)
			if testCase.wantErr != "" {
				if err == nil {
					t.Fatalf("malformed identity accepted: %+v", chains)
				}
				if !strings.Contains(err.Error(), testCase.wantErr) {
					t.Fatalf("error %q does not name %q", err, testCase.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("well-formed identity rejected: %v", err)
			}
			if len(chains) != testCase.want {
				t.Fatalf("selected chains = %+v, want %d record(s)", chains, testCase.want)
			}
			for _, chain := range chains {
				if chain.table != anchorTableName {
					t.Fatalf("record table = %q, want %q", chain.table, anchorTableName)
				}
			}
		})
	}
}

// qa622RuleDumpDatagram builds one rule dump datagram from one or more reply
// attribute sets, each becoming its own NFT_MSG_NEWRULE message.
func qa622RuleDumpDatagram(t *testing.T, family byte, messages ...[]netlink.Attribute) string {
	t.Helper()
	var datagram []byte
	for _, attributes := range messages {
		payload, err := netlink.MarshalAttributes(attributes)
		if err != nil {
			t.Fatalf("marshal rule record: %v", err)
		}
		datagram = appendNetlinkMessage(datagram, uint16(unix.NFNL_SUBSYS_NFTABLES<<8)|uint16(unix.NFT_MSG_NEWRULE),
			netlink.Multi, qa622Seq, append(nfgenmsg(family, 0), payload...))
	}
	datagram = appendNetlinkMessage(datagram, unix.NLMSG_DONE, netlink.Multi, qa622Seq, nil)
	return hex.EncodeToString(datagram)
}

func qa622RuleAttributes(table, chain string, handle uint64, userdata string) []netlink.Attribute {
	attrs := []netlink.Attribute{
		{Type: unix.NFTA_RULE_TABLE, Data: []byte(table + "\x00")},
		{Type: unix.NFTA_RULE_CHAIN, Data: []byte(chain + "\x00")},
		{Type: unix.NFTA_RULE_HANDLE, Data: binary.BigEndian.AppendUint64(nil, handle)},
	}
	if userdata != "" {
		attrs = append(attrs, netlink.Attribute{Type: unix.NFTA_RULE_USERDATA, Data: []byte(userdata)})
	}
	return attrs
}

// TestAnchorForeignTableRuleDumpIsNotAdopted keeps the rule readback on the
// same returned identity: a rule of another table is never recorded as an own
// anchor rule, and a malformed rule identity fails closed.
func TestAnchorForeignTableRuleDumpIsNotAdopted(t *testing.T) {
	own := qa622RuleUserdata()
	datagram := qa622RuleDumpDatagram(t, byte(unix.NFPROTO_IPV4),
		qa622RuleAttributes(anchorTableName, anchorMarkerChainName, 77, own),
		qa622RuleAttributes(qa622AttributionTable, anchorBaseOutputName, 78, own))
	scripted := &nftScriptedDatagram{steps: []nftScriptedRecv{nftScriptedDatagramStep(t, datagram, nftKernelPeer())}}
	session := newNftScriptedSession(qa622Port, qa622Seq-1, scripted)
	rules, err := readAnchorRules(session, byte(unix.NFPROTO_IPV4), anchorTableName, anchorMarkerChainName)
	if err != nil {
		t.Fatalf("rule readback: %v", err)
	}
	if len(rules) != 1 || rules[0].table != anchorTableName || rules[0].handle != 77 || rules[0].chain != anchorMarkerChainName {
		t.Fatalf("selected rules = %+v, want only the own marker rule", rules)
	}
	// Malformed identity of a rule reply fails closed.
	for _, broken := range [][]netlink.Attribute{
		{{Type: unix.NFTA_RULE_CHAIN, Data: []byte(anchorMarkerChainName + "\x00")}},
		append(qa622RuleAttributes(qa622AttributionTable, anchorMarkerChainName, 77, own),
			netlink.Attribute{Type: unix.NFTA_RULE_TABLE, Data: []byte(anchorTableName + "\x00")}),
	} {
		dump := qa622RuleDumpDatagram(t, byte(unix.NFPROTO_IPV4), broken)
		scripted = &nftScriptedDatagram{steps: []nftScriptedRecv{nftScriptedDatagramStep(t, dump, nftKernelPeer())}}
		session = newNftScriptedSession(qa622Port, qa622Seq-1, scripted)
		if _, err := readAnchorRules(session, byte(unix.NFPROTO_IPV4), anchorTableName, anchorMarkerChainName); err == nil {
			t.Fatalf("malformed rule identity accepted: %+v", broken)
		}
	}
}

// qa622RuleUserdata is the marker anchor record of the QA622 epoch, so a
// misattributed foreign rule would be a valid-looking own record.
func qa622RuleUserdata() string {
	return anchorMarkerUserdata("ip", "184f7a4c8de751dbd2168d08b905a8cd")
}

// qa622UnfilteredChainDump reproduces the exact target kernel's GETCHAIN dump
// semantics over the hermetic model: every chain of every table of the
// requested family is returned, regardless of the requested NFTA_TABLE_NAME
// (nf_tables_dump_chains). The production lifecycle runs unchanged on top of
// it. Only the transport model differs; no production selection is replaced.
type qa622UnfilteredChainDump struct {
	*fakeAnchorSession
}

func (s *qa622UnfilteredChainDump) dump(typ uint16, family byte, attrs []netlink.Attribute) ([]nftReply, error) {
	if typ != unix.NFT_MSG_GETCHAIN {
		return s.fakeAnchorSession.dump(typ, family, attrs)
	}
	s.namespace.mu.Lock()
	tables := make([]string, 0, len(s.namespace.tables[family]))
	for name := range s.namespace.tables[family] {
		tables = append(tables, name)
	}
	s.namespace.mu.Unlock()
	sort.Strings(tables)
	replies := make([]nftReply, 0, len(tables))
	for _, table := range tables {
		tableReplies, err := s.fakeAnchorSession.dump(typ, family, []netlink.Attribute{
			{Type: unix.NFTA_TABLE_NAME, Data: []byte(table + "\x00")},
		})
		if err != nil {
			return nil, err
		}
		replies = append(replies, tableReplies...)
	}
	return replies, nil
}

// qa622DuplicateOwnChain repeats the first own chain reply of every dump, so a
// genuine duplicate of the requested table is still refused.
type qa622DuplicateOwnChain struct {
	*qa622UnfilteredChainDump
}

func (s *qa622DuplicateOwnChain) dump(typ uint16, family byte, attrs []netlink.Attribute) ([]nftReply, error) {
	replies, err := s.qa622UnfilteredChainDump.dump(typ, family, attrs)
	if err != nil || typ != unix.NFT_MSG_GETCHAIN {
		return replies, err
	}
	for _, reply := range replies {
		_, replyAttrs, parseErr := nftMessageData(reply)
		if parseErr != nil {
			return nil, parseErr
		}
		if table, ok := qa622ReplyTable(replyAttrs); !ok || table != anchorTableName {
			continue
		}
		duplicate := reply
		duplicate.data = append([]byte(nil), reply.data...)
		return append(replies, duplicate), nil
	}
	return replies, nil
}

// TestAnchorForeignTableCoexistenceReadback composes an ordinary activation
// (production openLinuxCapture over the hermetic model) with the kernel's real
// chain-dump semantics and an unrelated regular table in BOTH families, whose
// chain is named "output" and which also carries an unrelated regular chain and
// an own-shaped rule. Activation readback must succeed and adopt nothing from
// the foreign table; a genuine duplicate inside the own table is still refused.
func TestAnchorForeignTableCoexistenceReadback(t *testing.T) {
	data := newFakeNFQueueConn("qa622-foreign", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	_, lease := newLinuxCaptureLease(t, 16130)
	capture, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() {
		if closeErr := capture.Close(); closeErr != nil {
			t.Fatalf("close: %v", closeErr)
		}
	}()
	plain := &fakeAnchorSession{namespace: seams.anchors, port: 0x40000025}
	families := []Family{FamilyIPv4, FamilyIPv6}
	epochs := make(map[Family]string, len(families))
	for _, family := range families {
		state, err := readAnchorFamilyState(plain, family)
		if err != nil {
			t.Fatalf("own readback before the foreign table: %v", err)
		}
		epochs[family] = state.epoch
	}
	// The unrelated regular table and its chains, exactly as the native
	// attribution created them: an "output" collision and an unrelated name.
	for _, family := range families {
		familyByte := byte(unix.NFPROTO_IPV4)
		if family == FamilyIPv6 {
			familyByte = byte(unix.NFPROTO_IPV6)
		}
		foreignTable := &fakeNftTable{name: qa622AttributionTable, chains: map[string]*fakeNftChain{
			anchorBaseOutputName: {name: anchorBaseOutputName},
			"harmless":           {name: "harmless"},
		}}
		foreignTable.chains[anchorBaseOutputName].rules = []*fakeNftRule{{
			handle:   424242,
			userdata: []byte(anchorCaptureUserdata(epochs[family], "qa622", "foreign", "inject")),
		}}
		seams.anchors.mu.Lock()
		if seams.anchors.tables[familyByte] == nil {
			seams.anchors.tables[familyByte] = make(map[string]*fakeNftTable)
		}
		seams.anchors.tables[familyByte][qa622AttributionTable] = foreignTable
		seams.anchors.mu.Unlock()
	}
	before := qa622ForeignFingerprint(seams.anchors)
	session := &qa622UnfilteredChainDump{fakeAnchorSession: plain}
	for _, family := range families {
		familyByte := qa622FamilyByte(t, family)
		// The model really returns the foreign chains: this is the kernel
		// behaviour observed by QA622, not a filtered convenience.
		replies, err := session.dump(unix.NFT_MSG_GETCHAIN, familyByte, []netlink.Attribute{
			{Type: unix.NFTA_TABLE_NAME, Data: []byte(anchorTableName + "\x00")},
		})
		if err != nil {
			t.Fatalf("%v: chain dump over the foreign table: %v", family, err)
		}
		foreign := make([]string, 0, 2)
		own := make([]string, 0, 5)
		for _, reply := range replies {
			_, attrs, parseErr := nftMessageData(reply)
			if parseErr != nil {
				t.Fatalf("%v: parse chain reply: %v", family, parseErr)
			}
			table, ok := qa622ReplyTable(attrs)
			if !ok {
				t.Fatalf("%v: chain reply has no table identity", family)
			}
			name, _ := nftAttrString(attrs, unix.NFTA_CHAIN_NAME)
			if table != anchorTableName {
				foreign = append(foreign, table+"/"+name)
				continue
			}
			own = append(own, name)
		}
		sort.Strings(foreign)
		sort.Strings(own)
		seams.anchors.mu.Lock()
		ownTable := seams.anchors.tables[familyByte][anchorTableName]
		modelOwn := make([]string, 0, len(ownTable.chains))
		for name := range ownTable.chains {
			modelOwn = append(modelOwn, name)
		}
		seams.anchors.mu.Unlock()
		sort.Strings(modelOwn)
		if strings.Join(own, ",") != strings.Join(modelOwn, ",") {
			t.Fatalf("%v: dump own chains = %v, want the model's own set %v", family, own, modelOwn)
		}
		if strings.Join(foreign, ",") != qa622AttributionTable+"/harmless,"+qa622AttributionTable+"/output" {
			t.Fatalf("%v: foreign dump replies = %v, want both unrelated chains", family, foreign)
		}
		state, err := readAnchorFamilyState(session, family)
		if err != nil {
			t.Fatalf("%v: activation readback with an unrelated regular table: %v", family, err)
		}
		chains, err := readAnchorChains(session, familyByte, anchorTableName)
		if err != nil {
			t.Fatalf("%v: chain selection: %v", family, err)
		}
		for _, chain := range chains {
			if chain.table != anchorTableName {
				t.Fatalf("%v: foreign chain %q adopted from table %q", family, chain.name, chain.table)
			}
		}
		if len(chains) != len(modelOwn) {
			t.Fatalf("%v: selected own chain replies = %d, want %d", family, len(chains), len(modelOwn))
		}
		// The capture's own chains live in its endpoint family; the other
		// family legitimately has no capture chains. What must never happen is
		// a foreign table chain appearing as a capture chain.
		if family == FamilyIPv4 && len(state.chains) != 1 {
			t.Fatalf("%v: capture chain sets = %v, want exactly the own capture", family, state.chains)
		}
		for key, chainNames := range state.chains {
			if state.captures[key] == nil {
				t.Fatalf("%v: chain set %q without a capture manifest", family, key)
			}
			for name := range chainNames {
				if !strings.HasPrefix(name, anchorChainPrefix) {
					t.Fatalf("%v: foreign chain %q adopted into capture %q", family, name, key)
				}
			}
		}
		for _, rules := range state.baseRules {
			for _, rule := range rules {
				if rule.record.capture == "foreign" {
					t.Fatalf("%v: foreign rule adopted into base rules: %+v", family, rule)
				}
			}
		}
	}
	if after := qa622ForeignFingerprint(seams.anchors); after != before {
		t.Fatalf("readback changed the unrelated table:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	// A genuine duplicate inside the requested own table keeps its own
	// rejection: foreign-skipping must not become duplicate acceptance.
	duplicate := &qa622DuplicateOwnChain{qa622UnfilteredChainDump: session}
	_, err = readAnchorFamilyState(duplicate, FamilyIPv4)
	if err == nil || !strings.Contains(err.Error(), "duplicate anchor chain") {
		t.Fatalf("duplicate own chain accepted or misreported: %v", err)
	}
}

// qa622ReplyTable reads the table identity of one replayed reply. It is a
// test-local reader so this file also compiles against the pre-repair source and
// the RED run can only fail behaviourally.
func qa622ReplyTable(attrs []netlink.Attribute) (string, bool) {
	table, ok := nftAttrString(attrs, unix.NFTA_CHAIN_TABLE)
	if !ok || table == "" {
		return "", false
	}
	return table, true
}

func qa622FamilyByte(t *testing.T, family Family) byte {
	t.Helper()
	_, familyByte, err := anchorFamilyNames(family)
	if err != nil {
		t.Fatal(err)
	}
	return familyByte
}

// qa622ForeignFingerprint renders only the unrelated tables of the model.
func qa622ForeignFingerprint(namespace *fakeNftNamespace) string {
	namespace.mu.Lock()
	defer namespace.mu.Unlock()
	var builder strings.Builder
	families := make([]int, 0, len(namespace.tables))
	for family := range namespace.tables {
		families = append(families, int(family))
	}
	sort.Ints(families)
	for _, familyValue := range families {
		table := namespace.tables[byte(familyValue)][qa622AttributionTable]
		if table == nil {
			continue
		}
		names := make([]string, 0, len(table.chains))
		for name := range table.chains {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			chain := table.chains[name]
			builder.WriteString("table " + table.name + " family " + uintString(uint64(familyValue)) +
				" chain " + name + " flags=" + uintString(uint64(chain.flags)) +
				" userdata=" + string(chain.userdata) + "\n")
			for _, rule := range chain.rules {
				builder.WriteString("rule " + uintString(rule.handle) + " " + string(rule.userdata) + "\n")
			}
		}
	}
	return builder.String()
}

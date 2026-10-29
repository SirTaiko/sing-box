//go:build linux

package desync

// Permanent regression for the native chain readback of the selected-A fixed
// anchors (QA553 finding S23-DEFAULT-BASE-FLAGS).
//
// Provenance of the captured fixture
// ----------------------------------
//   - Captured by the independent QA553 run (artifact t_288a5c5c, run553) from
//     the ordinary first StartCapture of the submission23 product binary, in
//     the capture's own Linux network namespace, on the target
//     Ubuntu 6.8.0-146-generic (6.8.12) kernel.
//   - Byte-for-byte from netlink-trace-decoded.json frames 55 and 56: one
//     408-byte NFNL_SUBSYS_NFTABLES datagram with the three NFT_MSG_NEWCHAIN
//     replies of the seq-37 GETCHAIN dump, and the 20-byte NLMSG_DONE of the
//     same sequence, both delivered by the kernel to the bound metadata port
//     0x40000001. Source log sha256
//     1c000ce15e994ce18ccbb72f955622bbe89f8010abe590216c40764b00fbb714.
//   - The dump is nonempty and native: the marker chain "__sbds_v1" carries no
//     NFTA_CHAIN_FLAGS attribute, while the fixed "input"/"output" base chains
//     carry NFTA_CHAIN_FLAGS = 1, i.e. NFT_CHAIN_BASE (1 << 0) of
//     linux/netfilter/nf_tables.h, the intrinsic flag the kernel sets for every
//     base chain in nft_basechain_init.
//   - The flag bits appear here as literals (0x1 base, 0x2 hardware offload,
//     0x4 binding, 0x8 and above unknown) so this file also compiles against
//     the pre-repair production blob: the pre-repair behaviour must fail these
//     assertions behaviourally, never with a compile error.
//
// These are model tests: no kernel object is created and no capture is opened on
// a real queue. The captured bytes drive the production
// dump -> readAnchorChains -> validator path, and the composed lifecycle cases
// run the production first-install/reuse/close code over the hermetic nftables
// model, whose dump emits the same intrinsic base flag.

import (
	"encoding/binary"
	"sort"
	"strings"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	// nativeAnchorChainDump is the verbatim seq-37 GETCHAIN reply of the
	// ordinary first activation: __sbds_v1, input, output.
	nativeAnchorChainDump = "48000000030a020025000000a1050040020000070e00010073625f646573796e630000000e0003005f5f736264735f76310000000c00020000000000000000010800060000000002a8000000030a020025000000a1050040020000070e00010073625f646573796e630000000a000300696e7075740000000c000200000000000000000414000400080001000000000108000200ffffff6a08000500000000010b00070066696c746572000008000a0000000001080006000000000033000c00736264733a313a623a66386535383232646636643637343830313837356230393965623738356537663a696e70757400a8000000030a020025000000a1050040020000070e00010073625f646573796e630000000b0003006f757470757400000c000200000000000000000514000400080001000000000308000200ffffff6a08000500000000010b00070066696c746572000008000a0000000001080006000000000034000c00736264733a313a623a66386535383232646636643637343830313837356230393965623738356537663a6f7574707574"
	// nativeAnchorChainDumpDone is the verbatim NLMSG_DONE of that dump.
	nativeAnchorChainDumpDone = "140000000300020025000000a105004000000000"
	// nativeAnchorChainPort is the bound metadata port of the captured dump.
	nativeAnchorChainPort = uint32(1073743265)
	// nativeAnchorChainSeq is the sequence before the dump request: the dump
	// itself uses seq 37, exactly as captured.
	nativeAnchorChainSeq = uint32(36)
	// nativeAnchorEpoch is the epoch token of the captured anchor userdata.
	nativeAnchorEpoch = "f8e5822df6d674801875b099eb785e7f"
)

// nativeAnchorSession returns a model metadata socket that answers the captured
// dump exactly once.
func nativeAnchorSession(t *testing.T, datagram, done string) (*nftScriptedDatagram, *nftNetlink) {
	t.Helper()
	scripted := &nftScriptedDatagram{steps: []nftScriptedRecv{
		nftScriptedDatagramStep(t, datagram, nftKernelPeer()),
		nftScriptedDatagramStep(t, done, nftKernelPeer()),
	}}
	return scripted, newNftScriptedSession(nativeAnchorChainPort, nativeAnchorChainSeq, scripted)
}

// TestAnchorNativeOwnBaseChainReadback replays the captured own-chain dump
// through production parsing and shape validation. It is the permanent form of
// the defect that stopped S23: the kernel's own intrinsic base-chain flag must
// not be rejected as a foreign flag.
func TestAnchorNativeOwnBaseChainReadback(t *testing.T) {
	scripted, session := nativeAnchorSession(t, nativeAnchorChainDump, nativeAnchorChainDumpDone)
	chains, err := readAnchorChains(session, byte(unix.NFPROTO_IPV4), anchorTableName)
	if err != nil {
		t.Fatalf("native chain dump: %v", err)
	}
	if len(scripted.steps) != 0 {
		t.Fatalf("unread native reply steps = %d", len(scripted.steps))
	}
	if len(chains) != 3 {
		t.Fatalf("native chain records = %d, want 3", len(chains))
	}
	byName := make(map[string]nftChainRecord, len(chains))
	for _, chain := range chains {
		byName[chain.name] = chain
	}
	marker, ok := byName[anchorMarkerChainName]
	if !ok {
		t.Fatalf("captured dump has no marker chain: %v", byName)
	}
	if marker.hasHook || marker.hasType || marker.flags != 0 {
		t.Fatalf("captured marker chain shape = %+v, want a flagless regular chain", marker)
	}
	hooks := map[string]uint32{
		anchorBaseInputName:  uint32(unix.NF_INET_LOCAL_IN),
		anchorBaseOutputName: uint32(unix.NF_INET_LOCAL_OUT),
	}
	names := make([]string, 0, len(hooks))
	for name := range hooks {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		record, found := byName[name]
		if !found {
			t.Fatalf("captured dump has no %q base chain", name)
		}
		// The captured bytes themselves must carry the intrinsic base flag;
		// without this the replay would not exercise the native shape at all.
		if record.flags != 0x1 {
			t.Fatalf("captured base chain %q flags = %#x, want NFT_CHAIN_BASE", name, record.flags)
		}
		if err := validateAnchorBaseChain(record, "ip", byte(unix.NFPROTO_IPV4), name, hooks[name], nativeAnchorEpoch); err != nil {
			t.Errorf("production rejected its own native base chain %q readback: %v", name, err)
		}
	}
}

// TestAnchorBaseChainFlagInterpretation pins the accepted and rejected flag
// shapes of a fixed base chain. The only tolerated value is the kernel's
// intrinsic NFT_CHAIN_BASE bit (absent on kernels that do not report it);
// hardware offload, binding, unknown bits and every non-flag identity field
// stay strict.
func TestAnchorBaseChainFlagInterpretation(t *testing.T) {
	native := func() nftChainRecord {
		return nftChainRecord{
			table: anchorTableName, name: anchorBaseInputName,
			family: byte(unix.NFPROTO_IPV4), hasHook: true,
			hooknum: uint32(unix.NF_INET_LOCAL_IN), priority: anchorBaseHookPriority,
			hasType: true, kind: "filter", policy: nftVerdictAccept,
			flags:    0x1,
			userdata: []byte(anchorBaseUserdata(nativeAnchorEpoch, anchorBaseInputName)),
		}
	}
	cases := []struct {
		name   string
		mutate func(*nftChainRecord)
		want   string
	}{
		{name: "captured intrinsic base flag", mutate: func(*nftChainRecord) {}, want: ""},
		{name: "kernel without the reported flag", mutate: func(r *nftChainRecord) { r.flags = 0 }, want: ""},
		{name: "hardware offload", mutate: func(r *nftChainRecord) { r.flags = 0x2 }, want: "hardware offloaded"},
		{name: "base plus offload", mutate: func(r *nftChainRecord) { r.flags = 0x3 }, want: "hardware offloaded"},
		{name: "binding chain", mutate: func(r *nftChainRecord) { r.flags = 0x4 }, want: "binding chain"},
		{name: "base plus binding", mutate: func(r *nftChainRecord) { r.flags = 0x5 }, want: "binding chain"},
		{name: "unknown flag bit", mutate: func(r *nftChainRecord) { r.flags = 0x8 }, want: "unknown flags"},
		{name: "unknown high bit", mutate: func(r *nftChainRecord) { r.flags = 0x80000000 }, want: "unknown flags"},
		{name: "foreign table", mutate: func(r *nftChainRecord) { r.table = "other" }, want: "unexpected base chain"},
		{name: "foreign name", mutate: func(r *nftChainRecord) { r.name = "other" }, want: "unexpected base chain"},
		{name: "wrong family", mutate: func(r *nftChainRecord) { r.family = byte(unix.NFPROTO_IPV6) }, want: "has family"},
		{name: "wrong hook", mutate: func(r *nftChainRecord) { r.hooknum = uint32(unix.NF_INET_LOCAL_OUT) }, want: "no matching hook"},
		{name: "missing hook", mutate: func(r *nftChainRecord) { r.hasHook = false }, want: "no matching hook"},
		{name: "wrong priority", mutate: func(r *nftChainRecord) { r.priority = anchorBaseHookPriority + 1 }, want: "has priority"},
		{name: "non filter type", mutate: func(r *nftChainRecord) { r.kind = "route" }, want: "not a filter chain"},
		{name: "missing type", mutate: func(r *nftChainRecord) { r.hasType = false }, want: "not a filter chain"},
		{name: "drop policy", mutate: func(r *nftChainRecord) { r.policy = 0 }, want: "not accept"},
		{name: "foreign userdata", mutate: func(r *nftChainRecord) {
			r.userdata = []byte(anchorBaseUserdata(nativeAnchorEpoch, anchorBaseOutputName))
		}, want: "foreign userdata"},
		{name: "wrong epoch userdata", mutate: func(r *nftChainRecord) {
			r.userdata = []byte(anchorBaseUserdata("00000000000000000000000000000000", anchorBaseInputName))
		}, want: "foreign userdata"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			record := native()
			testCase.mutate(&record)
			err := validateAnchorBaseChain(record, "ip", byte(unix.NFPROTO_IPV4), anchorBaseInputName,
				uint32(unix.NF_INET_LOCAL_IN), nativeAnchorEpoch)
			if testCase.want == "" {
				if err != nil {
					t.Fatalf("want accepted, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want a %q rejection, got nil", testCase.want)
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error %q does not name %q", err, testCase.want)
			}
		})
	}
}

// TestAnchorChainFlagsAttributeMustBeWellFormed drives hand-built chain dump
// records through production parsing: a repeated or wrongly sized
// NFTA_CHAIN_FLAGS attribute must be a visible readback error, never a silent
// "no flags" that would validate an object whose shape was not really seen.
func TestAnchorChainFlagsAttributeMustBeWellFormed(t *testing.T) {
	flagsAttribute := func(data []byte) netlink.Attribute {
		return netlink.Attribute{Type: nftAttrChainFlags, Data: data}
	}
	baseFlag := binary.BigEndian.AppendUint32(nil, 0x1)
	otherFlag := binary.BigEndian.AppendUint32(nil, 0x2)
	cases := []struct {
		name       string
		attributes []netlink.Attribute
		wantErr    string
		wantFlags  uint32
	}{
		{name: "single intrinsic base flag", attributes: []netlink.Attribute{flagsAttribute(baseFlag)}, wantFlags: 0x1},
		{name: "duplicate attribute", attributes: []netlink.Attribute{flagsAttribute(baseFlag), flagsAttribute(otherFlag)}, wantErr: "duplicate NFTA_CHAIN_FLAGS"},
		{name: "short attribute", attributes: []netlink.Attribute{flagsAttribute(baseFlag[:2])}, wantErr: "want 4"},
		{name: "long attribute", attributes: []netlink.Attribute{flagsAttribute(append(append([]byte(nil), baseFlag...), 0))}, wantErr: "want 4"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			attributes := []netlink.Attribute{
				{Type: unix.NFTA_CHAIN_TABLE, Data: []byte(anchorTableName + "\x00")},
				{Type: unix.NFTA_CHAIN_NAME, Data: []byte(anchorBaseInputName + "\x00")},
			}
			attributes = append(attributes, testCase.attributes...)
			payload, err := netlink.MarshalAttributes(attributes)
			if err != nil {
				t.Fatalf("marshal chain record: %v", err)
			}
			datagram := appendNetlinkMessage(nil, uint16(unix.NFNL_SUBSYS_NFTABLES<<8)|uint16(unix.NFT_MSG_NEWCHAIN),
				netlink.Multi, 37, append(nfgenmsg(byte(unix.NFPROTO_IPV4), 0), payload...))
			datagram = appendNetlinkMessage(datagram, unix.NLMSG_DONE, netlink.Multi, 37, nil)
			scripted := &nftScriptedDatagram{steps: []nftScriptedRecv{nftScriptedDatagramStep(t, hexBytes(datagram), nftKernelPeer())}}
			session := newNftScriptedSession(nativeAnchorChainPort, nativeAnchorChainSeq, scripted)
			chains, err := readAnchorChains(session, byte(unix.NFPROTO_IPV4), anchorTableName)
			if testCase.wantErr != "" {
				if err == nil {
					t.Fatalf("malformed flags attribute accepted: %+v", chains)
				}
				if !strings.Contains(err.Error(), testCase.wantErr) {
					t.Fatalf("error %q does not name %q", err, testCase.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("well-formed flags attribute rejected: %v", err)
			}
			if len(chains) != 1 || chains[0].flags != testCase.wantFlags {
				t.Fatalf("parsed chains = %+v, want one record with flags %#x", chains, testCase.wantFlags)
			}
		})
	}
}

// TestAnchorRegularChainNeverCarriesBaseFlag keeps the intrinsic base semantics
// out of the named regular chains of the anchor table: only base chains may
// carry NFT_CHAIN_BASE.
func TestAnchorRegularChainNeverCarriesBaseFlag(t *testing.T) {
	data := newFakeNFQueueConn("regular-flag", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	_, lease := newLinuxCaptureLease(t, 16123)
	capture, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	defer func() {
		if closeErr := capture.Close(); closeErr != nil {
			t.Fatalf("close: %v", closeErr)
		}
	}()
	session := &fakeAnchorSession{namespace: seams.anchors, port: 0x40000021}
	if _, err := readAnchorFamilyState(session, FamilyIPv4); err != nil {
		t.Fatalf("native-shaped model anchors: %v", err)
	}
	table := seams.anchors.tableLocked(byte(unix.NFPROTO_IPV4), anchorTableName)
	if table == nil {
		t.Fatal("model anchor table missing")
	}
	marker := table.chains[anchorMarkerChainName]
	if marker == nil {
		t.Fatal("model marker chain missing")
	}
	captureChainName := ""
	for name := range table.chains {
		if strings.HasPrefix(name, anchorChainPrefix) {
			captureChainName = name
			break
		}
	}
	if captureChainName == "" {
		t.Fatal("model capture chain missing")
	}
	for _, regular := range []string{anchorMarkerChainName, captureChainName} {
		seams.anchors.mu.Lock()
		original := table.chains[regular].flags
		table.chains[regular].flags = 0x1
		seams.anchors.mu.Unlock()
		_, err := readAnchorFamilyState(session, FamilyIPv4)
		if err == nil {
			seams.anchors.mu.Lock()
			table.chains[regular].flags = original
			seams.anchors.mu.Unlock()
			t.Fatalf("regular chain %q accepted the intrinsic base-chain flag", regular)
		}
		if !strings.Contains(err.Error(), "flags") {
			seams.anchors.mu.Lock()
			table.chains[regular].flags = original
			seams.anchors.mu.Unlock()
			t.Fatalf("regular chain %q rejection hides the flag cause: %v", regular, err)
		}
		seams.anchors.mu.Lock()
		table.chains[regular].flags = original
		seams.anchors.mu.Unlock()
	}
	if _, err := readAnchorFamilyState(session, FamilyIPv4); err != nil {
		t.Fatalf("restoring the regular chain flags did not restore the anchors: %v", err)
	}
}

// TestAnchorNativeShapeFirstInstallReuseClose composes the whole first
// activation over the model transport whose dump is kernel-shaped: install,
// full own-anchor readback with the intrinsic base flag, reuse by a second
// capture, close, and a still-valid idle anchor.
func TestAnchorNativeShapeFirstInstallReuseClose(t *testing.T) {
	data := newFakeNFQueueConn("native-shape", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	_, lease := newLinuxCaptureLease(t, 16124)
	capture, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("first install: %v", err)
	}
	session := &fakeAnchorSession{namespace: seams.anchors, port: 0x40000022}
	chains, err := readAnchorChains(session, byte(unix.NFPROTO_IPV4), anchorTableName)
	if err != nil {
		t.Fatalf("model readback: %v", err)
	}
	baseFlags := make(map[string]uint32)
	for _, chain := range chains {
		if chain.hasHook {
			baseFlags[chain.name] = chain.flags
		} else if chain.flags != 0 {
			t.Fatalf("model regular chain %q flags = %#x, want none", chain.name, chain.flags)
		}
	}
	if len(baseFlags) != 2 || baseFlags[anchorBaseInputName] != 0x1 || baseFlags[anchorBaseOutputName] != 0x1 {
		t.Fatalf("model base-chain flags = %v, want the intrinsic NFT_CHAIN_BASE bit on both", baseFlags)
	}
	state, err := readAnchorFamilyState(session, FamilyIPv4)
	if err != nil {
		t.Fatalf("readback of own native-shaped anchors: %v", err)
	}
	if state.epoch == "" || len(state.chains) == 0 {
		t.Fatalf("anchor state after first install = %+v", state)
	}
	_, secondLease := newLinuxCaptureLease(t, 16125)
	second, err := openLinuxCapture(secondLease)
	if err != nil {
		t.Fatalf("reuse open: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("reuse close: %v", err)
	}
	tables, err := readAnchorTables(session, byte(unix.NFPROTO_IPV4))
	if err != nil {
		t.Fatalf("tables after reuse: %v", err)
	}
	count := 0
	for _, table := range tables {
		if table.name == anchorTableName {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("anchor tables after reuse = %d, want exactly one generation", count)
	}
	if err := capture.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := readAnchorFamilyState(session, FamilyIPv4); err != nil {
		t.Fatalf("idle anchors after close: %v", err)
	}
	if records := modelCaptureRecords(t, seams, FamilyIPv4); len(records) != 0 {
		t.Fatalf("capture records left after close: %v", records)
	}
}

// fakeAnchorFingerprint renders the complete model namespace in a stable order.
// The negative control below uses it to prove a rejected readback changed
// nothing, including the transaction counter.
func fakeAnchorFingerprint(namespace *fakeNftNamespace) string {
	namespace.mu.Lock()
	defer namespace.mu.Unlock()
	var builder strings.Builder
	families := make([]int, 0, len(namespace.tables))
	for family := range namespace.tables {
		families = append(families, int(family))
	}
	sort.Ints(families)
	for _, familyValue := range families {
		family := byte(familyValue)
		tables := make([]string, 0, len(namespace.tables[family]))
		for name := range namespace.tables[family] {
			tables = append(tables, name)
		}
		sort.Strings(tables)
		for _, name := range tables {
			table := namespace.tables[family][name]
			builder.WriteString("table " + name + " " + string(rune(table.flags)) + "\n")
			chains := make([]string, 0, len(table.chains))
			for chainName := range table.chains {
				chains = append(chains, chainName)
			}
			sort.Strings(chains)
			for _, chainName := range chains {
				chain := table.chains[chainName]
				builder.WriteString("chain " + chainName + " base=" + boolString(chain.base) +
					" hook=" + uintString(uint64(chain.hooknum)) + " prio=" + intString(int64(chain.priority)) +
					" policy=" + uintString(uint64(chain.policy)) + " kind=" + chain.kind +
					" flags=" + uintString(uint64(chain.flags)) + " userdata=" + string(chain.userdata) + "\n")
				for _, rule := range chain.rules {
					builder.WriteString("rule " + uintString(rule.handle) + " " + string(rule.userdata) + "\n")
				}
			}
		}
	}
	builder.WriteString("batches " + uintString(uint64(namespace.batchCalls)) +
		" gen " + uintString(uint64(namespace.gen)) + "\n")
	return builder.String()
}

func boolString(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

// TestAnchorOffloadBaseChainRejectedVisibly proves that a foreign flag on a
// fixed base chain is refused with the actual cause visible, that the refused
// readback mutates nothing, and that the anchors stay usable afterwards.
func TestAnchorOffloadBaseChainRejectedVisibly(t *testing.T) {
	data := newFakeNFQueueConn("offload-flag", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	_, lease := newLinuxCaptureLease(t, 16126)
	capture, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	defer func() {
		if closeErr := capture.Close(); closeErr != nil {
			t.Fatalf("close: %v", closeErr)
		}
	}()
	session := &fakeAnchorSession{namespace: seams.anchors, port: 0x40000023}
	table := seams.anchors.tableLocked(byte(unix.NFPROTO_IPV4), anchorTableName)
	if table == nil || table.chains[anchorBaseOutputName] == nil {
		t.Fatal("model output base chain missing")
	}
	seams.anchors.mu.Lock()
	table.chains[anchorBaseOutputName].flags |= 0x2
	seams.anchors.mu.Unlock()
	before := fakeAnchorFingerprint(seams.anchors)
	_, err = readAnchorFamilyState(session, FamilyIPv4)
	if err == nil {
		t.Fatal("hardware-offloaded base chain accepted")
	}
	if !strings.Contains(err.Error(), "hardware offloaded") {
		t.Fatalf("rejection hides the offload cause: %v", err)
	}
	if after := fakeAnchorFingerprint(seams.anchors); after != before {
		t.Fatalf("rejected readback mutated the namespace:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	seams.anchors.mu.Lock()
	table.chains[anchorBaseOutputName].flags &^= 0x2
	seams.anchors.mu.Unlock()
	if _, err := readAnchorFamilyState(session, FamilyIPv4); err != nil {
		t.Fatalf("anchors unusable after clearing the foreign flag: %v", err)
	}
}

// TestAnchorForeignChainIsNotAdopted keeps the no-name-only-adoption rule next
// to the new flag handling: a chain of the anchor table that is not one of the
// fixed base chains, the marker chain or a recorded capture chain is a
// collision, even when its name looks harmless.
func TestAnchorForeignChainIsNotAdopted(t *testing.T) {
	data := newFakeNFQueueConn("foreign-chain", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	_, lease := newLinuxCaptureLease(t, 16127)
	capture, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	defer func() {
		if closeErr := capture.Close(); closeErr != nil {
			t.Fatalf("close: %v", closeErr)
		}
	}()
	session := &fakeAnchorSession{namespace: seams.anchors, port: 0x40000024}
	if _, err := readAnchorFamilyState(session, FamilyIPv4); err != nil {
		t.Fatalf("install readback: %v", err)
	}
	seams.anchors.mu.Lock()
	seams.anchors.tableLocked(byte(unix.NFPROTO_IPV4), anchorTableName).chains["foreign"] = &fakeNftChain{name: "foreign"}
	seams.anchors.mu.Unlock()
	_, err = readAnchorFamilyState(session, FamilyIPv4)
	if err == nil {
		t.Fatal("foreign chain adopted")
	}
	if !strings.Contains(err.Error(), "unknown anchor chain") {
		t.Fatalf("foreign chain rejection hides the cause: %v", err)
	}
	seams.anchors.mu.Lock()
	delete(seams.anchors.tableLocked(byte(unix.NFPROTO_IPV4), anchorTableName).chains, "foreign")
	seams.anchors.mu.Unlock()
	if _, err := readAnchorFamilyState(session, FamilyIPv4); err != nil {
		t.Fatalf("anchors unusable after removing the foreign chain: %v", err)
	}
}

// TestAnchorTableShapeStaysStrict keeps the table-level rejection of foreign,
// dormant and owned objects unchanged next to the new chain flag handling.
func TestAnchorTableShapeStaysStrict(t *testing.T) {
	cases := []struct {
		name  string
		flags uint32
		want  string
	}{
		{name: "own plain table", flags: 0, want: ""},
		{name: "dormant", flags: 0x1, want: "dormant"},
		{name: "owner", flags: 0x2, want: "carries flags"},
		{name: "persist", flags: 0x4, want: "carries flags"},
		{name: "unknown", flags: 0x8, want: "carries flags"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := validateAnchorTable(nftTableRecord{name: anchorTableName, flags: testCase.flags})
			if testCase.want == "" {
				if err != nil {
					t.Fatalf("want accepted, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want a %q rejection, got nil", testCase.want)
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error %q does not name %q", err, testCase.want)
			}
		})
	}
	if err := validateAnchorTable(nftTableRecord{name: "foreign"}); err == nil {
		t.Fatal("foreign table name accepted")
	}
}

// hexBytes renders one datagram as the lowercase hex the fixture helpers take.
func hexBytes(data []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(data)*2)
	for _, value := range data {
		out = append(out, digits[value>>4], digits[value&0xf])
	}
	return string(out)
}

func uintString(value uint64) string {
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	position := len(buffer)
	for value > 0 {
		position--
		buffer[position] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[position:])
}

func intString(value int64) string {
	if value < 0 {
		return "-" + uintString(uint64(-value))
	}
	return uintString(uint64(value))
}

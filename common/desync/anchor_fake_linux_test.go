//go:build linux

package desync

// Hermetic model of the nftables object namespace used by the persistent-anchor
// lifecycle. Model tests: no kernel object is created, and every case says so.
// It implements the same anchorSession surface as the production
// raw-netlink client, so the real lifecycle code (ensureAnchorFamily,
// readAnchorFamilyState, recovery, retirement) runs unchanged without
// CAP_NET_ADMIN.
//
// The model keeps creation atomic per batch (the real kernel aborts the whole
// transaction on the first error), honours NLM_F_EXCL, allocates rule handles,
// echoes NEWRULE handles, and can simulate a lost acknowledgement by committing
// a batch and returning an error afterwards.

import (
	"encoding/binary"
	"errors"

	"sort"
	"strings"
	"sync"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// nftChainFlagBaseModel is NFT_CHAIN_BASE (1 << 0) of
// linux/netfilter/nf_tables.h. It is spelled as a model-local constant so the
// model also compiles against the pre-repair production blob: a regression run
// against that blob must fail behaviourally, never with a build error.
const nftChainFlagBaseModel = 0x1

type fakeNftRule struct {
	handle      uint64
	userdata    []byte
	expressions [][]byte
}

type fakeNftChain struct {
	name     string
	base     bool
	hooknum  uint32
	priority int32
	policy   uint32
	kind     string
	flags    uint32
	userdata []byte
	rules    []*fakeNftRule
}

type fakeNftTable struct {
	name   string
	flags  uint32
	chains map[string]*fakeNftChain
}

type fakeNftNamespace struct {
	mu         sync.Mutex
	nextHandle uint64
	tables     map[byte]map[string]*fakeNftTable
	// batchCalls counts batches (diagnostics in tests).
	batchCalls int
	// loseAck, when positive, commits exactly that many upcoming batches and
	// then returns the configured error instead of the acknowledgement.
	loseAck int
	// gen counts committed nftables transactions; it is the model's generation
	// counter.
	gen uint32

	// batchError, when set, makes every batch fail before any effect.
	batchError error
	// failRuleSubstring makes a NEWRULE whose userdata contains the substring
	// fail the whole batch, modelling an nftables rule rejection.
	failRuleSubstring string
	// loseAckForSubstring commits a batch containing a request whose payload
	// contains the substring and then reports a lost acknowledgement.
	loseAckForSubstring string
}

func newFakeNftNamespace() *fakeNftNamespace {
	return &fakeNftNamespace{nextHandle: 100, tables: make(map[byte]map[string]*fakeNftTable)}
}

func (n *fakeNftNamespace) clone() *fakeNftNamespace {
	copyState := &fakeNftNamespace{nextHandle: n.nextHandle, gen: n.gen, tables: make(map[byte]map[string]*fakeNftTable),
		failRuleSubstring: n.failRuleSubstring, loseAckForSubstring: n.loseAckForSubstring}
	for family, tables := range n.tables {
		familyCopy := make(map[string]*fakeNftTable, len(tables))
		for name, table := range tables {
			tableCopy := &fakeNftTable{name: table.name, flags: table.flags, chains: make(map[string]*fakeNftChain)}
			for chainName, chain := range table.chains {
				chainCopy := &fakeNftChain{
					name: chain.name, base: chain.base, hooknum: chain.hooknum, priority: chain.priority,
					policy: chain.policy, kind: chain.kind, flags: chain.flags,
					userdata: append([]byte(nil), chain.userdata...),
				}
				for _, rule := range chain.rules {
					chainCopy.rules = append(chainCopy.rules, &fakeNftRule{
						handle: rule.handle, userdata: append([]byte(nil), rule.userdata...),
						expressions: append([][]byte(nil), rule.expressions...),
					})
				}
				tableCopy.chains[chainName] = chainCopy
			}
			familyCopy[name] = tableCopy
		}
		copyState.tables[family] = familyCopy
	}
	return copyState
}

func (n *fakeNftNamespace) replaceWith(other *fakeNftNamespace) {
	n.tables = other.tables
	n.nextHandle = other.nextHandle
}

func (n *fakeNftNamespace) tableLocked(family byte, name string) *fakeNftTable {
	if n.tables[family] == nil {
		return nil
	}
	return n.tables[family][name]
}

func (n *fakeNftNamespace) chainLocked(family byte, table, chain string) (*fakeNftChain, error) {
	tableObject := n.tableLocked(family, table)
	if tableObject == nil {
		return nil, unix.ENOENT
	}
	found := tableObject.chains[chain]
	if found == nil {
		return nil, unix.ENOENT
	}
	return found, nil
}

func parseFakeMessage(data []byte) (byte, []netlink.Attribute, error) {
	if len(data) < 4 {
		return 0, nil, errors.New("fake nft: short message")
	}
	attributes, err := netlink.UnmarshalAttributes(data[4:])
	if err != nil {
		return 0, nil, err
	}
	return data[0], attributes, nil
}

func fakeAttrString(attributes []netlink.Attribute, want uint16) (string, bool) {
	data, ok := nftAttrBytes(attributes, want)
	if !ok {
		return "", false
	}
	if len(data) > 0 && data[len(data)-1] == 0 {
		data = data[:len(data)-1]
	}
	return string(data), true
}

func fakeAttrUint32(attributes []netlink.Attribute, want uint16) (uint32, bool) {
	data, ok := nftAttrBytes(attributes, want)
	if !ok || len(data) != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(data), true
}

func fakeAttrUint64(attributes []netlink.Attribute, want uint16) (uint64, bool) {
	data, ok := nftAttrBytes(attributes, want)
	if !ok || len(data) != 8 {
		return 0, false
	}
	return binary.BigEndian.Uint64(data), true
}

func (n *fakeNftNamespace) applyBatchLocked(requests []nftRequest) ([]nftReply, error) {
	echoes := make([]nftReply, 0, len(requests))
	for _, request := range requests {
		family, attributes, err := parseFakeMessage(request.data)
		if err != nil {
			return nil, err
		}
		switch request.typ {
		case unix.NFT_MSG_NEWTABLE:
			name, ok := fakeAttrString(attributes, unix.NFTA_TABLE_NAME)
			if !ok {
				return nil, unix.EINVAL
			}
			if n.tables[family] == nil {
				n.tables[family] = make(map[string]*fakeNftTable)
			}
			if _, found := n.tables[family][name]; found {
				return nil, unix.EEXIST
			}
			flags, _ := fakeAttrUint32(attributes, unix.NFTA_TABLE_FLAGS)
			n.tables[family][name] = &fakeNftTable{name: name, flags: flags, chains: make(map[string]*fakeNftChain)}
		case unix.NFT_MSG_NEWCHAIN:
			tableName, ok := fakeAttrString(attributes, unix.NFTA_CHAIN_TABLE)
			if !ok {
				return nil, unix.EINVAL
			}
			tableObject := n.tableLocked(family, tableName)
			if tableObject == nil {
				return nil, unix.ENOENT
			}
			chainName, ok := fakeAttrString(attributes, unix.NFTA_CHAIN_NAME)
			if !ok {
				return nil, unix.EINVAL
			}
			if _, found := tableObject.chains[chainName]; found {
				if request.flags&netlink.Excl != 0 {
					return nil, unix.EEXIST
				}
				return nil, unix.EEXIST
			}
			chainObject := &fakeNftChain{name: chainName}
			if hookData, hasHook := nftAttrBytes(attributes, unix.NFTA_CHAIN_HOOK); hasHook {
				hookAttrs, hookErr := netlink.UnmarshalAttributes(hookData)
				if hookErr != nil {
					return nil, hookErr
				}
				chainObject.base = true
				chainObject.hooknum, _ = fakeAttrUint32(hookAttrs, unix.NFTA_HOOK_HOOKNUM)
				priority, _ := fakeAttrUint32(hookAttrs, unix.NFTA_HOOK_PRIORITY)
				chainObject.priority = int32(priority)
				chainObject.policy, _ = fakeAttrUint32(attributes, unix.NFTA_CHAIN_POLICY)
				chainObject.kind, _ = fakeAttrString(attributes, unix.NFTA_CHAIN_TYPE)
			}
			if userdata, ok := nftAttrBytes(attributes, nftAttrChainUserdata); ok {
				chainObject.userdata = append([]byte(nil), userdata...)
			}
			if flags, ok := fakeAttrUint32(attributes, nftAttrChainFlags); ok {
				chainObject.flags = flags
			}
			tableObject.chains[chainName] = chainObject
		case unix.NFT_MSG_NEWRULE:
			tableName, ok := fakeAttrString(attributes, unix.NFTA_RULE_TABLE)
			if !ok {
				return nil, unix.EINVAL
			}
			chainName, ok := fakeAttrString(attributes, unix.NFTA_RULE_CHAIN)
			if !ok {
				return nil, unix.EINVAL
			}
			chainObject, chainErr := n.chainLocked(family, tableName, chainName)
			if chainErr != nil {
				return nil, chainErr
			}
			ruleObject := &fakeNftRule{handle: n.nextHandle}
			n.nextHandle++
			if userdata, ok := nftAttrBytes(attributes, unix.NFTA_RULE_USERDATA); ok {
				ruleObject.userdata = append([]byte(nil), userdata...)
				if n.failRuleSubstring != "" && strings.Contains(string(userdata), n.failRuleSubstring) {
					return nil, unix.EINVAL
				}
			}
			if expressionData, ok := nftAttrBytes(attributes, unix.NFTA_RULE_EXPRESSIONS); ok {
				expressionAttrs, expressionErr := netlink.UnmarshalAttributes(expressionData)
				if expressionErr != nil {
					return nil, expressionErr
				}
				for _, expression := range expressionAttrs {
					ruleObject.expressions = append(ruleObject.expressions, append([]byte(nil), expression.Data...))
				}
			}
			if request.flags&netlink.Append != 0 {
				chainObject.rules = append(chainObject.rules, ruleObject)
			} else {
				chainObject.rules = append([]*fakeNftRule{ruleObject}, chainObject.rules...)
			}
			if request.flags&netlink.Echo != 0 {
				echoData := fakeRuleAttributes(tableName, chainName, ruleObject)
				echoes = append(echoes, nftReply{typ: uint16(unix.NFNL_SUBSYS_NFTABLES<<8) | unix.NFT_MSG_NEWRULE,
					data: append(nfgenmsg(family, 0), echoData...)})
			}
		case unix.NFT_MSG_DELRULE:
			tableName, _ := fakeAttrString(attributes, unix.NFTA_RULE_TABLE)
			chainName, _ := fakeAttrString(attributes, unix.NFTA_RULE_CHAIN)
			handle, ok := fakeAttrUint64(attributes, unix.NFTA_RULE_HANDLE)
			if !ok {
				return nil, unix.EINVAL
			}
			chainObject, chainErr := n.chainLocked(family, tableName, chainName)
			if chainErr != nil {
				return nil, chainErr
			}
			removed := false
			kept := chainObject.rules[:0]
			for _, rule := range chainObject.rules {
				if rule.handle == handle {
					removed = true
					continue
				}
				kept = append(kept, rule)
			}
			chainObject.rules = kept
			if !removed {
				return nil, unix.ENOENT
			}
		case unix.NFT_MSG_DELCHAIN:
			tableName, _ := fakeAttrString(attributes, unix.NFTA_CHAIN_TABLE)
			chainName, _ := fakeAttrString(attributes, unix.NFTA_CHAIN_NAME)
			tableObject := n.tableLocked(family, tableName)
			if tableObject == nil {
				return nil, unix.ENOENT
			}
			chainObject := tableObject.chains[chainName]
			if chainObject == nil {
				return nil, unix.ENOENT
			}
			if len(chainObject.rules) != 0 {
				return nil, unix.EBUSY
			}
			delete(tableObject.chains, chainName)
		default:
			return nil, unix.EOPNOTSUPP
		}
	}
	return echoes, nil
}

func fakeRuleAttributes(table, chain string, rule *fakeNftRule) []byte {
	attributes := []netlink.Attribute{
		{Type: unix.NFTA_RULE_TABLE, Data: []byte(table + "\x00")},
		{Type: unix.NFTA_RULE_CHAIN, Data: []byte(chain + "\x00")},
		{Type: unix.NFTA_RULE_HANDLE, Data: binary.BigEndian.AppendUint64(nil, rule.handle)},
	}
	if rule.userdata != nil {
		attributes = append(attributes, netlink.Attribute{Type: unix.NFTA_RULE_USERDATA, Data: rule.userdata})
	}
	data, _ := netlink.MarshalAttributes(attributes)
	return data
}

// fakeAnchorSession implements anchorSession over the model. Every call gets a
// fresh session object (like a fresh metadata socket), but they share the one
// namespace state.
type fakeAnchorSession struct {
	namespace *fakeNftNamespace
	port      uint32
	// rawReplies stores datagrams produced for sendRaw, in FIFO order.
	mu         sync.Mutex
	rawReplies [][]byte
	rawPeer    *unix.SockaddrNetlink
}

func (s *fakeAnchorSession) Close() error      { return nil }
func (s *fakeAnchorSession) boundPort() uint32 { return s.port }

func (s *fakeAnchorSession) generation(byte) (uint32, error) {
	s.namespace.mu.Lock()
	defer s.namespace.mu.Unlock()
	return s.namespace.gen, nil
}

func (s *fakeAnchorSession) batch(requests []nftRequest) ([]nftReply, error) {
	s.namespace.mu.Lock()
	defer s.namespace.mu.Unlock()
	s.namespace.batchCalls++
	if s.namespace.batchError != nil {
		return nil, s.namespace.batchError
	}
	working := s.namespace.clone()
	echoes, err := working.applyBatchLocked(requests)
	if err != nil {
		return nil, err
	}
	s.namespace.replaceWith(working)
	s.namespace.gen++
	if s.namespace.loseAckForSubstring != "" {
		for _, request := range requests {
			if strings.Contains(string(request.data), s.namespace.loseAckForSubstring) {
				s.namespace.loseAckForSubstring = ""
				return nil, errNftMetadataTimeout
			}
		}
	}
	if s.namespace.loseAck > 0 {
		s.namespace.loseAck--
		return nil, errNftMetadataTimeout
	}
	return echoes, nil
}

func (s *fakeAnchorSession) dump(typ uint16, family byte, attrs []netlink.Attribute) ([]nftReply, error) {
	s.namespace.mu.Lock()
	defer s.namespace.mu.Unlock()
	switch typ {
	case unix.NFT_MSG_GETTABLE:
		replies := make([]nftReply, 0)
		for name, table := range s.namespace.tables[family] {
			data, _ := netlink.MarshalAttributes([]netlink.Attribute{
				{Type: unix.NFTA_TABLE_NAME, Data: []byte(name + "\x00")},
				{Type: unix.NFTA_TABLE_FLAGS, Data: binary.BigEndian.AppendUint32(nil, table.flags)},
			})
			replies = append(replies, nftReply{typ: uint16(unix.NFNL_SUBSYS_NFTABLES<<8) | unix.NFT_MSG_NEWTABLE,
				data: append(nfgenmsg(family, 0), data...)})
		}
		return replies, nil
	case unix.NFT_MSG_GETCHAIN:
		tableName, _ := fakeAttrString(attrs, unix.NFTA_TABLE_NAME)
		table := s.namespace.tableLocked(family, tableName)
		if table == nil {
			return nil, unix.ENOENT
		}
		names := make([]string, 0, len(table.chains))
		for name := range table.chains {
			names = append(names, name)
		}
		sort.Strings(names)
		replies := make([]nftReply, 0, len(names))
		for _, name := range names {
			chain := table.chains[name]
			chainAttrs := []netlink.Attribute{
				{Type: unix.NFTA_CHAIN_TABLE, Data: []byte(tableName + "\x00")},
				{Type: unix.NFTA_CHAIN_NAME, Data: []byte(name + "\x00")},
			}
			if chain.base {
				hookData, _ := netlink.MarshalAttributes([]netlink.Attribute{
					{Type: unix.NFTA_HOOK_HOOKNUM, Data: binary.BigEndian.AppendUint32(nil, chain.hooknum)},
					{Type: unix.NFTA_HOOK_PRIORITY, Data: binary.BigEndian.AppendUint32(nil, uint32(chain.priority))},
				})
				chainAttrs = append(chainAttrs,
					netlink.Attribute{Type: unix.NLA_F_NESTED | unix.NFTA_CHAIN_HOOK, Data: hookData},
					netlink.Attribute{Type: unix.NFTA_CHAIN_POLICY, Data: binary.BigEndian.AppendUint32(nil, chain.policy)},
					netlink.Attribute{Type: unix.NFTA_CHAIN_TYPE, Data: []byte(chain.kind + "\x00")},
				)
			}
			if chain.userdata != nil {
				chainAttrs = append(chainAttrs, netlink.Attribute{Type: nftAttrChainUserdata, Data: chain.userdata})
			}
			// Native shape: nft_basechain_init sets NFT_CHAIN_BASE in
			// nft_chain.flags for every base chain and
			// nf_tables_fill_chain_info reports the whole flags word, so a
			// model base chain reads back with the intrinsic base bit exactly
			// like the captured native dump. A named regular chain carries no
			// flags at all.
			flags := chain.flags
			if chain.base {
				flags |= nftChainFlagBaseModel
			}
			if flags != 0 {
				chainAttrs = append(chainAttrs, netlink.Attribute{Type: nftAttrChainFlags, Data: binary.BigEndian.AppendUint32(nil, flags)})
			}
			data, _ := netlink.MarshalAttributes(chainAttrs)
			replies = append(replies, nftReply{typ: uint16(unix.NFNL_SUBSYS_NFTABLES<<8) | unix.NFT_MSG_NEWCHAIN,
				data: append(nfgenmsg(family, 0), data...)})
		}
		return replies, nil
	case unix.NFT_MSG_GETRULE:
		tableName, _ := fakeAttrString(attrs, unix.NFTA_RULE_TABLE)
		table := s.namespace.tableLocked(family, tableName)
		if table == nil {
			return nil, unix.ENOENT
		}
		chainFilter, hasFilter := fakeAttrString(attrs, unix.NFTA_RULE_CHAIN)
		names := make([]string, 0, len(table.chains))
		for name := range table.chains {
			names = append(names, name)
		}
		sort.Strings(names)
		replies := make([]nftReply, 0)
		for _, name := range names {
			if hasFilter && name != chainFilter {
				continue
			}
			for _, rule := range table.chains[name].rules {
				data := fakeRuleAttributes(tableName, name, rule)
				replies = append(replies, nftReply{typ: uint16(unix.NFNL_SUBSYS_NFTABLES<<8) | unix.NFT_MSG_NEWRULE,
					data: append(nfgenmsg(family, 0), data...)})
			}
		}
		return replies, nil
	default:
		return nil, unix.EOPNOTSUPP
	}
}

// sendRaw answers a no-attribute queue lookup with the exact kernel -ENODEV
// echo shape. A test can preload another reply to model EPERM/lost/foreign.
func (s *fakeAnchorSession) sendRaw(datagram []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.rawReplies) > 0 {
		return nil
	}
	reply, err := fakeQueueAbsenceReply(datagram, s.port)
	if err != nil {
		return err
	}
	s.rawReplies = append(s.rawReplies, reply)
	s.rawPeer = &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 0, Groups: 0}
	return nil
}

func (s *fakeAnchorSession) recvRaw() ([]byte, *unix.SockaddrNetlink, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.rawReplies) == 0 {
		return nil, nil, errNftMetadataTimeout
	}
	reply := s.rawReplies[0]
	s.rawReplies = s.rawReplies[1:]
	return reply, s.rawPeer, nil
}

func (s *fakeAnchorSession) setRawReply(reply []byte, peer *unix.SockaddrNetlink) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rawReplies = [][]byte{reply}
	s.rawPeer = peer
}

// fakeQueueAbsenceReply builds one NLMSG_ERROR(-ENODEV) whose embedded request
// echo is the exact sent datagram.
func fakeQueueAbsenceReply(datagram []byte, port uint32) ([]byte, error) {
	if len(datagram) < 20 {
		return nil, errors.New("fake nft: short queue lookup")
	}
	length := 20 + len(datagram)
	reply := make([]byte, length)
	binary.NativeEndian.PutUint32(reply[0:], uint32(length))
	binary.NativeEndian.PutUint16(reply[4:], unix.NLMSG_ERROR)
	binary.NativeEndian.PutUint16(reply[6:], 0)
	binary.NativeEndian.PutUint32(reply[8:], binary.NativeEndian.Uint32(datagram[8:]))
	binary.NativeEndian.PutUint32(reply[12:], port)
	code := int32(-int32(unix.ENODEV))
	binary.NativeEndian.PutUint32(reply[16:], uint32(code))
	copy(reply[20:], datagram)
	return reply, nil
}

// fakeFenceTransport answers the exact fence request with the selected
// -EINVAL echo by default. Tests replace reply to model every rejected shape.
type fakeFenceTransport struct {
	port   uint32
	mu     sync.Mutex
	reply  func(request enqueueFenceRequest, port uint32) ([]byte, *unix.SockaddrNetlink, error)
	closed bool
}

func validFenceReply(request enqueueFenceRequest, port uint32) ([]byte, *unix.SockaddrNetlink, error) {
	getgen := request.getgenBytes
	length := 20 + len(getgen)
	reply := make([]byte, length)
	binary.NativeEndian.PutUint32(reply[0:], uint32(length))
	binary.NativeEndian.PutUint16(reply[4:], unix.NLMSG_ERROR)
	binary.NativeEndian.PutUint16(reply[6:], 0)
	binary.NativeEndian.PutUint32(reply[8:], fenceGetgenSequence)
	binary.NativeEndian.PutUint32(reply[12:], port)
	code := int32(-int32(unix.EINVAL))
	binary.NativeEndian.PutUint32(reply[16:], uint32(code))
	copy(reply[20:], getgen)
	return reply, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 0, Groups: 0}, nil
}

func (t *fakeFenceTransport) Close() error      { return nil }
func (t *fakeFenceTransport) boundPort() uint32 { return t.port }
func (t *fakeFenceTransport) send(datagram []byte) error {
	if len(datagram) != 3*fenceMessageBytes {
		return errors.New("fake fence: malformed request datagram")
	}
	lastFenceRequest.Lock()
	lastFenceRequest.request = enqueueFenceRequest{
		datagram:    append([]byte(nil), datagram...),
		getgenBytes: append([]byte(nil), datagram[fenceMessageBytes:2*fenceMessageBytes]...),
	}
	lastFenceRequest.Unlock()
	return nil
}
func (t *fakeFenceTransport) recvDatagram() ([]byte, *unix.SockaddrNetlink, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.reply == nil {
		return nil, nil, errors.New("fake fence: no reply configured")
	}
	return t.reply(lastFenceRequestForTest(), t.port)
}

// ---------------------------------------------------------------------------
// Decoders for the encoded expressions stored by the model.
// ---------------------------------------------------------------------------

type fakeDecodedExpr struct {
	name string
	data map[uint16][]byte
}

// fakeNftCmpLte is NFT_CMP_LTE of the kernel nftables UAPI.
const fakeNftCmpLte = 3

// decodedExpressions decodes the marshaled `expr.Any` list of one rule.
func decodedExpressions(rule *fakeNftRule) ([]fakeDecodedExpr, error) {
	decoded := make([]fakeDecodedExpr, 0, len(rule.expressions))
	for _, raw := range rule.expressions {
		attrs, err := netlink.UnmarshalAttributes(raw)
		if err != nil {
			return nil, err
		}
		expression := fakeDecodedExpr{data: make(map[uint16][]byte)}
		for _, attr := range attrs {
			switch attr.Type & 0x3fff {
			case unix.NFTA_EXPR_NAME:
				name := string(attr.Data)
				for len(name) > 0 && name[len(name)-1] == 0 {
					name = name[:len(name)-1]
				}
				expression.name = name
			case unix.NFTA_EXPR_DATA:
				nested, nestedErr := netlink.UnmarshalAttributes(attr.Data)
				if nestedErr != nil {
					return nil, nestedErr
				}
				for _, nestedAttr := range nested {
					expression.data[nestedAttr.Type&0x3fff] = nestedAttr.Data
				}
			}
		}
		decoded = append(decoded, expression)
	}
	return decoded, nil
}

// fakeRuleQueues returns every queue number one rule targets.
func fakeRuleQueues(rule *fakeNftRule) []uint16 {
	decoded, err := decodedExpressions(rule)
	if err != nil {
		return nil
	}
	queues := make([]uint16, 0, 1)
	for _, expression := range decoded {
		if expression.name != "queue" {
			continue
		}
		if data := expression.data[unix.NFTA_QUEUE_NUM]; len(data) == 2 {
			queues = append(queues, binary.BigEndian.Uint16(data))
		}
	}
	return queues
}

// fakeCmpValue unwraps the NFTA_DATA_VALUE attribute of a cmp expression.
func fakeCmpValue(expression fakeDecodedExpr) []byte {
	raw := expression.data[unix.NFTA_CMP_DATA]
	nested, err := netlink.UnmarshalAttributes(raw)
	if err != nil {
		return raw
	}
	for _, attr := range nested {
		if attr.Type&0x3fff == unix.NFTA_DATA_VALUE {
			return attr.Data
		}
	}
	return raw
}

// fakeRuleHasCtPacketsBound reports the `ct [reply] packets <= N` test of one
// rule, if present.
func fakeRuleHasCtPacketsBound(rule *fakeNftRule) (uint64, bool) {
	decoded, err := decodedExpressions(rule)
	if err != nil {
		return 0, false
	}
	counter := false
	for _, expression := range decoded {
		switch expression.name {
		case "ct":
			if data := expression.data[unix.NFTA_CT_KEY]; len(data) == 4 &&
				binary.BigEndian.Uint32(data) == unix.NFT_CT_PKTS {
				counter = true
			}
		case "cmp":
			if !counter {
				continue
			}
			operator := expression.data[unix.NFTA_CMP_OP]
			value := fakeCmpValue(expression)
			if len(operator) != 4 || len(value) != 8 {
				continue
			}
			if binary.BigEndian.Uint32(operator) == fakeNftCmpLte {
				return binary.BigEndian.Uint64(value), true
			}
		}
	}
	return 0, false
}

// fakeRuleMatchesByte reports whether a rule carries a one-byte comparison
// against the given value (the ICMP type check).
func fakeRuleMatchesByte(rule *fakeNftRule, want byte) bool {
	decoded, err := decodedExpressions(rule)
	if err != nil {
		return false
	}
	for _, expression := range decoded {
		if expression.name != "cmp" {
			continue
		}
		if value := fakeCmpValue(expression); len(value) == 1 && value[0] == want {
			return true
		}
	}
	return false
}

// fakeRulesWithUserdata returns every rule whose userdata contains the marker.
func fakeRulesWithUserdata(namespace *fakeNftNamespace, family byte, tableName, substring string) []*fakeNftRule {
	namespace.mu.Lock()
	defer namespace.mu.Unlock()
	table := namespace.tableLocked(family, tableName)
	if table == nil {
		return nil
	}
	var rules []*fakeNftRule
	for _, chain := range table.chains {
		for _, rule := range chain.rules {
			if substring == "" || len(rule.userdata) > 0 && strings.Contains(string(rule.userdata), substring) {
				rules = append(rules, rule)
			}
		}
	}
	return rules
}

// lastFenceRequestForTest is set by the fake fence send, which records the
// actual datagram the production builder sent.
var lastFenceRequest = struct {
	sync.Mutex
	request enqueueFenceRequest
}{}

func lastFenceRequestForTest() enqueueFenceRequest {
	lastFenceRequest.Lock()
	defer lastFenceRequest.Unlock()
	return lastFenceRequest.request
}

//go:build linux

package desync

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/expr"
	"golang.org/x/sys/unix"
)

const (
	// injectionPriority marks locally generated replacement packets so the
	// owned nftables chain can bypass its own queue and, for ALT11, clear the
	// kernel-assigned IPv4 ID before the packet leaves the host.
	injectionPriority = 0x53590001
	// injectionMarkBit marks replacement packets in the socket mark without
	// disturbing the effective routing mark carried by the original socket.
	injectionMarkBit     = 0x53590000
	nfqueueVerdictAccept = 1
	nfqueueVerdictDrop   = 0

	// NFQUEUE netlink constants (linux/netfilter/nfnetlink_queue.h).
	// Attribute types of NFQNL_MSG_CONFIG.
	nfqCfgAttrCmd      = 1 // NFQA_CFG_CMD, payload nfqnl_msg_config_cmd
	nfqCfgAttrParams   = 2 // NFQA_CFG_PARAMS
	nfqCfgAttrQueueMax = 3 // NFQA_CFG_QUEUE_MAXLEN
	nfqCfgAttrMask     = 4 // NFQA_CFG_MASK
	nfqCfgAttrFlags    = 5 // NFQA_CFG_FLAGS
	// Command values carried in the NFQA_CFG_CMD payload.
	nfqCfgCmdBind    = 1 // NFQNL_CFG_CMD_BIND
	nfqCfgCmdUnbind  = 2 // NFQNL_CFG_CMD_UNBIND
	nfqCfgFlagFail   = 1 << 0
	nfqCfgFlagCT     = 1 << 1
	nfqCfgFlagGSO    = 1 << 2
	nfqPacketID      = 1
	nfqPacketPayload = 10

	// queueCandidates bounds the managed queue allocation attempts. The
	// kernel and /proc reports are authoritative; this is only a search bound.
	queueCandidates = 64
	// queueCapacity bounds the kernel-side queue of one owned capture. It must
	// cover the held originals of one flow plus the initial flight.
	queueCapacity = 8192
	// queueStopDrain bounds the teardown drain of one owned capture. After the
	// owned table is removed, the receive loop keeps answering the packets that
	// are already queued and leaves once a full window passes without a
	// message. The window alone is only an interrupt: it does not prove the
	// queue is empty (see stopReceive), so the final drain is validated with a
	// deadline-independent readiness probe before the queue-control exchange
	// on the same connection.
	queueStopDrain = 10 * time.Millisecond
)

type linuxBackend struct{}

func NewNativeBackend() Backend { return linuxBackend{} }

func (linuxBackend) Name() string { return "linux-nfqueue" }

// nfqueueConn is the NFQUEUE netlink transport of one capture. Production uses
// *netlink.Conn; tests substitute a deterministic in-memory implementation so
// the queue binding identity, the packet delivery and the receive/control
// teardown ordering are exercisable without kernel objects.
//
// The kernel delivers a queued packet to the netlink port that issued the queue
// BIND. Bindings, packet verdicts and the receive loop must therefore live on
// ONE connection: a binding issued on a different socket would deliver every
// captured packet to that other socket, where nothing reads it (the flow stalls
// until the queue is destroyed) and where the unread packet messages corrupt
// the next request/reply exchange of that socket.
//
// The same connection cannot both wait in Receive and run a queue-control
// exchange: netlink.Conn.Receive holds Conn.mu for the whole blocking socket
// read, while Conn.Execute takes the write lock for request and reply. Verdicts
// are unaffected because Conn.Send shares the read side. Teardown therefore
// stops (and drains) the receive loop through SetReadDeadline before it unbinds
// the queues on that connection; an unbind issued against a blocked Receive
// would block forever (D3-L1).
type nfqueueConn interface {
	Receive() ([]netlink.Message, error)
	Execute(netlink.Message) ([]netlink.Message, error)
	Send(netlink.Message) (netlink.Message, error)
	SetReadDeadline(time.Time) error
	// pending reports whether a datagram is already readable on the transport,
	// without consuming it and without consulting the read deadline. A read
	// deadline takes effect only when a read starts, so neither a timeout nor
	// the absence of one can answer this question on its own.
	pending() (bool, error)
	Close() error
}

// openNFQueueConn opens one NETLINK_NETFILTER connection. It is a seam so the
// capture lifecycle can be verified hermetically; production always dials the
// kernel.
var openNFQueueConn = func() (nfqueueConn, error) {
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, err
	}
	return netlinkQueueConn{Conn: conn}, nil
}

// netlinkQueueConn is the production NFQUEUE transport. pending is implemented
// with a non-blocking peek on the socket itself: the poll deadline is applied
// when a read is prepared, not when data arrives, so a goroutine that resumes
// after the deadline expired observes os.ErrDeadlineExceeded without the
// kernel ever having been asked whether a packet is waiting.
type netlinkQueueConn struct {
	*netlink.Conn
}

func (c netlinkQueueConn) pending() (bool, error) {
	raw, err := c.Conn.SyscallConn()
	if err != nil {
		return false, err
	}
	var (
		readable bool
		peekErr  error
	)
	if err := raw.Control(func(fd uintptr) {
		buffer := make([]byte, 1)
		n, _, err := unix.Recvfrom(int(fd), buffer, unix.MSG_PEEK|unix.MSG_DONTWAIT|unix.MSG_TRUNC)
		switch {
		case err == nil:
			readable = n > 0
		case errors.Is(err, unix.EAGAIN):
			readable = false
		default:
			peekErr = err
		}
	}); err != nil {
		return false, err
	}
	return readable, peekErr
}

// linuxRuleWriter is the nftables transaction surface of one capture. The
// production value is *nftables.Conn; the seam keeps the owned-table
// lifecycle verifiable without a netfilter socket.
type linuxRuleWriter interface {
	AddTable(*nftables.Table) *nftables.Table
	AddChain(*nftables.Chain) *nftables.Chain
	AddRule(*nftables.Rule) *nftables.Rule
	DelTable(*nftables.Table)
	Flush() error
}

var newLinuxRuleWriter = func() linuxRuleWriter { return &nftables.Conn{} }

func (linuxBackend) Open(lease *Lease) (Capture, error) {
	return openLinuxCapture(lease)
}

var linuxQueueCounter atomic.Uint32

func init() {
	linuxQueueCounter.Store(uint32(os.Getpid())*7 + 1000)
}

// prepareSocket is called from the dialer's per-attempt Control hook, after all
// existing interface/mark/netns controls and before connect/send. It binds the
// exclusive local port and establishes capture ownership for the exact tuple.
func prepareSocket(lease *Lease, fd uintptr) error {
	intent := lease.Intent()
	socketFd := int(fd)
	var bindSockaddr unix.Sockaddr
	switch intent.Family {
	case FamilyIPv4:
		sockaddr := &unix.SockaddrInet4{}
		if intent.Source.IsValid() && intent.Source.Addr().Is4() {
			sockaddr.Addr = intent.Source.Addr().As4()
		}
		bindSockaddr = sockaddr
	case FamilyIPv6:
		sockaddr := &unix.SockaddrInet6{}
		if intent.Source.IsValid() && intent.Source.Addr().Is6() {
			sockaddr.Addr = intent.Source.Addr().As16()
			if intent.Source.Addr().Zone() != "" {
				iface, err := net.InterfaceByName(intent.Source.Addr().Zone())
				if err != nil {
					return fmt.Errorf("desync: resolve zone %s: %w", intent.Source.Addr().Zone(), err)
				}
				sockaddr.ZoneId = uint32(iface.Index)
			}
		}
		bindSockaddr = sockaddr
	default:
		return fmt.Errorf("desync: unsupported address family")
	}
	if err := unix.Bind(socketFd, bindSockaddr); err != nil {
		return fmt.Errorf("desync: bind exclusive local port: %w", err)
	}
	sockaddr, err := unix.Getsockname(socketFd)
	if err != nil {
		return fmt.Errorf("desync: read bound local endpoint: %w", err)
	}
	var local netip.AddrPort
	switch value := sockaddr.(type) {
	case *unix.SockaddrInet4:
		local = netip.AddrPortFrom(netip.AddrFrom4(value.Addr), uint16(value.Port))
	case *unix.SockaddrInet6:
		local = netip.AddrPortFrom(netip.AddrFrom16(value.Addr), uint16(value.Port))
	default:
		return fmt.Errorf("desync: unexpected local endpoint family")
	}
	lease.SetLocalAddress(local)
	mark, markErr := unix.GetsockoptInt(socketFd, unix.SOL_SOCKET, unix.SO_MARK)
	if markErr == nil {
		lease.setSocketMark(mark)
	}
	device, deviceErr := unix.GetsockoptString(socketFd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	if deviceErr == nil {
		lease.setSocketDevice(device)
	}
	return lease.StartCapture()
}

type linuxCapture struct {
	lease        *Lease
	queue        uint16 // owned outbound queue
	inQueue      uint16 // owned inbound observation queue
	icmpQueue    uint16 // owned ICMP-error queue (only when configured)
	overrideQnum int
	// nl is the single NFQUEUE connection of this capture: it binds the owned
	// queues, receives their packets, sends their verdicts and unbinds them.
	// One connection is required because NFQUEUE delivers a queued packet to
	// the portid that issued the BIND.
	nl    nfqueueConn
	nft   linuxRuleWriter
	table *nftables.Table
	bound bool
	// started reports whether the receive loop owns the connection.
	started bool
	// stopping requests the receive loop to drain and exit on its next wake.
	stopping atomic.Bool

	// sendMu serializes netlink verdicts: the capture loop and the hold
	// release path (timer goroutine) both send on the same connection.
	sendMu sync.Mutex

	rawMu sync.Mutex
	raw4  int
	raw6  int
	dst4  *unix.SockaddrInet4
	dst6  *unix.SockaddrInet6

	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func openLinuxCapture(lease *Lease) (Capture, error) {
	endpoint := lease.Endpoint()
	if !endpoint.Source.IsValid() || endpoint.Source.Port() == 0 {
		return nil, fmt.Errorf("desync: capture requires an owned local endpoint")
	}
	capture := &linuxCapture{
		lease: lease,
		raw4:  -1,
		raw6:  -1,
		done:  make(chan struct{}),
	}
	if endpoint.Destination.IsValid() {
		switch endpoint.Family {
		case FamilyIPv4:
			capture.dst4 = &unix.SockaddrInet4{Port: int(endpoint.Destination.Port())}
			capture.dst4.Addr = endpoint.Destination.Addr().As4()
		case FamilyIPv6:
			capture.dst6 = &unix.SockaddrInet6{Port: int(endpoint.Destination.Port())}
			capture.dst6.Addr = endpoint.Destination.Addr().As16()
		}
	}
	nl, err := openNFQueueConn()
	if err != nil {
		return nil, err
	}
	capture.nl = nl
	queue, inQueue, err := capture.acquireQueues(endpoint)
	if err != nil {
		_ = nl.Close()
		return nil, err
	}
	capture.queue, capture.inQueue, capture.bound = queue, inQueue, true
	if capture.wantsICMPFilter() {
		icmpQueue, err := capture.acquireICMPQueue(endpoint, queue, inQueue)
		if err != nil {
			capture.unbindQueues()
			_ = nl.Close()
			return nil, err
		}
		capture.icmpQueue = icmpQueue
	}
	if err = capture.installRules(endpoint); err != nil {
		capture.unbindQueues()
		_ = nl.Close()
		return nil, err
	}
	capture.started = true
	go capture.loop()
	return capture, nil
}

// acquireQueues allocates two managed queue identities from a bounded
// candidate window. A candidate is skipped when /proc reports it in use or when
// the actual NFQUEUE bind fails; a failure never touches the foreign queue. The
// allocation rolls back its own successful bind when the second queue cannot be
// acquired.
func (c *linuxCapture) acquireQueues(endpoint Endpoint) (uint16, uint16, error) {
	if configured := c.lease.engine.Config().Capture; configured.qnumSet {
		if configured.qnum < 0 || configured.qnum > 65535 {
			return 0, 0, fmt.Errorf("desync: capture.linux.qnum %d outside 0..65535", configured.qnum)
		}
		if linuxQueueInUse(uint16(configured.qnum)) {
			return 0, 0, fmt.Errorf("desync: capture.linux.qnum %d is bound by another listener", configured.qnum)
		}
		if err := reserveQnum(configured.qnum); err != nil {
			return 0, 0, err
		}
		out, err := c.bindQueue(uint16(configured.qnum), endpoint.Family)
		if err != nil {
			releaseQnum(configured.qnum)
			return 0, 0, err
		}
		c.overrideQnum = configured.qnum
		start := uint16(managedQueueBase + (linuxQueueCounter.Add(1)*7)%managedQueueSpan)
		inCandidates := nextFreeQueues(start, 1, func(queue uint16) bool {
			return uint16(configured.qnum) == queue || linuxQueueInUse(queue)
		})
		if len(inCandidates) < 1 {
			_ = c.unbindQueue(out, endpoint.Family)
			releaseQnum(configured.qnum)
			return 0, 0, fmt.Errorf("desync: no free inbound NFQUEUE identity")
		}
		in, err := c.bindQueue(inCandidates[0], endpoint.Family)
		if err != nil {
			_ = c.unbindQueue(out, endpoint.Family)
			releaseQnum(configured.qnum)
			return 0, 0, err
		}
		return out, in, nil
	}
	start := uint16(managedQueueBase + (linuxQueueCounter.Add(1)*7)%managedQueueSpan)
	if start < managedQueueBase {
		start = managedQueueBase
	}
	candidates := nextFreeQueues(start, 2, func(queue uint16) bool {
		return qnumLive(int(queue)) || linuxQueueInUse(queue)
	})
	if len(candidates) < 2 {
		return 0, 0, fmt.Errorf("desync: no free NFQUEUE identity in the managed range")
	}
	out, err := c.bindQueue(candidates[0], endpoint.Family)
	if err != nil {
		return 0, 0, err
	}
	in, err := c.bindQueue(candidates[1], endpoint.Family)
	if err != nil {
		_ = c.unbindQueue(out, endpoint.Family)
		return 0, 0, err
	}
	return out, in, nil
}

// acquireICMPQueue binds one additional managed queue for the owned ICMP-error
// rule. It is only called when capture.filter_ttl_expired_icmp is enabled, so a
// default configuration keeps exactly the previous two queue bindings.
func (c *linuxCapture) acquireICMPQueue(endpoint Endpoint, outbound uint16, inbound uint16) (uint16, error) {
	start := uint16(managedQueueBase + (linuxQueueCounter.Add(1)*7)%managedQueueSpan)
	candidates := nextFreeQueues(start, 1, func(queue uint16) bool {
		return queue == outbound || queue == inbound || qnumLive(int(queue)) || linuxQueueInUse(queue)
	})
	if len(candidates) < 1 {
		return 0, fmt.Errorf("desync: no free ICMP NFQUEUE identity in the managed range")
	}
	queue, err := c.bindQueue(candidates[0], endpoint.Family)
	if err != nil {
		return 0, err
	}
	return queue, nil
}

// linuxQueueReportPath is the kernel's bound-queue report. It is read-only and
// overridable in tests so queue identity allocation is verifiable without
// touching host networking.
var linuxQueueReportPath = "/proc/net/netfilter/nfnetlink_queue"

// linuxQueueInUse reports whether the kernel currently has a listener bound to
// the queue in this network namespace.
func linuxQueueInUse(queue uint16) bool {
	return queueInUseReport(linuxQueueReportPath, queue)
}

func queueInUseReport(path string, queue uint16) bool {
	content, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	needle := strconv.Itoa(int(queue))
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == needle {
			return true
		}
	}
	return false
}

// nextFreeQueues returns up to count managed queue identities at or after start
// that the inUse report does not list. Allocation is bounded: fewer candidates
// than requested is a hard failure, never a wrap-around into an unmanaged range.
func nextFreeQueues(start uint16, count int, inUse func(uint16) bool) []uint16 {
	if start < managedQueueBase {
		start = managedQueueBase
	}
	candidates := make([]uint16, 0, count)
	for index := 0; index < queueCandidates && len(candidates) < count; index++ {
		candidate := start + uint16(index)
		if inUse(candidate) {
			continue
		}
		candidates = append(candidates, candidate)
	}
	return candidates
}

func (c *linuxCapture) bindQueue(queue uint16, family Family) (uint16, error) {
	if err := c.configureOn(queue, family, []netlink.Attribute{
		{Type: nfqCfgAttrCmd, Data: []byte{nfqCfgCmdBind, 0, 0, transactionFamily(family)}},
	}); err != nil {
		return 0, fmt.Errorf("desync: bind NFQUEUE %d: %w", queue, err)
	}
	// Always declare the queue parameters explicitly. Clearing the GSO flag
	// (and masking it) makes the kernel segment large/offloaded packets before
	// delivery, so every captured packet is one wire-shaped packet and the
	// semantic counters and transforms see real payload lengths.
	flags := make([]byte, 4)
	binary.BigEndian.PutUint32(flags, nfqCfgFlagFail)
	mask := make([]byte, 4)
	binary.BigEndian.PutUint32(mask, nfqCfgFlagFail|nfqCfgFlagGSO|nfqCfgFlagCT)
	capacity := make([]byte, 4)
	binary.BigEndian.PutUint32(capacity, queueCapacity)
	params := []netlink.Attribute{
		{Type: nfqCfgAttrQueueMax, Data: capacity},
		{Type: nfqCfgAttrMask, Data: mask},
		{Type: nfqCfgAttrFlags, Data: flags},
		{Type: nfqCfgAttrParams, Data: []byte{0, 0, 0xff, 0xff, 2}},
	}
	if err := c.configureOn(queue, family, params); err != nil {
		_ = c.unbindQueue(queue, family)
		return 0, fmt.Errorf("desync: configure NFQUEUE %d: %w", queue, err)
	}
	return queue, nil
}

func (c *linuxCapture) unbindQueues() error {
	if !c.bound {
		return nil
	}
	endpoint := c.lease.Endpoint()
	var firstErr error
	if c.icmpQueue != 0 {
		if err := c.unbindQueue(c.icmpQueue, endpoint.Family); err != nil {
			firstErr = err
		}
	}
	if err := c.unbindQueue(c.inQueue, endpoint.Family); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := c.unbindQueue(c.queue, endpoint.Family); err != nil && firstErr == nil {
		firstErr = err
	}
	c.bound = false
	return firstErr
}

func (c *linuxCapture) unbindQueue(queue uint16, family Family) error {
	if queue == 0 {
		return nil
	}
	// NFQA_CFG_CMD carries the command byte. Sending the unbind command in
	// NFQA_CFG_PARAMS (the previous shape) was rejected by the kernel and the
	// error was discarded, so the queue stayed bound after teardown.
	return c.configureOn(queue, family, []netlink.Attribute{
		{Type: nfqCfgAttrCmd, Data: []byte{nfqCfgCmdUnbind, 0, 0, transactionFamily(family)}},
	})
}

func transactionFamily(family Family) byte {
	if family == FamilyIPv6 {
		return unix.AF_INET6
	}
	return unix.AF_INET
}

func (c *linuxCapture) installRules(endpoint Endpoint) (err error) {
	c.nft = newLinuxRuleWriter()
	family := nftables.TableFamilyIPv4
	if endpoint.Family == FamilyIPv6 {
		family = nftables.TableFamilyIPv6
	}
	c.table = c.nft.AddTable(&nftables.Table{Family: family,
		Name: fmt.Sprintf("sb_dsync_%d_%d", os.Getpid(), c.queue)})
	chain := c.nft.AddChain(&nftables.Chain{Table: c.table, Name: "output",
		Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityMangle})
	defer func() {
		if err != nil {
			c.nft.DelTable(c.table)
			_ = c.nft.Flush()
			c.table = nil
		}
	}()
	priority := make([]byte, 4)
	binary.NativeEndian.PutUint32(priority, injectionPriority)
	// Rule 1: replacement packets generated through our own injection socket
	// bypass this engine's queue. For IPv4 the ALT11 ip-id=zero contract is
	// enforced here, after the kernel has normalized the raw-socket header.
	bypass := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyPRIORITY, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: priority},
	}
	if endpoint.Family == FamilyIPv4 && c.lease.engine.config.RequiresZeroIPID() {
		bypass = append(bypass,
			&expr.Immediate{Register: 1, Data: []byte{0, 0}},
			&expr.Payload{OperationType: expr.PayloadWrite, SourceRegister: 1,
				Base: expr.PayloadBaseNetworkHeader, Offset: 4, Len: 2,
				CsumType: expr.CsumTypeInet, CsumOffset: 10},
		)
	}
	bypass = append(bypass, &expr.Verdict{Kind: expr.VerdictAccept})
	c.nft.AddRule(&nftables.Rule{Table: c.table, Chain: chain, Exprs: bypass})

	protocol := byte(unix.IPPROTO_TCP)
	if endpoint.Transport == TransportUDP {
		protocol = unix.IPPROTO_UDP
	}
	rules := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocol}},
	}
	// The owned native attempt's actual output device narrows the rule. An
	// unbound attempt has no name here and is never given an invented one.
	if endpoint.Interface != "" {
		rules = append(rules, interfaceNameCompare(expr.MetaKeyOIFNAME, endpoint.Interface)...)
	}
	addresses := make([]byte, 0, 32)
	sourceAddressSpecified := endpoint.Source.IsValid() && !endpoint.Source.Addr().IsUnspecified()
	if sourceAddressSpecified && endpoint.Destination.IsValid() {
		addresses = append(addresses, endpoint.Source.Addr().AsSlice()...)
		addresses = append(addresses, endpoint.Destination.Addr().AsSlice()...)
		rules = append(rules,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: uint32(len(addresses))},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addresses})
	}
	ports := make([]byte, 4)
	binary.BigEndian.PutUint16(ports[:2], endpoint.Source.Port())
	binary.BigEndian.PutUint16(ports[2:], endpoint.Destination.Port())
	if endpoint.Destination.IsValid() {
		rules = append(rules,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ports})
	} else {
		// Listener ownership: only the local port is fixed; the destination is
		// the per-peer discriminator. Match the local port alone.
		rules = append(rules,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ports[:2]})
	}
	// NFQWS_*_PKT_OUT: a bounded direction keeps only the configured kernel
	// conntrack packets and an explicit zero disables the direction entirely.
	// Either way the limit lives in the owned queue rule, before any semantic
	// rule eligibility, and ownership/cleanup are unaffected.
	outboundLimit := c.lease.engine.Config().Capture.limits.direction(endpoint.Transport, true)
	if outboundLimit.enabled() {
		if expressions := c.outboundLimitExpressions(endpoint, outboundLimit); len(expressions) > 0 {
			rules = append(rules, expressions...)
		}
		rules = append(rules, &expr.Queue{Num: c.queue, Flag: expr.QueueFlagBypass})
		c.nft.AddRule(&nftables.Rule{Table: c.table, Chain: chain, Exprs: rules})
	}

	// A narrowly scoped reply-side queue observes the reverse of the owned
	// tuple. Replies are always passed and never re-injected; they only feed
	// handshake/sequence/ack/window observations. The separate queue number is
	// what preserves the direction.
	inputChain := c.nft.AddChain(&nftables.Chain{Table: c.table, Name: "input",
		Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookInput,
		Priority: nftables.ChainPriorityMangle})
	inputRules := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocol}},
	}
	// Reply observations are bound to the same owned device (input direction).
	if endpoint.Interface != "" {
		inputRules = append(inputRules, interfaceNameCompare(expr.MetaKeyIIFNAME, endpoint.Interface)...)
	}
	if sourceAddressSpecified && endpoint.Destination.IsValid() {
		reverseAddresses := make([]byte, 0, 32)
		reverseAddresses = append(reverseAddresses, endpoint.Destination.Addr().AsSlice()...)
		reverseAddresses = append(reverseAddresses, endpoint.Source.Addr().AsSlice()...)
		inputRules = append(inputRules,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: uint32(len(reverseAddresses))},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: reverseAddresses})
	}
	reversePorts := make([]byte, 4)
	binary.BigEndian.PutUint16(reversePorts[:2], endpoint.Destination.Port())
	binary.BigEndian.PutUint16(reversePorts[2:], endpoint.Source.Port())
	if endpoint.Destination.IsValid() {
		inputRules = append(inputRules,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: reversePorts})
	} else {
		inputRules = append(inputRules,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: reversePorts[2:]})
	}
	// NFQWS_*_PKT_IN: a zero inbound bound disables the reply-side capture, so
	// neither the queue rule nor its observations are installed. A positive
	// inbound bound is rejected at compile time because the pinned nftables
	// API cannot express the reply-direction kernel packet counter; matching
	// the original direction here would capture the wrong packets.
	inboundLimit := c.lease.engine.Config().Capture.limits.direction(endpoint.Transport, false)
	if inboundLimit.enabled() {
		if inboundLimit.bounded() {
			// A positive reply bound is the `ct reply packets 1-N` kernel
			// counter. The pinned nftables API cannot emit its direction, so
			// the rule is sent as one owned batch after the library
			// transaction (nft_reply_limit_linux.go). The bound never falls
			// back to the original direction.
			return c.installReplyLimitRule(inputRules, inboundLimit)
		}
		inputRules = append(inputRules, &expr.Queue{Num: c.inQueue, Flag: expr.QueueFlagBypass})
		c.nft.AddRule(&nftables.Rule{Table: c.table, Chain: inputChain, Exprs: inputRules})
	}
	if c.wantsICMPFilter() {
		// The ICMP time-exceeded queue is an additional, narrowly scoped
		// rule of the same owned table. It never drops by itself: every
		// packet it captures is validated against the owned tuple in the
		// receive loop and foreign errors are passed unchanged.
		c.nft.AddRule(&nftables.Rule{Table: c.table, Chain: inputChain, Exprs: c.icmpErrorRule(endpoint)})
	}
	return c.nft.Flush()
}

// installReplyLimitRule installs the bounded reply rule. Table, chain and all
// other rules are committed by the library first; the reply rule is then sent
// as a single nftables batch because only the direction attribute of the ct
// packet counter is outside the pinned library. A failure is a real activation
// error: capture is never silently widened to an unlimited reply direction.
func (c *linuxCapture) installReplyLimitRule(inputRules []expr.Any, limit packetLimit) error {
	if err := c.nft.Flush(); err != nil {
		return err
	}
	family := byte(nftables.TableFamilyIPv4)
	if c.lease.Endpoint().Family == FamilyIPv6 {
		family = byte(nftables.TableFamilyIPv6)
	}
	expressions := make([][]byte, 0, len(inputRules)+3)
	for _, expression := range inputRules {
		encoded, err := expr.Marshal(family, expression)
		if err != nil {
			return err
		}
		expressions = append(expressions, encoded)
	}
	ctExpression, comparison, err := replyLimitExpressions(limit)
	if err != nil {
		return err
	}
	queue, err := expr.Marshal(family, &expr.Queue{Num: c.inQueue, Flag: expr.QueueFlagBypass})
	if err != nil {
		return err
	}
	expressions = append(expressions, ctExpression, comparison, queue)
	batch, err := marshalRuleBatch(family, c.table.Name, "input", expressions)
	if err != nil {
		return err
	}
	sender, err := newNftBatchSender()
	if err != nil {
		return err
	}
	defer sender.Close()
	return sender.Send(batch)
}

// wantsICMPFilter reports whether owned quoted-ICMP filtering is enabled.
func (c *linuxCapture) wantsICMPFilter() bool {
	return c.lease.engine.Config().Capture.filterTTLExpiredICMP
}

// icmpErrorRule is the owned time-exceeded queue rule. It matches the capture's
// own family, the time-exceeded ICMP type, the owned interface (when the native
// attempt is interface-bound) and, when the local address is known, the quoted
// inner source address at its fixed offset. IPv4 additionally requires a plain
// 20-byte outer header so that fixed offset is exactly the quoted inner header.
// Parameter-problem messages are deliberately not matched.
func (c *linuxCapture) icmpErrorRule(endpoint Endpoint) []expr.Any {
	protocol := byte(unix.IPPROTO_ICMP)
	icmpType := byte(11)
	if endpoint.Family == FamilyIPv6 {
		protocol = byte(unix.IPPROTO_ICMPV6)
		icmpType = 3
	}
	rules := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocol}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{icmpType}},
	}
	if endpoint.Interface != "" {
		rules = append(rules, interfaceNameCompare(expr.MetaKeyIIFNAME, endpoint.Interface)...)
	}
	local := endpoint.Source
	if local.IsValid() && !local.Addr().IsUnspecified() {
		address := local.Addr()
		if endpoint.Family == FamilyIPv4 && !address.Is4() {
			address = netip.Addr{}
		}
		if endpoint.Family == FamilyIPv6 && (address.Is4() || !address.Is6()) {
			address = netip.Addr{}
		}
		if address.IsValid() {
			if endpoint.Family == FamilyIPv4 {
				// Fixed offsets require the outer IPv4 header to have no
				// options: 20-byte IP header + 8-byte ICMP header = 28, and
				// the quoted inner source address is at 28+12 = 40.
				rules = append(rules,
					&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 0, Len: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x45}})
			}
			rules = append(rules, innerQuotedSourceCompare(endpoint.Family, address)...)
		}
	}
	return append(rules, &expr.Queue{Num: c.icmpQueue, Flag: expr.QueueFlagBypass})
}

// innerQuotedSourceCompare matches the quoted inner source address of a captured
// ICMP error. The offsets are the parsed quote offsets of this package:
// IPv4 ::= 20-byte header + 8-byte ICMP header + 12; IPv6 ::= 40-byte header +
// 8-byte ICMPv6 header + 8.
func innerQuotedSourceCompare(family Family, address netip.Addr) []expr.Any {
	offset := uint32(40)
	data := address.AsSlice()
	if family == FamilyIPv6 {
		offset = 56
	}
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: uint32(len(data))},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data},
	}
}

// outboundLimitExpressions builds the kernel conntrack packet bound of the
// owned output rule. The source uses the inclusive `ct original packets 1-N`
// range; conntrack counters start at one, so `packets <= N` selects exactly the
// same set. A keepalive destination port removes only this outgoing bound
// (source NFQWS_PORTS_*_KEEPALIVE is a separate, unlimited-out rule set).
func (c *linuxCapture) outboundLimitExpressions(endpoint Endpoint, limit packetLimit) []expr.Any {
	if !limit.bounded() {
		return nil
	}
	if endpoint.Destination.IsValid() &&
		c.lease.engine.Config().Capture.keepalive.contains(endpoint.Transport, endpoint.Destination.Port()) {
		return nil
	}
	value := make([]byte, 8)
	binary.BigEndian.PutUint64(value, uint64(limit.value))
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeyPKTS},
		&expr.Cmp{Op: expr.CmpOpLte, Register: 1, Data: value},
	}
}

// interfaceNameCompare builds the meta iifname/oifname equality test of one
// owned interface. nftables string data is padded to a 4-byte boundary.
func interfaceNameCompare(key expr.MetaKey, name string) []expr.Any {
	data := []byte(name)
	if pad := len(data) % 4; pad != 0 {
		data = append(data, make([]byte, 4-pad)...)
	}
	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data},
	}
}

func (c *linuxCapture) messageOn(queue uint16, family Family, typ uint16, attrs []netlink.Attribute, ack bool) (netlink.Message, error) {
	data, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return netlink.Message{}, err
	}
	header := []byte{transactionFamily(family), 0, byte(queue >> 8), byte(queue)}
	flags := netlink.Request
	if ack {
		flags |= netlink.Acknowledge
	}
	return netlink.Message{Header: netlink.Header{Type: netlink.HeaderType(3<<8 | typ), Flags: flags}, Data: append(header, data...)}, nil
}

func (c *linuxCapture) message(typ uint16, attrs []netlink.Attribute, ack bool) (netlink.Message, error) {
	return c.messageOn(c.queue, c.lease.Endpoint().Family, typ, attrs, ack)
}

// configureOn performs one NFQNL_MSG_CONFIG request/reply exchange on the
// capture's only connection. It is only reached while the receive loop is not
// running: at open, before the loop starts, and at teardown, after the loop has
// drained and been joined. That ordering is what keeps the exchange off a lock
// held by a blocked receive and keeps an unread packet message from being
// validated as this request's reply.
func (c *linuxCapture) configureOn(queue uint16, family Family, attrs []netlink.Attribute) error {
	message, err := c.messageOn(queue, family, 2, attrs, true)
	if err != nil {
		return err
	}
	if c.nl == nil {
		return fmt.Errorf("desync: NFQUEUE connection is not open")
	}
	_, err = c.nl.Execute(message)
	return err
}

// sendVerdict delivers the one terminal disposition of a captured packet. It is
// also the completer of a held packet, therefore it must be safe to call from
// the release path and must tolerate a closed connection.
func (c *linuxCapture) sendVerdict(queue uint16, id []byte, verdict Verdict, reason string, modified []byte) {
	nativeVerdict := uint32(nfqueueVerdictAccept)
	if verdict == VerdictDrop {
		nativeVerdict = nfqueueVerdictDrop
	}
	value := make([]byte, 8)
	binary.BigEndian.PutUint32(value[:4], nativeVerdict)
	copy(value[4:], id)
	attributes := []netlink.Attribute{{Type: 2, Data: value}}
	if verdict == VerdictModify && len(modified) > 0 {
		// NFQA_PAYLOAD carries the in-place replacement bytes with NF_ACCEPT.
		// This never re-egresses an INPUT packet through the raw socket: the
		// kernel continues its normal inbound path with these bytes.
		attributes = append(attributes, netlink.Attribute{Type: 1, Data: modified})
	}
	message, err := c.messageOn(queue, c.lease.Endpoint().Family, 1, attributes, false)
	if err != nil {
		return
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	_, _ = c.nl.Send(message)
}

func (c *linuxCapture) loop() {
	defer close(c.done)
	for {
		messages, err := c.nl.Receive()
		if err != nil {
			return
		}
		if !c.handleBatch(messages) {
			return
		}
		if c.stopping.Load() {
			// Teardown is draining. Extend the window after every answered
			// batch so a packet that was already queued is still answered
			// instead of being dropped by the queue destroy, and so the final
			// timeout really means "nothing left on this socket". An arm
			// failure ends the loop; Close reports it.
			if err := c.nl.SetReadDeadline(time.Now().Add(queueStopDrain)); err != nil {
				return
			}
		}
	}
}

// handleBatch answers every owned packet message of one receive batch. It
// returns false when the batch cannot be parsed, which terminates the receive
// loop and the teardown drain alike.
func (c *linuxCapture) handleBatch(messages []netlink.Message) bool {
	for _, message := range messages {
		if uint16(message.Header.Type) != 3<<8 || len(message.Data) < 4 {
			continue
		}
		queue := binary.BigEndian.Uint16(message.Data[2:4])
		if queue != c.queue && queue != c.inQueue && queue != c.icmpQueue {
			// Never answer a verdict for a queue this capture does not own.
			continue
		}
		attributes, err := netlink.UnmarshalAttributes(message.Data[4:])
		if err != nil {
			return false
		}
		var (
			id    []byte
			frame []byte
		)
		for _, attribute := range attributes {
			switch attribute.Type & 0x3fff {
			case nfqPacketID:
				if len(attribute.Data) >= 4 {
					id = append([]byte(nil), attribute.Data[:4]...)
				}
			case nfqPacketPayload:
				frame = attribute.Data
			}
		}
		if len(id) != 4 || len(frame) == 0 {
			continue
		}
		if c.icmpQueue != 0 && queue == c.icmpQueue {
			// A captured ICMP/ICMPv6 error is never transformed and never
			// reaches the packet planner: it is either dropped as a
			// validated owned low-hop error or passed unchanged.
			verdict := VerdictPass
			if c.lease.HandleICMPTimeExceeded(frame) {
				verdict = VerdictDrop
			}
			c.sendVerdict(queue, id, verdict, "", nil)
			continue
		}
		direction := DirectionOutbound
		if queue == c.inQueue {
			direction = DirectionInbound
		}
		packetQueue := queue
		packetID := id
		complete := func(verdict Verdict, reason string, modified []byte) {
			// The completer owns this captured packet's terminal disposition,
			// including the exact in-place bytes of a held Modify.
			c.sendVerdict(packetQueue, packetID, verdict, reason, modified)
		}
		verdict := c.lease.HandlePacket(frame, direction, c.inject, complete)
		if verdict == VerdictHold {
			// The completer owns the verdict; no native disposition now.
			continue
		}
		modified := []byte(nil)
		if verdict == VerdictModify {
			modified = c.lease.TakeModified(DirectionOutbound)
		}
		c.sendVerdict(packetQueue, packetID, verdict, "", modified)
	}
	return true
}

func (c *linuxCapture) inject(packet []byte) error {
	parsed, err := ParsePacket(packet)
	if err != nil {
		return err
	}
	c.rawMu.Lock()
	defer c.rawMu.Unlock()
	switch parsed.Family {
	case FamilyIPv4:
		if c.raw4 < 0 {
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
			if err != nil {
				return err
			}
			if err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
				unix.Close(fd)
				return err
			}
			if bindSource(c.lease.engine.Config().Capture, FamilyIPv4) {
				bindInjectionSource(fd, FamilyIPv4, parsed.Src)
			}
			if mark := injectionMark(c.lease.socketMark(), c.lease.engine.Config().Capture); mark != 0 {
				_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, mark)
			}
			if device := c.lease.socketDevice(); device != "" {
				_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, device)
			}
			if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PRIORITY, injectionPriority); err != nil {
				unix.Close(fd)
				return err
			}
			c.raw4 = fd
		}
		destination := c.dst4
		if destination == nil {
			destination = &unix.SockaddrInet4{Port: int(parsed.DstPort)}
			destination.Addr = parsed.Dst.As4()
		}
		err := unix.Sendto(c.raw4, packet, 0, destination)
		if err == nil {
			c.lease.noteInjection()
		}
		return err
	case FamilyIPv6:
		if c.raw6 < 0 {
			fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
			if err != nil {
				return err
			}
			if bindSource(c.lease.engine.Config().Capture, FamilyIPv6) {
				bindInjectionSource(fd, FamilyIPv6, parsed.Src)
			}
			if mark := injectionMark(c.lease.socketMark(), c.lease.engine.Config().Capture); mark != 0 {
				_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, mark)
			}
			if device := c.lease.socketDevice(); device != "" {
				_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, device)
			}
			if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PRIORITY, injectionPriority); err != nil {
				unix.Close(fd)
				return err
			}
			c.raw6 = fd
		}
		destination := c.dst6
		if destination == nil {
			destination = &unix.SockaddrInet6{Port: int(parsed.DstPort)}
			destination.Addr = parsed.Dst.As16()
		}
		err := unix.Sendto(c.raw6, packet, 0, destination)
		if err == nil {
			c.lease.noteInjection()
		}
		return err
	default:
		return fmt.Errorf("desync: unsupported injection family")
	}
}

// bindInjectionSource ports the upstream bind-fix4/bind-fix6 behavior of
// rawsend: bind the raw socket to the source address carried by the generated
// packet. A refused bind is ignored ("bind (ignoring)" in nfq/darkmagic.c), so
// the socket keeps sending through the owned device as before.
func bindInjectionSource(fd int, family Family, source netip.Addr) {
	if !source.IsValid() {
		return
	}
	var sockaddr unix.Sockaddr
	switch family {
	case FamilyIPv4:
		if !source.Is4() {
			return
		}
		value := &unix.SockaddrInet4{Addr: source.As4()}
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_FREEBIND, 1)
		sockaddr = value
	case FamilyIPv6:
		if !source.Is6() {
			return
		}
		value := &unix.SockaddrInet6{Addr: source.As16()}
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_FREEBIND, 1)
		sockaddr = value
	default:
		return
	}
	_ = unix.Bind(fd, sockaddr)
}

// stopReceive ends the receive loop of an open capture without closing the
// connection. It arms the bounded teardown window, waits until the loop is
// interrupted and joined, answers whatever is still readable on the owned
// queues, and clears the deadline so the following queue-control exchange on
// the same connection is not rejected by an expired read deadline.
func (c *linuxCapture) stopReceive() error {
	if c.nl == nil || !c.started {
		return nil
	}
	c.stopping.Store(true)
	if err := c.nl.SetReadDeadline(time.Now().Add(queueStopDrain)); err != nil {
		// The transport cannot interrupt a blocked receive with a deadline.
		// Closing the connection is the only interrupt left, and it also makes
		// the owned queue bindings unreachable for an explicit unbind, so the
		// failure is reported instead of being turned into a silent leak.
		_ = c.nl.Close()
		<-c.done
		return fmt.Errorf("desync: stop NFQUEUE receive: %w", err)
	}
	<-c.done
	// Joining the loop is not the same as proving the queue is empty. A read
	// deadline takes effect when a read is prepared: a receive goroutine that
	// is not scheduled again until the deadline has already expired gets a
	// timeout back without the kernel ever being asked, even though a packet
	// of this owned flow is queued and readable. Unread packet messages would
	// then be consumed by the following queue-control exchange (or destroyed
	// with the queue), so the drain is completed against the transport itself
	// before the bindings are removed.
	drainErr := c.drainQueued()
	if err := c.nl.SetReadDeadline(time.Time{}); err != nil && drainErr == nil {
		drainErr = fmt.Errorf("desync: clear NFQUEUE read deadline: %w", err)
	}
	return drainErr
}

// drainQueued answers every message that is still readable on the owned queues
// after the receive loop was interrupted. Emptiness is decided by the
// transport's readiness probe, never by a deadline: once a message is known to
// be readable the read is issued with no deadline, so it cannot be refused
// before it reaches the socket. Only one goroutine (the receive loop, then the
// teardown path) ever reads this connection.
func (c *linuxCapture) drainQueued() error {
	for {
		pending, err := c.nl.pending()
		if err != nil {
			return fmt.Errorf("desync: inspect NFQUEUE receive queue: %w", err)
		}
		if !pending {
			return nil
		}
		if err := c.nl.SetReadDeadline(time.Time{}); err != nil {
			return fmt.Errorf("desync: clear NFQUEUE read deadline: %w", err)
		}
		messages, err := c.nl.Receive()
		if err != nil {
			return fmt.Errorf("desync: drain NFQUEUE receive queue: %w", err)
		}
		if !c.handleBatch(messages) {
			return fmt.Errorf("desync: drain NFQUEUE receive queue: malformed message batch")
		}
	}
}

func (c *linuxCapture) Close() error {
	c.closeOnce.Do(func() {
		if c.overrideQnum != 0 {
			releaseQnum(c.overrideQnum)
		}
		// Held originals are released by Lease.Close before this point; the
		// capture only removes its own queue bindings and table.
		//
		// Ordering is the liveness fix (D3-L1) and the packet-delivery fix at
		// once:
		//  1. The owned table is removed first, so no new packet can enter the
		//     owned queues.
		//  2. The receive loop is then interrupted through a bounded read
		//     deadline and joined. Receive holds the connection lock for the
		//     whole blocking read while Execute needs it for the bind/unbind
		//     exchange, so the loop must be joined before any control message
		//     is sent. Joining alone does not prove the queue is empty: a
		//     reader resuming after the deadline gets a refusal without the
		//     kernel being asked. The teardown path therefore checks the
		//     transport's readiness directly and answers every readable
		//     message itself, so a packet queued before the table removal is
		//     never abandoned and no unread packet message can fail the next
		//     reply validation.
		//  3. Bindings are removed on that same connection - the one whose
		//     portid owns the queues, so a queued packet can never be delivered
		//     to an unread socket.
		//  4. The connection is closed last, after the loop is gone.
		if c.nft != nil && c.table != nil {
			c.nft.DelTable(c.table)
			c.closeErr = c.nft.Flush()
			c.table = nil
		}
		if err := c.stopReceive(); err != nil && c.closeErr == nil {
			c.closeErr = err
		}
		if err := c.unbindQueues(); err != nil && c.closeErr == nil {
			c.closeErr = err
		}
		if c.nl != nil {
			_ = c.nl.Close()
		}
		if !c.started {
			close(c.done)
		}
		c.rawMu.Lock()
		if c.raw4 >= 0 {
			unix.Close(c.raw4)
			c.raw4 = -1
		}
		if c.raw6 >= 0 {
			unix.Close(c.raw6)
			c.raw6 = -1
		}
		c.rawMu.Unlock()
	})
	return c.closeErr
}

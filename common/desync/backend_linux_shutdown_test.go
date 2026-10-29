//go:build linux

package desync

// Hermetic lifecycle and packet-delivery tests for the Linux NFQUEUE capture
// backend. Model tests: no kernel object is created, and every case says so.
//
// The native QA of this backend (t_fd9d1fe5) observed three facts that this
// harness has to model, not just mimic with mocked return values:
//
//   - NFQUEUE delivers a queued packet to the netlink port id that issued the
//     queue BIND, so the bindings, the verdicts and the receive loop must live
//     on one connection; a binding issued elsewhere leaves every captured
//     packet unread and stalls the flow until the queue is destroyed.
//   - An unread packet message on a connection corrupts the next request/reply
//     exchange of *that* connection: mdlayher/netlink.Conn.Execute validates the
//     sequence of the first reply it reads ("mismatched sequence in netlink
//     reply").
//   - netlink.Conn.Receive holds the connection lock for the whole blocking
//     socket read while Execute needs the same lock, so a queue-control
//     exchange issued against a blocked receive blocks forever (D3-L1).
//
// fakeQueueKernel is therefore a small stateful model of the kernel-side queue
// table (owner port, delivery to the owner, dropped packets for unbound
// queues, per-port control permission) and fakeNFQueueConn mirrors the pinned
// netlink connection contract (RWMutex: Receive/Send on the read side, Execute
// on the write side, deadlines that interrupt a blocked read). No privilege is
// required; production code paths (openLinuxCapture, capture.loop,
// capture.Close) are the real ones.
//
// No timeout is used as a success signal: a timeout is always a test failure.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/sagernet/nftables"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

var (
	errFakeNFQueueClosed   = errors.New("fake nfqueue connection is closed")
	errFakeSequence        = errors.New("netlink validate: mismatched sequence in netlink reply")
	errFakeNoDeadline      = errors.New("fake nfqueue connection does not support read deadlines")
	errFakeForeignPort     = errors.New("operation not permitted")
	errFakeQueueNotBound   = errors.New("no such queue")
	errFakeNoSuchInstance  = errors.New("no such queue instance")
	errFakeQueueBusy       = errors.New("device or resource busy")
	errFakeControlRejected = errors.New("fake kernel rejected the queue-control message")
)

// fakeKernelEvent is one ordered kernel-side event of one test. Ordering
// between delivery, verdicts and control messages is the interleaving evidence
// the teardown contract needs, so the model records it instead of asserting on
// final state only.
type fakeKernelEvent struct {
	kind    string // bind, unbind, config, deliver, drop, verdict
	queue   uint16
	port    uint32
	id      uint32
	verdict uint32
}

// fakeQueueKernel models the kernel state that the backend contract depends on.
type fakeQueueKernel struct {
	mu       sync.Mutex
	bindings map[uint16]*fakeNFQueueConn
	// entries is the queue-entry table of one instance: the packet ids it still
	// holds. A packet id is added when the packet is enqueued, removed when its
	// verdict is applied, and removed with NF_DROP when the kernel flushes the
	// instance (nfnetlink_queue.c: queue->queue_list and find_dequeue_entry()).
	entries map[uint16]map[uint32]bool
	events  []fakeKernelEvent
	// reportPath mirrors /proc/net/netfilter/nfnetlink_queue for the model
	// kernel: every state change rewrites one row per bound instance with its
	// exact current queue_total. extraReportRows are deliberate stale or
	// foreign rows that survive state changes.
	reportPath      string
	extraReportRows []string
}

func newFakeQueueKernel() *fakeQueueKernel {
	return &fakeQueueKernel{
		bindings: make(map[uint16]*fakeNFQueueConn),
		entries:  make(map[uint16]map[uint32]bool),
	}
}

// addEntryLocked records one enqueued packet of an instance. Caller holds k.mu.
func (k *fakeQueueKernel) addEntryLocked(queue uint16, id uint32) {
	if k.entries[queue] == nil {
		k.entries[queue] = make(map[uint32]bool)
	}
	k.entries[queue][id] = true
	k.publishReportLocked()
}

// The deployed producer's seq_show() prints nine columns. The model reports the
// same copy_mode/copy_range the capture configures with NFQA_CFG_PARAMS
// (0x0000ffff range, NFQNL_COPY_PACKET=2) rather than an abbreviated row. The
// values are spelled out here, independent of the parser's own constants, so a
// wrong parser constant cannot make the fixture agree with the bug.
const (
	fakeReportCopyMode  = 2
	fakeReportCopyRange = 0x0000ffff
)

// queueReportRow renders one row with the exact deployed producer grammar
// (linux-v6.8 net/netfilter/nfnetlink_queue.c seq_show): nine unsigned decimal
// columns and the constant trailing 1.
func queueReportRow(queue uint16, port, total uint32) string {
	return fmt.Sprintf("%5d %6d %5d %1d %5d %5d %5d %8d %2d",
		queue, port, total, fakeReportCopyMode, fakeReportCopyRange, 0, 0, 0, 1)
}

// publishReportLocked rewrites the model /proc/net/netfilter/nfnetlink_queue
// file: one deployed-shape row per bound instance, in queue order, with the
// exact number of packets the instance still holds. Caller holds k.mu.
func (k *fakeQueueKernel) publishReportLocked() {
	if k.reportPath == "" {
		return
	}
	queues := make([]int, 0, len(k.bindings))
	for queue := range k.bindings {
		queues = append(queues, int(queue))
	}
	sort.Ints(queues)
	var report strings.Builder
	for _, value := range queues {
		queue := uint16(value)
		report.WriteString(queueReportRow(queue, k.bindings[queue].portid, uint32(len(k.entries[queue]))) + "\n")
	}
	for _, row := range k.extraReportRows {
		report.WriteString(row + "\n")
	}
	_ = os.WriteFile(k.reportPath, []byte(report.String()), 0o644)
}

// dropEntriesLocked flushes every queued entry of one instance the way the
// kernel does it on nfqnl_flush(): the entry is dequeued and the packet is
// reinjected with NF_DROP, so the id can no longer be answered. Caller holds
// k.mu.
func (k *fakeQueueKernel) dropEntriesLocked(queue uint16) {
	ids := make([]uint32, 0, len(k.entries[queue]))
	for id := range k.entries[queue] {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		k.events = append(k.events, fakeKernelEvent{kind: "drop", queue: queue, id: id})
	}
	delete(k.entries, queue)
	k.publishReportLocked()
}

// hookDrop models nf_queue_nf_hook_drop(): unregistering one netfilter hook in
// a network namespace flushes EVERY queue instance of that namespace and
// reinjects the packets it still holds with NF_DROP
// (net/netfilter/core.c: __nf_unregister_net_hook -> nf_queue_nf_hook_drop ->
// net/netfilter/nfnetlink_queue.c: nfqnl_nf_hook_drop -> nfqnl_flush(NULL)).
//
// Deleting an nftables table unregisters the hooks of its base chains, so a
// capture's own table removal is such an event: every packet that is still
// queued at that moment is dropped and its id becomes invalid. The instances
// themselves stay bound - only the hook that feeds them is gone.
func (k *fakeQueueKernel) hookDrop() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.events = append(k.events, fakeKernelEvent{kind: "hookdrop"})
	for queue := range k.bindings {
		k.dropEntriesLocked(queue)
	}
}

func (k *fakeQueueKernel) record(event fakeKernelEvent) {
	k.mu.Lock()
	k.events = append(k.events, event)
	k.mu.Unlock()
}

// control applies one queue-control message for the calling connection. The
// ownership checks mirror the kernel: a queue is created by the BIND of one
// port and every later control message for it must come from that port.
func (k *fakeQueueKernel) control(owner *fakeNFQueueConn, queue uint16, command byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	bound, isBound := k.bindings[queue]
	switch command {
	case nfqCfgCmdBind:
		if isBound {
			return errFakeQueueBusy
		}
		k.bindings[queue] = owner
		k.events = append(k.events, fakeKernelEvent{kind: "bind", queue: queue, port: owner.portid})
		k.publishReportLocked()
		return nil
	case nfqCfgCmdUnbind:
		if !isBound {
			return errFakeQueueNotBound
		}
		if bound != owner {
			return errFakeForeignPort
		}
		delete(k.bindings, queue)
		k.events = append(k.events, fakeKernelEvent{kind: "unbind", queue: queue, port: owner.portid})
		k.publishReportLocked()
		return nil
	default:
		// Queue parameter update.
		if !isBound {
			// A parameter or queue-limit message for a queue number without an
			// instance is the kernel's -ENODEV, the exact shape QA464 observed
			// when a released port destroyed a freshly bound queue.
			return errFakeNoSuchInstance
		}
		if bound != owner {
			return errFakeForeignPort
		}
		k.events = append(k.events, fakeKernelEvent{kind: "config", queue: queue, port: owner.portid})
		return nil
	}
}

// deliver routes one queued packet to the port that bound the queue. A queue
// that nobody bound is not ours to answer: the packet is dropped and recorded
// as such so a test can distinguish "delivered" from "silently lost".
func (k *fakeQueueKernel) deliver(queue uint16, message netlink.Message, id uint32) bool {
	k.mu.Lock()
	owner, ok := k.bindings[queue]
	if !ok {
		k.events = append(k.events, fakeKernelEvent{kind: "drop", queue: queue, id: id})
		k.mu.Unlock()
		return false
	}
	k.addEntryLocked(queue, id)
	k.events = append(k.events, fakeKernelEvent{kind: "deliver", queue: queue, port: owner.portid, id: id})
	k.mu.Unlock()
	return owner.deliver(message)
}

// verdict applies the disposition the capture sent for one packet, with the
// kernel's acceptance rule: nfqnl_recv_verdict() looks the id up in the
// instance's entry list and answers -ENOENT when find_dequeue_entry() no longer
// holds it (the packet was already answered, or a hook drop flushed it), and
// netlink_rcv_skb() acknowledges a failed request even without NLM_F_ACK. That
// acknowledgement is an ordinary message on the verdict socket, so the next
// Receive - not the Send - reports it.
func (k *fakeQueueKernel) verdict(owner *fakeNFQueueConn, queue uint16, id, verdict uint32) {
	k.mu.Lock()
	if !k.entries[queue][id] {
		k.events = append(k.events, fakeKernelEvent{
			kind: "reject", queue: queue, port: owner.portid, id: id, verdict: verdict,
		})
		k.mu.Unlock()
		owner.notifyKernelRejection(unix.ENOENT)
		return
	}
	delete(k.entries[queue], id)
	k.events = append(k.events, fakeKernelEvent{
		kind: "verdict", queue: queue, port: owner.portid, id: id, verdict: verdict,
	})
	k.publishReportLocked()
	k.mu.Unlock()
}

func (k *fakeQueueKernel) owner(queue uint16) *fakeNFQueueConn {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.bindings[queue]
}

func (k *fakeQueueKernel) boundQueues() map[uint16]bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	bound := make(map[uint16]bool, len(k.bindings))
	for queue := range k.bindings {
		bound[queue] = true
	}
	return bound
}

func (k *fakeQueueKernel) eventList() []fakeKernelEvent {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]fakeKernelEvent(nil), k.events...)
}

// eventIndex returns the position of the first matching event, or -1.
func (k *fakeQueueKernel) eventIndex(match func(fakeKernelEvent) bool) int {
	for index, event := range k.eventList() {
		if match(event) {
			return index
		}
	}
	return -1
}

func (k *fakeQueueKernel) verdictsFor(queue uint16, id uint32) []fakeKernelEvent {
	var verdicts []fakeKernelEvent
	for _, event := range k.eventList() {
		if event.kind == "verdict" && event.queue == queue && event.id == id {
			verdicts = append(verdicts, event)
		}
	}
	return verdicts
}

// fakeDeadlineGen is one arm generation of a read deadline. Replacing or
// firing it closes the channel so a blocked reader re-evaluates.
type fakeDeadlineGen struct {
	once    sync.Once
	ch      chan struct{}
	expires time.Time
}

func newFakeDeadlineGen(expires time.Time) *fakeDeadlineGen {
	return &fakeDeadlineGen{ch: make(chan struct{}), expires: expires}
}

func (g *fakeDeadlineGen) fire() {
	g.once.Do(func() { close(g.ch) })
}

// fakeNFQueueConn mirrors mdlayher/netlink.Conn: Receive and Send share the
// read lock, Execute takes the write lock for the whole request/reply exchange,
// Close interrupts a blocked read, and SetReadDeadline interrupts a blocked
// read and makes later reads fail while it is expired.
type fakeNFQueueConn struct {
	label  string
	portid uint32
	kernel *fakeQueueKernel

	mu sync.RWMutex

	closeOnce sync.Once
	closed    atomic.Bool
	closedCh  chan struct{}

	receiveOnce sync.Once
	receiving   chan struct{}
	incoming    chan netlink.Message

	deadlineMu       sync.Mutex
	deadlineGen      *fakeDeadlineGen
	deadlineWake     chan struct{}
	deadlineTimer    *time.Timer
	deadlineDisabled bool
	deadlineCalls    atomic.Int32

	executeHook func(call int, message netlink.Message) error
	executeGate chan struct{}

	stateMu    sync.Mutex
	executed   []netlink.Message
	sent       []netlink.Message
	closeCount int
	sequence   uint32
}

func newFakeNFQueueConn(label string, portid uint32, kernel *fakeQueueKernel) *fakeNFQueueConn {
	return &fakeNFQueueConn{
		label:        label,
		portid:       portid,
		kernel:       kernel,
		closedCh:     make(chan struct{}),
		receiving:    make(chan struct{}),
		incoming:     make(chan netlink.Message, 32),
		deadlineWake: make(chan struct{}),
	}
}

func (f *fakeNFQueueConn) deliver(message netlink.Message) bool {
	select {
	case f.incoming <- message:
		return true
	default:
		return false
	}
}

func (f *fakeNFQueueConn) deadlineState() (*fakeDeadlineGen, chan struct{}, bool) {
	f.deadlineMu.Lock()
	defer f.deadlineMu.Unlock()
	expired := f.deadlineGen != nil && !f.deadlineGen.expires.IsZero() && !f.deadlineGen.expires.After(time.Now())
	return f.deadlineGen, f.deadlineWake, expired
}

// notifyKernelRejection queues the kernel's acknowledgement of a failed request
// on this connection: an NLMSG_ERROR message whose payload is the negative
// errno, unicast to the port that sent the rejected request (netlink_ack()).
func (f *fakeNFQueueConn) notifyKernelRejection(errno unix.Errno) {
	payload := make([]byte, 4)
	binary.NativeEndian.PutUint32(payload, uint32(-int32(errno)))
	select {
	case f.incoming <- netlink.Message{Header: netlink.Header{Type: netlink.Error}, Data: payload}:
	default:
	}
}

// fakeReceiveError mirrors the pinned library's checkMessage(): an NLMSG_ERROR
// message carrying a non-zero code is returned to the caller as an OpError with
// Op "receive" and the raw errno - deliberately not an os.SyscallError, because
// the error came from a netlink message and not from a system call. That is why
// a rejected verdict surfaces on the NEXT Receive as
// "netlink receive: no such file or directory", never on the Send itself.
func fakeReceiveError(message netlink.Message) error {
	if message.Header.Type != netlink.Error || len(message.Data) < 4 {
		return nil
	}
	code := int32(binary.NativeEndian.Uint32(message.Data[:4]))
	if code == 0 {
		return nil
	}
	return &netlink.OpError{Op: "receive", Err: unix.Errno(-code)}
}

func (f *fakeNFQueueConn) Receive() ([]netlink.Message, error) {
	f.receiveOnce.Do(func() { close(f.receiving) })
	// Mirror netlink.Conn.Receive: the read lock is held for the whole
	// blocking read, which is what keeps Execute from running concurrently.
	f.mu.RLock()
	defer f.mu.RUnlock()
	for {
		gen, wake, expired := f.deadlineState()
		if expired {
			// internal/poll refuses the read while the deadline is expired, so
			// a buffered message stays buffered.
			return nil, os.ErrDeadlineExceeded
		}
		var deadlineFired chan struct{}
		if gen != nil {
			deadlineFired = gen.ch
		}
		select {
		case message := <-f.incoming:
			if err := fakeReceiveError(message); err != nil {
				return nil, err
			}
			return []netlink.Message{message}, nil
		case <-f.closedCh:
			return nil, errFakeNFQueueClosed
		case <-wake:
			// The deadline was armed or changed: re-evaluate it.
		case <-deadlineFired:
			// The armed deadline was reached: re-evaluate it.
		}
	}
}

func (f *fakeNFQueueConn) Execute(message netlink.Message) ([]netlink.Message, error) {
	// Mirror netlink.Conn.Execute: the write lock covers the request and the
	// reply read, so it cannot run while a receive is blocked on this
	// connection.
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed.Load() {
		return nil, errFakeNFQueueClosed
	}
	f.stateMu.Lock()
	f.executed = append(f.executed, message)
	call := len(f.executed)
	hook := f.executeHook
	gate := f.executeGate
	f.stateMu.Unlock()
	if gate != nil {
		<-gate
	}
	if hook != nil {
		if err := hook(call, message); err != nil {
			return nil, err
		}
	}
	// The reply exchange reads this socket. A message that is already queued
	// here was not produced by this request, and netlink.Conn.Execute validates
	// the sequence of everything it reads: the exchange fails and the queue
	// state is untouched. This is the native "mismatched sequence" shape.
	if len(f.incoming) > 0 {
		return nil, errFakeSequence
	}
	queue, command, ok := parseNFQueueConfig(message)
	if !ok {
		return nil, errors.New("fake nfqueue connection: malformed control message")
	}
	if err := f.kernel.control(f, queue, command); err != nil {
		return nil, err
	}
	f.stateMu.Lock()
	f.sequence++
	sequence := f.sequence
	f.stateMu.Unlock()
	ack := make([]byte, 4)
	return []netlink.Message{{Header: netlink.Header{Type: netlink.Error, Sequence: sequence}, Data: ack}}, nil
}

func (f *fakeNFQueueConn) Send(message netlink.Message) (netlink.Message, error) {
	// Mirror netlink.Conn.Send: the read side of the lock, so verdicts are
	// allowed while a receive is blocked.
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.closed.Load() {
		return netlink.Message{}, errFakeNFQueueClosed
	}
	f.stateMu.Lock()
	f.sent = append(f.sent, message)
	f.stateMu.Unlock()
	queue, id, verdict, ok := parseNFQueueVerdict(message)
	if !ok {
		return netlink.Message{}, errors.New("fake nfqueue connection: malformed verdict")
	}
	f.kernel.verdict(f, queue, id, verdict)
	return netlink.Message{}, nil
}

func (f *fakeNFQueueConn) SetReadDeadline(deadline time.Time) error {
	f.deadlineCalls.Add(1)
	if f.deadlineDisabled {
		return errFakeNoDeadline
	}
	gen := newFakeDeadlineGen(deadline)
	f.deadlineMu.Lock()
	previousWake := f.deadlineWake
	previousTimer := f.deadlineTimer
	f.deadlineGen = gen
	f.deadlineTimer = nil
	f.deadlineWake = make(chan struct{})
	if !deadline.IsZero() {
		if remaining := time.Until(deadline); remaining > 0 {
			f.deadlineTimer = time.AfterFunc(remaining, gen.fire)
		} else {
			gen.fire()
		}
	}
	f.deadlineMu.Unlock()
	if previousTimer != nil {
		previousTimer.Stop()
	}
	// Any deadline change wakes a blocked reader so it re-evaluates, exactly
	// like runtime_pollSetDeadline does for a blocked read.
	close(previousWake)
	return nil
}

func (f *fakeNFQueueConn) Close() error {
	f.closeOnce.Do(func() {
		f.closed.Store(true)
		f.stateMu.Lock()
		f.closeCount++
		f.stateMu.Unlock()
		// Kernel socket release destroys every NFQUEUE instance bound to this
		// port in one instances_lock critical section.
		if f.kernel != nil {
			f.kernel.releasePort(f)
		}
		f.deadlineMu.Lock()
		if f.deadlineTimer != nil {
			f.deadlineTimer.Stop()
			f.deadlineTimer = nil
		}
		f.deadlineMu.Unlock()
		close(f.closedCh)
	})
	return nil
}

// releasePort models netlink_release -> NETLINK_URELEASE ->
// nfqnl_rcv_nl_event: every instance whose peer_portid is this port is
// destroyed, and its pending entries are flushed with NF_DROP.
func (k *fakeQueueKernel) releasePort(conn *fakeNFQueueConn) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for queue, owner := range k.bindings {
		if owner != conn {
			continue
		}
		delete(k.bindings, queue)
		k.dropEntriesLocked(queue)
		k.events = append(k.events, fakeKernelEvent{kind: "release", queue: queue, port: conn.portid})
	}
	k.publishReportLocked()
}

// pending mirrors a MSG_PEEK|MSG_DONTWAIT probe on the socket: it reports an
// already queued datagram without consuming it and without consulting the read
// deadline. Receive refuses the read while the deadline is expired, so a
// timeout and this probe answer different questions.
func (f *fakeNFQueueConn) pending() (bool, error) {
	if f.closed.Load() {
		return false, errFakeNFQueueClosed
	}
	return len(f.incoming) > 0, nil
}

// boundPort is the explicitly bound queue-class port of this connection.
func (f *fakeNFQueueConn) boundPort() uint32 { return f.portid }

func (f *fakeNFQueueConn) executedMessages() []netlink.Message {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	return append([]netlink.Message(nil), f.executed...)
}

func (f *fakeNFQueueConn) sentMessages() []netlink.Message {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	return append([]netlink.Message(nil), f.sent...)
}

func (f *fakeNFQueueConn) closings() int {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	return f.closeCount
}

func (f *fakeNFQueueConn) setExecuteHook(hook func(call int, message netlink.Message) error) {
	f.stateMu.Lock()
	f.executeHook = hook
	f.stateMu.Unlock()
}

func (f *fakeNFQueueConn) setExecuteGate(gate chan struct{}) {
	f.stateMu.Lock()
	f.executeGate = gate
	f.stateMu.Unlock()
}

// parseNFQueueConfig decodes one NFQNL_MSG_CONFIG message: queue number and the
// command byte of NFQA_CFG_CMD (BIND=1, UNBIND=2, parameters=0).
func parseNFQueueConfig(message netlink.Message) (uint16, byte, bool) {
	if len(message.Data) < 4 {
		return 0, 0, false
	}
	queue := binary.BigEndian.Uint16(message.Data[2:4])
	attributes, err := netlink.UnmarshalAttributes(message.Data[4:])
	if err != nil {
		return 0, 0, false
	}
	command := byte(0)
	for _, attribute := range attributes {
		if attribute.Type == nfqCfgAttrCmd {
			if len(attribute.Data) < 1 {
				return 0, 0, false
			}
			command = attribute.Data[0]
		}
	}
	return queue, command, true
}

// parseNFQueueVerdict decodes one NFQA verdict message: the message header
// carries the queue number and NFQA_VERDICT_HDR carries verdict plus packet id.
func parseNFQueueVerdict(message netlink.Message) (uint16, uint32, uint32, bool) {
	if len(message.Data) < 4 {
		return 0, 0, 0, false
	}
	queue := binary.BigEndian.Uint16(message.Data[2:4])
	attributes, err := netlink.UnmarshalAttributes(message.Data[4:])
	if err != nil {
		return 0, 0, 0, false
	}
	for _, attribute := range attributes {
		if attribute.Type != 2 || len(attribute.Data) < 8 {
			continue
		}
		verdict := binary.BigEndian.Uint32(attribute.Data[:4])
		id := binary.BigEndian.Uint32(attribute.Data[4:8])
		return queue, id, verdict, true
	}
	return 0, 0, 0, false
}

// fakeRuleWriter is retained only for the reply-limit batch model tests; the
// persistent-anchor lifecycle itself runs against fakeNftNamespace.
type fakeRuleWriter struct {
	mu             sync.Mutex
	tables         []*nftables.Table
	rules          []*nftables.Rule
	deleted        []string
	deletedFlushed int
	flushes        int
	flushErr       error
	deleteHook     func()
}

func (f *fakeRuleWriter) AddTable(table *nftables.Table) *nftables.Table {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tables = append(f.tables, table)
	return table
}

func (f *fakeRuleWriter) AddChain(chain *nftables.Chain) *nftables.Chain { return chain }

func (f *fakeRuleWriter) AddRule(rule *nftables.Rule) *nftables.Rule {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = append(f.rules, rule)
	return rule
}

func (f *fakeRuleWriter) DelTable(table *nftables.Table) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if table != nil {
		f.deleted = append(f.deleted, table.Name)
	}
}

func (f *fakeRuleWriter) Flush() error {
	f.mu.Lock()
	hook := f.deleteHook
	pending := len(f.deleted) > f.deletedFlushed
	f.deletedFlushed = len(f.deleted)
	f.flushes++
	err := f.flushErr
	f.mu.Unlock()
	if pending && hook != nil {
		hook()
	}
	return err
}

// linuxCaptureSeams installs the hermetic native and anchor seams of one test.
// The dial factory hands out the queue connection first; any additional
// connection the implementation opens is tracked, because a capture must own
// exactly one: the port that receives is the port that binds.
type linuxCaptureSeams struct {
	first     *fakeNFQueueConn
	firstUsed bool
	kernel    *fakeQueueKernel
	anchors   *fakeNftNamespace

	mu         sync.Mutex
	extra      []*fakeNFQueueConn
	extraNext  uint32
	boundPorts []uint32

	guardsMu sync.Mutex
	guards   map[string]bool
	// forceGuardBusy models a guard inherited by a child: the exact-name probe
	// stays busy even after the local fd was closed.
	forceGuardBusy bool

	fenceMu sync.Mutex
	fence   *fakeFenceTransport
}

func (s *linuxCaptureSeams) dial(port uint32) (nfqueueTransport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.firstUsed {
		s.firstUsed = true
		if s.first == nil {
			s.first = newFakeNFQueueConn("queue", port, s.kernel)
		}
		s.first.portid = port
		s.boundPorts = append(s.boundPorts, port)
		return s.first, nil
	}
	s.extraNext++
	extra := newFakeNFQueueConn(fmt.Sprintf("extra-%d", s.extraNext), port, s.kernel)
	s.extra = append(s.extra, extra)
	s.boundPorts = append(s.boundPorts, port)
	return extra, nil
}

func (s *linuxCaptureSeams) extraConnections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.extra)
}

func (s *linuxCaptureSeams) boundPortList() []uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uint32(nil), s.boundPorts...)
}

func (s *linuxCaptureSeams) bindGuard(name string) (*anchorGuard, error) {
	s.guardsMu.Lock()
	defer s.guardsMu.Unlock()
	if s.guards[name] {
		return nil, unix.EADDRINUSE
	}
	s.guards[name] = true
	guard := &anchorGuard{fd: -1, name: name}
	guard.onClose = func() {
		s.guardsMu.Lock()
		delete(s.guards, name)
		s.guardsMu.Unlock()
	}
	return guard, nil
}

func (s *linuxCaptureSeams) probeGuard(name string) (bool, error) {
	s.guardsMu.Lock()
	defer s.guardsMu.Unlock()
	return s.guards[name] || s.forceGuardBusy, nil
}

func (s *linuxCaptureSeams) fenceTransport() (fenceTransport, error) {
	s.fenceMu.Lock()
	defer s.fenceMu.Unlock()
	if s.fence == nil {
		s.fence = &fakeFenceTransport{port: 0x40000001, reply: validFenceReply}
	}
	return s.fence, nil
}

func (s *linuxCaptureSeams) setFenceReply(reply func(request enqueueFenceRequest, port uint32) ([]byte, *unix.SockaddrNetlink, error)) {
	s.fenceMu.Lock()
	defer s.fenceMu.Unlock()
	if s.fence == nil {
		s.fence = &fakeFenceTransport{port: 0x40000001}
	}
	s.fence.reply = reply
}

// installLinuxCaptureSeams swaps the native and anchor seams for one test and
// restores them afterwards. The queue-report path is missing on purpose:
// absence of the kernel report must never be read as a collision. The
// namespace NFQUEUE report is an empty regular file so an available proc read
// is modelled separately from an unavailable one.
func installLinuxCaptureSeams(t *testing.T, queue *fakeNFQueueConn) *linuxCaptureSeams {
	t.Helper()
	kernel := newFakeQueueKernel()
	previousGet := getThreadNetns
	previousSet := setThreadNetns
	previousOpen := openQueueTransport
	previousSession := openAnchorSession
	previousFence := openFenceTransport
	previousGuardBind := bindAnchorGuardSocket
	previousGuardProbe := probeAnchorGuardAddress
	previousProcess := readProcessIdentity
	previousObserve := observeOwnerProcess
	previousReport := linuxQueueReportPath
	previousNamespaceReport := namespaceQueueReportPath
	seams := &linuxCaptureSeams{kernel: kernel, anchors: newFakeNftNamespace(), guards: make(map[string]bool)}
	if queue != nil {
		queue.kernel = kernel
		seams.first = queue
	}
	setThreadNetns = func(netns.NsHandle) error { return nil }
	openQueueTransport = seams.dial
	openAnchorSession = func() (anchorSession, error) {
		return &fakeAnchorSession{namespace: seams.anchors, port: 0x40000002}, nil
	}
	openFenceTransport = seams.fenceTransport
	bindAnchorGuardSocket = seams.bindGuard
	probeAnchorGuardAddress = seams.probeGuard
	readProcessIdentity = func() (processIdentity, error) {
		return processIdentity{pidns: anchorPidNamespace{dev: 1, ino: 2}, tgid: 4242, startTicks: 99}, nil
	}
	observeOwnerProcess = func(anchorRecord) (anchorOwnerObservation, error) {
		return anchorOwnerObservation{verdict: anchorOwnerDead, reason: "model: not observed"}, nil
	}
	linuxQueueReportPath = filepath.Join(t.TempDir(), "missing-nfnetlink_queue")
	queueReport := filepath.Join(t.TempDir(), "nfnetlink_queue")
	if err := os.WriteFile(queueReport, nil, 0o644); err != nil {
		t.Fatalf("write fake NFQUEUE report: %v", err)
	}
	namespaceQueueReportPath = queueReport
	kernel.reportPath = queueReport
	t.Cleanup(func() {
		getThreadNetns = previousGet
		setThreadNetns = previousSet
		openQueueTransport = previousOpen
		openAnchorSession = previousSession
		openFenceTransport = previousFence
		bindAnchorGuardSocket = previousGuardBind
		probeAnchorGuardAddress = previousGuardProbe
		readProcessIdentity = previousProcess
		observeOwnerProcess = previousObserve
		linuxQueueReportPath = previousReport
		namespaceQueueReportPath = previousNamespaceReport
		anchorOwnerRegistry.Lock()
		for key, owner := range anchorOwnerRegistry.owners {
			owner.mu.Lock()
			owner.closed = true
			owner.mu.Unlock()
			_ = owner.guard.close()
			if owner.nsFD >= 0 {
				_ = unix.Close(owner.nsFD)
				owner.nsFD = -1
			}
			delete(anchorOwnerRegistry.owners, key)
		}
		anchorOwnerRegistry.Unlock()
		seams.mu.Lock()
		extras := append([]*fakeNFQueueConn(nil), seams.extra...)
		if seams.first != nil {
			extras = append(extras, seams.first)
		}
		seams.mu.Unlock()
		for _, extra := range extras {
			_ = extra.Close()
		}
	})
	return seams
}

// newLinuxCaptureLease builds a real Engine/Lease pair whose capture backend is
// the production Linux backend. The explicit queue identity keeps native
// assertions exact; the in-process registry entry is released defensively.
func newLinuxCaptureLease(t *testing.T, queue int) (*Engine, *Lease) {
	t.Helper()
	content := fmt.Sprintf(`{"enabled":true,"capture":{"linux":{"qnum":%d}},"rules":[{"network":["tcp"],"port":[443],"methods":[]}]}`, queue)
	config, err := Compile(enabledOption(content), "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	engine, err := NewEngine(config, linuxBackend{})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	lease, err := engine.NewAttempt(Intent{
		Family:      FamilyIPv4,
		Transport:   TransportTCP,
		Source:      netip.MustParseAddrPort("192.0.2.1:40000"),
		Destination: netip.MustParseAddrPort("198.51.100.7:443"),
	})
	if err != nil {
		t.Fatalf("attempt: %v", err)
	}
	lease.SetLocalAddress(netip.MustParseAddrPort("192.0.2.1:40000"))
	t.Cleanup(func() {
		_ = engine.Close()
		releaseQnum(queue)
	})
	return engine, lease
}

// nfqueueCommand decodes the queue identity and configuration command of one
// NFQNL_CFG message built by messageOn.
func nfqueueCommand(t *testing.T, message netlink.Message) (uint16, uint16) {
	t.Helper()
	queue, command, ok := parseNFQueueConfig(message)
	if !ok {
		t.Fatalf("malformed nfqueue message: %d bytes", len(message.Data))
	}
	return queue, uint16(command)
}

// countQueueCommand counts bind (1) or unbind (2) messages for one queue.
func countQueueCommand(t *testing.T, messages []netlink.Message, queue, command uint16) int {
	t.Helper()
	count := 0
	for _, message := range messages {
		messageQueue, messageCommand := nfqueueCommand(t, message)
		if messageQueue == queue && messageCommand == command {
			count++
		}
	}
	return count
}

// fakePacketMessage builds one NFQA packet message for the capture loop.
func fakePacketMessage(queue uint16, id uint32, frame []byte) netlink.Message {
	packetID := make([]byte, 4)
	binary.BigEndian.PutUint32(packetID, id)
	attributes, _ := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: nfqPacketID, Data: packetID},
		{Type: nfqPacketPayload, Data: frame},
	})
	return netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(3 << 8)},
		Data:   append([]byte{1, 0, byte(queue >> 8), byte(queue)}, attributes...),
	}
}

func waitWithin(t *testing.T, what string, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not return within 5s (blocked native teardown)", what)
		return nil
	}
}

// waitForCondition polls a predicate with a hard bound. A bound hit is a test
// failure, never a success signal.
func waitForCondition(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen within 5s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestFakeKernelModelsBindingIdentity is the harness self-check: it proves the
// model reproduces the native QA observations, so the tests below really
// discriminate a binding on the wrong socket instead of just asserting on
// mocked return values.
func TestFakeKernelModelsBindingIdentity(t *testing.T) {
	kernel := newFakeQueueKernel()
	data := newFakeNFQueueConn("data", 1, kernel)
	control := newFakeNFQueueConn("control", 2, kernel)
	if err := kernel.control(control, 15000, nfqCfgCmdBind); err != nil {
		t.Fatalf("bind on control port: %v", err)
	}
	if got := kernel.owner(15000); got != control {
		t.Fatalf("queue owner = %v, want the binding connection", got)
	}
	// The queue delivers to the binding port only.
	if !kernel.deliver(15000, fakePacketMessage(15000, 7, []byte("x")), 7) {
		t.Fatal("kernel dropped a packet of a bound queue")
	}
	if len(data.incoming) != 0 {
		t.Fatal("packet was delivered to a connection that did not bind the queue")
	}
	if len(control.incoming) != 1 {
		t.Fatalf("binding port has %d queued packet messages, want 1", len(control.incoming))
	}
	// A request/reply exchange on that port now fails sequence validation: the
	// pending packet message is read as the reply. This is the native
	// "mismatched sequence in netlink reply" observation.
	message, err := (&linuxCapture{}).messageOn(15000, FamilyIPv4, 2, []netlink.Attribute{
		{Type: nfqCfgAttrCmd, Data: []byte{nfqCfgCmdUnbind, 0, 0, 4}},
	}, true)
	if err != nil {
		t.Fatalf("build control message: %v", err)
	}
	if _, err := control.Execute(message); !errors.Is(err, errFakeSequence) {
		t.Fatalf("control exchange error = %v, want the sequence validation failure", err)
	}
	// A control message from a port that does not own the queue is refused.
	if err := kernel.control(data, 15000, nfqCfgCmdUnbind); !errors.Is(err, errFakeForeignPort) {
		t.Fatalf("foreign-port unbind error = %v, want permission denied", err)
	}
	if kernel.owner(15000) != control {
		t.Fatal("a refused control message changed the queue owner")
	}
}

// TestLinuxCaptureBindsQueuesOnReceivingSocket pins the production correction:
// the owned queues are bound on the connection whose receive loop answers their
// packets, the kernel delivers to that port only, and a delivered packet is
// answered with a verdict on the same connection.
func TestLinuxCaptureBindsQueuesOnReceivingSocket(t *testing.T) {
	data := newFakeNFQueueConn("queue", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	_, lease := newLinuxCaptureLease(t, 15010)

	capture, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("open capture: %v", err)
	}
	defer capture.Close()
	linux := capture.(*linuxCapture)
	select {
	case <-data.receiving:
	case <-time.After(5 * time.Second):
		t.Fatal("capture loop never entered Receive")
	}
	if got := seams.extraConnections(); got != 0 {
		t.Fatalf("capture opened %d extra nfqueue connections; the queue must be bound on the receiving socket", got)
	}
	for _, queue := range []uint16{linux.queue, linux.inQueue} {
		if owner := seams.kernel.owner(queue); owner != data {
			t.Fatalf("queue %d owner = %v, want the receiving connection", queue, owner)
		}
		if got := countQueueCommand(t, data.executedMessages(), queue, nfqCfgCmdBind); got != 1 {
			t.Fatalf("queue %d binds on the receiving socket = %d, want 1", queue, got)
		}
	}

	packet := buildIPv4TCP(t, nil, 1000, tcpFlagACK|tcpFlagPSH)
	id := uint32(21)
	if !seams.kernel.deliver(linux.queue, fakePacketMessage(linux.queue, id, packet.Raw), id) {
		t.Fatal("owned outbound queue did not accept a delivered packet")
	}
	waitForCondition(t, "verdict for the delivered packet", func() bool {
		return len(seams.kernel.verdictsFor(linux.queue, id)) == 1
	})
	verdict := seams.kernel.verdictsFor(linux.queue, id)[0]
	if verdict.port != data.portid {
		t.Fatalf("verdict came from port %d, want the binding port %d", verdict.port, data.portid)
	}
	if len(data.sentMessages()) != 1 {
		t.Fatalf("verdicts sent on the receiving socket = %d, want 1", len(data.sentMessages()))
	}
	// The packet was answered, not lost.
	if index := seams.kernel.eventIndex(func(event fakeKernelEvent) bool {
		return event.kind == "drop" && event.queue == linux.queue
	}); index >= 0 {
		t.Fatal("a packet of the owned queue was dropped")
	}
}

// TestLinuxCaptureCloseReleasesIdleBlockingReceive is the D3-L1 regression on
// the single queue connection: an idle capture blocks in Receive holding the
// connection lock, so Close has to stop and join the loop before it can run the
// unbind exchange on that same connection.
func TestLinuxCaptureCloseReleasesIdleBlockingReceive(t *testing.T) {
	data := newFakeNFQueueConn("queue", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	_, lease := newLinuxCaptureLease(t, 15000)

	capture, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("open capture: %v", err)
	}
	linux := capture.(*linuxCapture)
	select {
	case <-data.receiving:
	case <-time.After(5 * time.Second):
		t.Fatal("capture loop never entered Receive")
	}

	closed := make(chan error, 1)
	go func() { closed <- capture.Close() }()
	if err := waitWithin(t, "capture Close", closed); err != nil {
		t.Fatalf("capture Close: %v", err)
	}

	executed := data.executedMessages()
	if got := countQueueCommand(t, executed, 15000, nfqCfgCmdUnbind); got != 0 {
		t.Fatalf("outq unbinds = %d, want 0 (the witness is released by its owning socket)", got)
	}
	if got := countQueueCommand(t, executed, linux.inQueue, nfqCfgCmdUnbind); got != 1 {
		t.Fatalf("inbound queue unbinds = %d, want 1", got)
	}
	if bound := seams.kernel.boundQueues(); len(bound) != 0 {
		t.Fatalf("queues still bound after Close: %v", bound)
	}
	// The fixed anchors outlive the capture: the table, both base chains, the
	// a/t markers and the empty base chains are validated after close.
	if err := readFakeAnchors(t, seams, FamilyIPv4); err != nil {
		t.Fatalf("anchor validation after close: %v", err)
	}
	if records := fakeCaptureRecords(t, seams, FamilyIPv4); len(records) != 0 {
		t.Fatalf("capture records after close: %v", records)
	}
	if data.closings() != 1 {
		t.Fatalf("connection closes = %d, want 1", data.closings())
	}
	// The unbind exchange must come after the queue connection stop: the model
	// refuses to run Execute while a receive holds the lock, so reaching this
	// point already proves it, and the recorded order documents it.
	unbindIndex := seams.kernel.eventIndex(func(event fakeKernelEvent) bool {
		return event.kind == "unbind" && event.queue == linux.inQueue
	})
	if unbindIndex < 0 {
		t.Fatal("no recorded unbind of the inbound observation queue")
	}

	// Repeated close is a no-op: it must not repeat any native side effect.
	if err := capture.Close(); err != nil {
		t.Fatalf("repeated Close: %v", err)
	}
	if got := len(data.executedMessages()); got != len(executed) {
		t.Fatalf("repeated Close sent %d extra control messages", got-len(executed))
	}
	if err := readFakeAnchors(t, seams, FamilyIPv4); err != nil {
		t.Fatalf("repeated Close disturbed the fixed anchors: %v", err)
	}
	if data.closings() != 1 {
		t.Fatal("repeated Close re-closed the native connection")
	}
	if qnumLive(15000) {
		t.Fatal("repeated Close left the explicit queue identity reserved")
	}
}

// teardownDeliverConn injects one already-enqueued packet of the owned flow at
// the teardown interrupt: the first read deadline a capture arms with a
// non-zero deadline is the one stopReceive uses to stop the receive loop.
// Delivery, deadlines, queue identity and verdicts stay entirely with the
// shipped fake transport; this wrapper only decides WHEN the packet reaches it,
// so the interleaving is deterministic instead of timing-dependent.
type teardownDeliverConn struct {
	*fakeNFQueueConn
	deliver func()
	once    sync.Once
}

func (c *teardownDeliverConn) SetReadDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		c.once.Do(c.deliver)
	}
	return c.fakeNFQueueConn.SetReadDeadline(deadline)
}

// TestLinuxCaptureCloseDrainsPacketsQueuedDuringTeardown covers the interleaved
// packet/control/teardown case: a packet of the owned flow that is still queued
// when the capture stops its receive loop is answered by the teardown drain
// before the owned table - and with it the base-chain hook that feeds the
// queue - is removed, so the kernel's hook drop never discards it, and the
// unbind exchange on the same connection then passes reply validation.
func TestLinuxCaptureCloseDrainsPacketsQueuedDuringTeardown(t *testing.T) {
	data := newFakeNFQueueConn("queue", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	_, lease := newLinuxCaptureLease(t, 15011)

	packet := buildIPv4TCP(t, nil, 1000, tcpFlagACK|tcpFlagPSH)
	queued := uint32(77)
	var linux *linuxCapture
	conn := &teardownDeliverConn{fakeNFQueueConn: data, deliver: func() {
		if !seams.kernel.deliver(linux.queue, fakePacketMessage(linux.queue, queued, packet.Raw), queued) {
			t.Errorf("owned queue refused the packet queued during teardown")
		}
	}}
	data.portid = 0x51a00003
	openQueueTransport = func(port uint32) (nfqueueTransport, error) { return conn, nil }

	capture, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("open capture: %v", err)
	}
	linux = capture.(*linuxCapture)
	select {
	case <-data.receiving:
	case <-time.After(5 * time.Second):
		t.Fatal("capture loop never entered Receive")
	}

	closed := make(chan error, 1)
	go func() { closed <- capture.Close() }()
	if err := waitWithin(t, "capture Close", closed); err != nil {
		t.Fatalf("capture Close: %v (the unread packet message must not fail the unbind exchange)", err)
	}

	verdicts := seams.kernel.verdictsFor(linux.queue, queued)
	if len(verdicts) != 1 {
		t.Fatalf("verdicts for the packet queued during teardown = %d, want 1 (dropped instead of drained)", len(verdicts))
	}
	// Ordering: answered while its kernel entry is still valid, i.e. before the
	// table removal flushed the instance, and before the queue was unbound.
	verdictIndex := seams.kernel.eventIndex(func(event fakeKernelEvent) bool {
		return event.kind == "verdict" && event.id == queued
	})
	unbindIndex := seams.kernel.eventIndex(func(event fakeKernelEvent) bool {
		return event.kind == "unbind" && event.queue == linux.inQueue
	})
	if verdictIndex < 0 || unbindIndex < 0 || verdictIndex > unbindIndex {
		t.Fatalf("event order verdict=%d unbind=%d, want the drain to answer before the unbind", verdictIndex, unbindIndex)
	}
	if drops := countKernelEvents(seams.kernel, "drop"); drops != 0 {
		t.Fatalf("kernel dropped %d queued packets at teardown, want 0", drops)
	}
	if bound := seams.kernel.boundQueues(); len(bound) != 0 {
		t.Fatalf("queues still bound after Close: %v", bound)
	}
	if err := readFakeAnchors(t, seams, FamilyIPv4); err != nil {
		t.Fatalf("anchor validation after close: %v", err)
	}
	if data.closings() != 1 {
		t.Fatalf("connection closes = %d, want 1", data.closings())
	}
}

// countKernelEvents counts recorded kernel events of one kind.
func countKernelEvents(kernel *fakeQueueKernel, kind string) int {
	count := 0
	for _, event := range kernel.eventList() {
		if event.kind == kind {
			count++
		}
	}
	return count
}

// TestLinuxCaptureCloseWithoutDeadlineSupportDoesNotHang pins the failure path
// of the stop signal: a transport that cannot interrupt a blocked receive is
// reported, the loop is still joined, and Close does not claim success.
func TestLinuxCaptureCloseWithoutDeadlineSupportDoesNotHang(t *testing.T) {
	data := newFakeNFQueueConn("queue", 0, nil)
	data.deadlineDisabled = true
	installLinuxCaptureSeams(t, data)
	_, lease := newLinuxCaptureLease(t, 15012)

	capture, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("open capture: %v", err)
	}
	select {
	case <-data.receiving:
	case <-time.After(5 * time.Second):
		t.Fatal("capture loop never entered Receive")
	}

	closed := make(chan error, 1)
	go func() { closed <- capture.Close() }()
	err = waitWithin(t, "capture Close", closed)
	if err == nil {
		t.Fatal("Close reported success although the receive loop could not be stopped")
	}
	if !errors.Is(err, errFakeNoDeadline) {
		t.Fatalf("Close error = %v, want the deadline failure", err)
	}
	if data.closings() != 1 {
		t.Fatalf("connection closes = %d, want 1", data.closings())
	}
}

// TestLinuxCaptureConcurrentLeaseAndEngineClose verifies exact-once teardown
// when Lease.Close and Engine.Close race, and that Engine.Close cannot report
// completion while its lease still owns native resources.
func TestLinuxCaptureConcurrentLeaseAndEngineClose(t *testing.T) {
	data := newFakeNFQueueConn("queue", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	engine, lease := newLinuxCaptureLease(t, 15001)
	if err := lease.StartCapture(); err != nil {
		t.Fatalf("start capture: %v", err)
	}
	select {
	case <-data.receiving:
	case <-time.After(5 * time.Second):
		t.Fatal("capture loop never entered Receive")
	}

	// Gate the first unbind so the teardown is observably in flight while
	// Engine.Close is called. Releasing the gate must not be required for
	// correctness - it only proves the wait.
	unbindEntered := make(chan struct{})
	gate := make(chan struct{})
	var gateOnce sync.Once
	data.setExecuteHook(func(call int, message netlink.Message) error {
		_, command := nfqueueCommand(t, message)
		if command == nfqCfgCmdUnbind {
			gateOnce.Do(func() {
				close(unbindEntered)
				<-gate
			})
		}
		return nil
	})

	leaseClosed := make(chan error, 1)
	go func() { leaseClosed <- lease.Close(nil) }()
	select {
	case <-unbindEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("lease Close never reached the native unbind")
	}

	engineClosed := make(chan error, 1)
	go func() { engineClosed <- engine.Close() }()
	select {
	case err := <-engineClosed:
		// Pre-fix (or an unguarded engine) returns while the capture teardown
		// is still gated below: the native resources must not be free yet.
		if data.closings() == 0 {
			t.Fatalf("Engine.Close returned before native teardown (err %v)", err)
		}
	case <-time.After(250 * time.Millisecond):
		// Waiting for the in-flight lease close, as required.
	}
	close(gate)

	if err := waitWithin(t, "lease Close", leaseClosed); err != nil {
		t.Fatalf("lease Close: %v", err)
	}
	if err := waitWithin(t, "engine Close", engineClosed); err != nil {
		t.Fatalf("engine Close: %v", err)
	}
	if data.closings() != 1 {
		t.Fatalf("connection closes = %d, want 1", data.closings())
	}
	if engine.ActiveLeases() != 0 {
		t.Fatal("engine still tracks a lease after Close")
	}
	if got := countQueueCommand(t, data.executedMessages(), 15001, nfqCfgCmdUnbind); got != 0 {
		t.Fatalf("outq unbinds = %d, want 0 (witness released by its owning socket)", got)
	}
	if bound := seams.kernel.boundQueues(); len(bound) != 0 {
		t.Fatalf("queues still bound after Close: %v", bound)
	}
}

// TestLinuxCaptureLoopIgnoresForeignQueues pins that the receive loop answers
// verdicts only for its own queue identities and never widens ownership.
func TestLinuxCaptureLoopIgnoresForeignQueues(t *testing.T) {
	data := newFakeNFQueueConn("queue", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	_, lease := newLinuxCaptureLease(t, 15002)
	capture, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("open capture: %v", err)
	}
	defer capture.Close()
	linux := capture.(*linuxCapture)
	select {
	case <-data.receiving:
	case <-time.After(5 * time.Second):
		t.Fatal("capture loop never entered Receive")
	}

	packet := buildIPv4TCP(t, nil, 1000, tcpFlagACK|tcpFlagPSH)
	// A message of a queue this capture does not own, delivered to its socket.
	data.incoming <- fakePacketMessage(linux.inQueue+7, 11, packet.Raw)
	// The owned packet goes through the kernel entry model, so its verdict is a
	// real dequeue of a queued entry instead of an unknown id.
	if !seams.kernel.deliver(linux.queue, fakePacketMessage(linux.queue, 12, packet.Raw), 12) {
		t.Fatal("owned queue refused the packet")
	}

	waitForCondition(t, "verdict for the owned packet", func() bool {
		return len(data.sentMessages()) > 0
	})
	sent := data.sentMessages()
	if len(sent) != 1 {
		t.Fatalf("verdicts sent = %d, want exactly the owned packet (foreign queue must be ignored)", len(sent))
	}
	queue := binary.BigEndian.Uint16(sent[0].Data[2:4])
	if queue != linux.queue {
		t.Fatalf("verdict queue = %d, want owned outbound queue %d", queue, linux.queue)
	}
	if got := countQueueCommand(t, data.executedMessages(), linux.inQueue+7, nfqCfgCmdUnbind); got != 0 {
		t.Fatal("capture answered a foreign queue")
	}
	_ = seams
}

// TestLinuxCaptureOpenRollsBackAfterFirstSideEffect injects a failure after
// each first native side effect and verifies the owned resources are released
// exactly once, without touching any other queue or table.
func TestLinuxCaptureOpenRollsBackAfterFirstSideEffect(t *testing.T) {
	t.Run("bind failure", func(t *testing.T) {
		data := newFakeNFQueueConn("queue", 0, nil)
		seams := installLinuxCaptureSeams(t, data)
		data.setExecuteHook(func(call int, message netlink.Message) error {
			if call == 1 {
				return errors.New("bind rejected")
			}
			return nil
		})
		_, lease := newLinuxCaptureLease(t, 15004)
		if _, err := openLinuxCapture(lease); err == nil {
			t.Fatal("capture opened although the queue bind failed")
		}
		executed := data.executedMessages()
		if len(executed) != 1 {
			t.Fatalf("control messages = %d, want only the failed bind", len(executed))
		}
		if got := countQueueCommand(t, executed, 15004, nfqCfgCmdUnbind); got != 0 {
			t.Fatal("a bind that never succeeded was unbound")
		}
		if data.closings() != 1 {
			t.Fatal("failed open leaked the queue connection")
		}
		if seams.extraConnections() != 0 {
			t.Fatal("failed open opened an extra connection")
		}
	})

	t.Run("queue parameter failure unbinds", func(t *testing.T) {
		data := newFakeNFQueueConn("queue", 0, nil)
		seams := installLinuxCaptureSeams(t, data)
		data.setExecuteHook(func(call int, message netlink.Message) error {
			if call == 2 {
				return errors.New("parameter rejected")
			}
			return nil
		})
		_, lease := newLinuxCaptureLease(t, 15005)
		if _, err := openLinuxCapture(lease); err == nil {
			t.Fatal("capture opened although the queue parameters failed")
		}
		if got := countQueueCommand(t, data.executedMessages(), 15005, nfqCfgCmdUnbind); got != 1 {
			t.Fatalf("rollback unbinds = %d, want 1", got)
		}
		if bound := seams.kernel.boundQueues(); len(bound) != 0 {
			t.Fatalf("queues still bound after the failed open: %v", bound)
		}
	})

	t.Run("rule installation failure unbinds both queues", func(t *testing.T) {
		data := newFakeNFQueueConn("queue", 0, nil)
		seams := installLinuxCaptureSeams(t, data)
		seams.anchors.failRuleSubstring = ":entry-o"
		_, lease := newLinuxCaptureLease(t, 15006)
		if _, err := openLinuxCapture(lease); err == nil {
			t.Fatal("capture opened although rule installation failed")
		}
		executed := data.executedMessages()
		if got := countQueueCommand(t, executed, 15006, nfqCfgCmdUnbind); got != 0 {
			t.Fatalf("outq rollback unbinds = %d, want 0 (the owning socket release is the witness path)", got)
		}
		if got := countQueueCommand(t, executed, uint16(0), nfqCfgCmdUnbind); got != 0 {
			t.Fatalf("unexpected queue-0 unbind = %d", got)
		}
		if data.closings() != 1 {
			t.Fatal("failed install leaked the queue connection")
		}
		if bound := seams.kernel.boundQueues(); len(bound) != 0 {
			t.Fatalf("queues still bound after the failed install: %v", bound)
		}
		if err := readFakeAnchors(t, seams, FamilyIPv4); err != nil {
			t.Fatalf("failed install damaged the fixed anchors: %v", err)
		}
		if records := fakeCaptureRecords(t, seams, FamilyIPv4); len(records) != 0 {
			t.Fatalf("failed install left capture records: %v", records)
		}
	})
}

// linuxTableName is the name of the owned nftables table of one capture.
func linuxTableName(capture *linuxCapture) string {
	return fmt.Sprintf("sb_dsync_%d_%d", os.Getpid(), capture.queue)
}

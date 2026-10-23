//go:build linux

package desync

// Hermetic lifecycle and packet-delivery tests for the Linux NFQUEUE capture
// backend.
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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/sagernet/nftables"
)

var (
	errFakeNFQueueClosed   = errors.New("fake nfqueue connection is closed")
	errFakeSequence        = errors.New("netlink validate: mismatched sequence in netlink reply")
	errFakeNoDeadline      = errors.New("fake nfqueue connection does not support read deadlines")
	errFakeForeignPort     = errors.New("operation not permitted")
	errFakeQueueNotBound   = errors.New("no such queue")
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
	events   []fakeKernelEvent
}

func newFakeQueueKernel() *fakeQueueKernel {
	return &fakeQueueKernel{bindings: make(map[uint16]*fakeNFQueueConn)}
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
		return nil
	default:
		// Queue parameter update.
		if !isBound {
			return errFakeQueueNotBound
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
	k.events = append(k.events, fakeKernelEvent{kind: "deliver", queue: queue, port: owner.portid, id: id})
	k.mu.Unlock()
	return owner.deliver(message)
}

// verdict records the disposition the capture sent for one packet.
func (k *fakeQueueKernel) verdict(owner *fakeNFQueueConn, queue uint16, id, verdict uint32) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.events = append(k.events, fakeKernelEvent{
		kind: "verdict", queue: queue, port: owner.portid, id: id, verdict: verdict,
	})
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
	return []netlink.Message{{Header: netlink.Header{Type: netlink.Error, Sequence: sequence}}}, nil
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
		hook := f.executeHook
		_ = hook
		f.stateMu.Unlock()
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

// fakeRuleWriter records the owned-table lifecycle instead of opening a
// NETLINK_NETFILTER nftables transaction.
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
		// The hook runs exactly between the table removal and the queue
		// teardown, which is the interleaving window a captured packet can
		// still be sitting in.
		hook()
	}
	return err
}

func (f *fakeRuleWriter) deletedTables() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.deleted...)
}

func (f *fakeRuleWriter) flushCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.flushes
}

func (f *fakeRuleWriter) setFlushError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flushErr = err
}

func (f *fakeRuleWriter) setDeleteHook(hook func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleteHook = hook
}

// linuxCaptureSeams is the in-memory replacement of the two native seams. The
// dial factory hands out the queue connection first; any additional connection
// the implementation opens is tracked, because a capture must own exactly one:
// the port that receives is the port that binds.
type linuxCaptureSeams struct {
	first     *fakeNFQueueConn
	firstUsed bool
	kernel    *fakeQueueKernel
	mu        sync.Mutex
	extra     []*fakeNFQueueConn
	extraNext uint32
}

func (s *linuxCaptureSeams) dial() (nfqueueConn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.firstUsed {
		s.firstUsed = true
		if s.first == nil {
			s.first = newFakeNFQueueConn("queue", 0x51a00001, s.kernel)
		}
		return s.first, nil
	}
	s.extraNext++
	extra := newFakeNFQueueConn(fmt.Sprintf("extra-%d", s.extraNext), 0x51a00001+s.extraNext, s.kernel)
	s.extra = append(s.extra, extra)
	return extra, nil
}

func (s *linuxCaptureSeams) extraConnections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.extra)
}

// installLinuxCaptureSeams swaps the native seams for one test and restores
// them afterwards. The probe file path is missing on purpose: absence of the
// kernel report must never be read as a collision.
func installLinuxCaptureSeams(t *testing.T, queue *fakeNFQueueConn, rules *fakeRuleWriter) *linuxCaptureSeams {
	t.Helper()
	kernel := newFakeQueueKernel()
	previousOpen := openNFQueueConn
	previousWriter := newLinuxRuleWriter
	previousReport := linuxQueueReportPath
	seams := &linuxCaptureSeams{kernel: kernel}
	if queue != nil {
		queue.kernel = kernel
		seams.first = queue
	}
	openNFQueueConn = seams.dial
	newLinuxRuleWriter = func() linuxRuleWriter { return rules }
	linuxQueueReportPath = filepath.Join(t.TempDir(), "missing-nfnetlink_queue")
	t.Cleanup(func() {
		openNFQueueConn = previousOpen
		newLinuxRuleWriter = previousWriter
		linuxQueueReportPath = previousReport
		seams.mu.Lock()
		extras := append([]*fakeNFQueueConn(nil), seams.extra...)
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
	rules := &fakeRuleWriter{}
	seams := installLinuxCaptureSeams(t, data, rules)
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
	rules := &fakeRuleWriter{}
	seams := installLinuxCaptureSeams(t, data, rules)
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
	if got := countQueueCommand(t, executed, 15000, nfqCfgCmdUnbind); got != 1 {
		t.Fatalf("outbound queue unbinds = %d, want 1 (messages %d)", got, len(executed))
	}
	if got := countQueueCommand(t, executed, linux.inQueue, nfqCfgCmdUnbind); got != 1 {
		t.Fatalf("inbound queue unbinds = %d, want 1", got)
	}
	if bound := seams.kernel.boundQueues(); len(bound) != 0 {
		t.Fatalf("queues still bound after Close: %v", bound)
	}
	if got := len(rules.deletedTables()); got != 1 || rules.deletedTables()[0] != linuxTableName(linux) {
		t.Fatalf("deleted tables = %v", rules.deletedTables())
	}
	if rules.flushCount() != 2 { // one install transaction, one table removal
		t.Fatalf("table flushes = %d, want 2", rules.flushCount())
	}
	if data.closings() != 1 {
		t.Fatalf("connection closes = %d, want 1", data.closings())
	}
	// The unbind exchange must come after the queue connection stop: the model
	// refuses to run Execute while a receive holds the lock, so reaching this
	// point already proves it, and the recorded order documents it.
	unbindIndex := seams.kernel.eventIndex(func(event fakeKernelEvent) bool {
		return event.kind == "unbind" && event.queue == 15000
	})
	if unbindIndex < 0 {
		t.Fatal("no recorded unbind of the outbound queue")
	}

	// Repeated close is a no-op: it must not repeat any native side effect.
	if err := capture.Close(); err != nil {
		t.Fatalf("repeated Close: %v", err)
	}
	if got := len(data.executedMessages()); got != len(executed) {
		t.Fatalf("repeated Close sent %d extra control messages", got-len(executed))
	}
	if got := len(rules.deletedTables()); got != 1 {
		t.Fatalf("repeated Close deleted %d tables", got)
	}
	if data.closings() != 1 {
		t.Fatal("repeated Close re-closed the native connection")
	}
	if qnumLive(15000) {
		t.Fatal("repeated Close left the explicit queue identity reserved")
	}
}

// TestLinuxCaptureCloseDrainsPacketsQueuedDuringTeardown covers the interleaved
// packet/control/teardown case: a packet that is still queued when the owned
// table is removed is answered by the loop before the queue is unbound, and the
// unbind exchange on the same connection then passes reply validation.
func TestLinuxCaptureCloseDrainsPacketsQueuedDuringTeardown(t *testing.T) {
	data := newFakeNFQueueConn("queue", 0, nil)
	rules := &fakeRuleWriter{}
	seams := installLinuxCaptureSeams(t, data, rules)
	_, lease := newLinuxCaptureLease(t, 15011)

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

	packet := buildIPv4TCP(t, nil, 1000, tcpFlagACK|tcpFlagPSH)
	queued := uint32(77)
	rules.setDeleteHook(func() {
		// Exactly the teardown window: the table is gone, the queues are still
		// bound and the receive loop has not been stopped yet.
		if !seams.kernel.deliver(linux.queue, fakePacketMessage(linux.queue, queued, packet.Raw), queued) {
			t.Errorf("owned queue refused the packet queued during teardown")
		}
	})

	closed := make(chan error, 1)
	go func() { closed <- capture.Close() }()
	if err := waitWithin(t, "capture Close", closed); err != nil {
		t.Fatalf("capture Close: %v (the unread packet message must not fail the unbind exchange)", err)
	}

	verdicts := seams.kernel.verdictsFor(linux.queue, queued)
	if len(verdicts) != 1 {
		t.Fatalf("verdicts for the packet queued during teardown = %d, want 1 (dropped instead of drained)", len(verdicts))
	}
	// Ordering: answered before the queue was unbound.
	verdictIndex := seams.kernel.eventIndex(func(event fakeKernelEvent) bool {
		return event.kind == "verdict" && event.id == queued
	})
	unbindIndex := seams.kernel.eventIndex(func(event fakeKernelEvent) bool {
		return event.kind == "unbind" && event.queue == linux.queue
	})
	if verdictIndex < 0 || unbindIndex < 0 || verdictIndex > unbindIndex {
		t.Fatalf("event order verdict=%d unbind=%d, want the drain to answer before the unbind", verdictIndex, unbindIndex)
	}
	if bound := seams.kernel.boundQueues(); len(bound) != 0 {
		t.Fatalf("queues still bound after Close: %v", bound)
	}
	if len(rules.deletedTables()) != 1 || data.closings() != 1 {
		t.Fatalf("table deletions = %d, connection closes = %d, want 1/1", len(rules.deletedTables()), data.closings())
	}
}

// TestLinuxCaptureCloseWithoutDeadlineSupportDoesNotHang pins the failure path
// of the stop signal: a transport that cannot interrupt a blocked receive is
// reported, the loop is still joined, and Close does not claim success.
func TestLinuxCaptureCloseWithoutDeadlineSupportDoesNotHang(t *testing.T) {
	data := newFakeNFQueueConn("queue", 0, nil)
	data.deadlineDisabled = true
	rules := &fakeRuleWriter{}
	installLinuxCaptureSeams(t, data, rules)
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
	if got := len(rules.deletedTables()); got != 1 {
		t.Fatalf("owned table deletions = %d, want 1", got)
	}
}

// TestLinuxCaptureConcurrentLeaseAndEngineClose verifies exact-once teardown
// when Lease.Close and Engine.Close race, and that Engine.Close cannot report
// completion while its lease still owns native resources.
func TestLinuxCaptureConcurrentLeaseAndEngineClose(t *testing.T) {
	data := newFakeNFQueueConn("queue", 0, nil)
	rules := &fakeRuleWriter{}
	seams := installLinuxCaptureSeams(t, data, rules)
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
	if got := countQueueCommand(t, data.executedMessages(), 15001, nfqCfgCmdUnbind); got != 1 {
		t.Fatalf("outbound unbinds = %d, want 1", got)
	}
	if bound := seams.kernel.boundQueues(); len(bound) != 0 {
		t.Fatalf("queues still bound after Close: %v", bound)
	}
}

// TestLinuxCaptureLoopIgnoresForeignQueues pins that the receive loop answers
// verdicts only for its own queue identities and never widens ownership.
func TestLinuxCaptureLoopIgnoresForeignQueues(t *testing.T) {
	data := newFakeNFQueueConn("queue", 0, nil)
	rules := &fakeRuleWriter{}
	seams := installLinuxCaptureSeams(t, data, rules)
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
	data.incoming <- fakePacketMessage(linux.queue, 12, packet.Raw)

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
		rules := &fakeRuleWriter{}
		seams := installLinuxCaptureSeams(t, data, rules)
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
		if rules.flushCount() != 0 {
			t.Fatal("failed open touched the owned table")
		}
		if seams.extraConnections() != 0 {
			t.Fatal("failed open opened an extra connection")
		}
	})

	t.Run("queue parameter failure unbinds", func(t *testing.T) {
		data := newFakeNFQueueConn("queue", 0, nil)
		rules := &fakeRuleWriter{}
		seams := installLinuxCaptureSeams(t, data, rules)
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
		if rules.flushCount() != 0 {
			t.Fatal("failed open touched the owned table")
		}
	})

	t.Run("rule installation failure unbinds both queues", func(t *testing.T) {
		data := newFakeNFQueueConn("queue", 0, nil)
		rules := &fakeRuleWriter{}
		seams := installLinuxCaptureSeams(t, data, rules)
		rules.setFlushError(errors.New("nftables transaction failed"))
		_, lease := newLinuxCaptureLease(t, 15006)
		if _, err := openLinuxCapture(lease); err == nil {
			t.Fatal("capture opened although rule installation failed")
		}
		executed := data.executedMessages()
		if got := countQueueCommand(t, executed, 15006, nfqCfgCmdUnbind); got != 1 {
			t.Fatalf("outbound rollback unbinds = %d, want 1", got)
		}
		if got := len(rules.deletedTables()); got != 1 {
			t.Fatalf("table deletions after failed install = %d, want 1", got)
		}
		if data.closings() != 1 {
			t.Fatal("failed install leaked the queue connection")
		}
		if bound := seams.kernel.boundQueues(); len(bound) != 0 {
			t.Fatalf("queues still bound after the failed install: %v", bound)
		}
	})
}

// linuxTableName is the name of the owned nftables table of one capture.
func linuxTableName(capture *linuxCapture) string {
	return fmt.Sprintf("sb_dsync_%d_%d", os.Getpid(), capture.queue)
}

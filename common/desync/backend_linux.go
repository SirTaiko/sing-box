//go:build linux

package desync

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"iter"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/socket"
	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/expr"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	// injectionMarkBit marks replacement packets in the socket mark without
	// disturbing the effective routing mark carried by the original socket.
	injectionMarkBit     = 0x53590000
	nfqueueVerdictAccept = 1
	nfqueueVerdictDrop   = 0

	// NFQUEUE netlink constants (linux/netfilter/nfnetlink_queue.h).
	nfqCfgAttrCmd      = 1 // NFQA_CFG_CMD, payload nfqnl_msg_config_cmd
	nfqCfgAttrParams   = 2 // NFQA_CFG_PARAMS
	nfqCfgAttrQueueMax = 3 // NFQA_CFG_QUEUE_MAXLEN
	nfqCfgAttrMask     = 4 // NFQA_CFG_MASK
	nfqCfgAttrFlags    = 5 // NFQA_CFG_FLAGS
	nfqCfgCmdBind      = 1 // NFQNL_CFG_CMD_BIND
	nfqCfgCmdUnbind    = 2 // NFQNL_CFG_CMD_UNBIND
	nfqCfgFlagFail     = 1 << 0
	nfqCfgFlagCT       = 1 << 1
	nfqCfgFlagGSO      = 1 << 2
	nfqPacketID        = 1
	nfqPacketPayload   = 10
	nfqMessageConfig   = 2

	// queueCandidates bounds the managed queue allocation attempts. The
	// kernel and /proc reports are authoritative; this is only a search bound.
	queueCandidates = 64
	// queueCapacity bounds the kernel-side queue of one owned capture. It must
	// cover the held originals of one flow plus the initial flight.
	queueCapacity = 8192
	// queueStopDrain bounds the teardown drain of one owned capture. The
	// window is only an interrupt; emptiness is proven by the transport
	// readiness probe and the ordered no-op CONFIG receipts.
	queueStopDrain = 10 * time.Millisecond

	// anchorTransactionAttempts bounds the retry of a busy namespace
	// transaction. EADDRINUSE is a wait, never authority to steal anything.
	anchorTransactionAttempts = 16
	// anchorTransactionBackoff is the first retry delay of a busy transaction.
	anchorTransactionBackoff = 2 * time.Millisecond
	// anchorReceiptAttempts bounds the repetition of a lost, no-mutation fence
	// reply or a lost creation/detach acknowledgement.
	anchorReceiptAttempts = 3
)

// anchorTransactionAddress is the shared short-lived namespace transaction
// mutex of the selected-A contract. Every cooperating process of one actual
// network namespace binds the same name; EADDRINUSE is a wait.
const anchorTransactionAddress = "\x00sing-box.desync.v1.tx"

// anchorGuardPrefix is the leading part of the owner-liveness abstract name.
const anchorGuardPrefix = "\x00sing-box.desync.v1.owner."

// anchorGuardAddress returns the owner-liveness address of one process token.
func anchorGuardAddress(process string) string { return anchorGuardPrefix + process }

// ---------------------------------------------------------------------------
// Pinned actual-namespace helper.
// ---------------------------------------------------------------------------

// getThreadNetns and setThreadNetns are seams: production uses the pinned
// vishvananda/netns thread helpers; model tests run the operation without
// entering a namespace.
var (
	getThreadNetns = netns.Get
	setThreadNetns = netns.Set
)

// withAnchorNamespace saves the origin namespace of the calling OS thread,
// enters the target, runs one bounded operation and restores the origin before
// unlocking the thread. A failed restoration must not return a contaminated
// thread to the pool: the helper returns without UnlockOSThread, so the runtime
// discards the thread instead of reusing it in the wrong namespace.
func withAnchorNamespace(namespaceFD int, operation func() error) error {
	runtime.LockOSThread()
	origin, err := getThreadNetns()
	if err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("desync: save calling network namespace: %w", err)
	}
	if err = setThreadNetns(netns.NsHandle(namespaceFD)); err != nil {
		_ = origin.Close()
		runtime.UnlockOSThread()
		return fmt.Errorf("desync: enter capture network namespace: %w", err)
	}
	operationErr := operation()
	restoreErr := setThreadNetns(origin)
	_ = origin.Close()
	if restoreErr != nil {
		// Deliberately no UnlockOSThread: the thread is contaminated and must
		// never serve another goroutine in the wrong namespace.
		if operationErr != nil {
			return errors.Join(operationErr, fmt.Errorf("desync: restore calling network namespace: %w", restoreErr))
		}
		return fmt.Errorf("desync: restore calling network namespace: %w", restoreErr)
	}
	runtime.UnlockOSThread()
	return operationErr
}

// withForkReadToken holds the single nonrecursive syscall.ForkLock read token
// for one short interval. No nested helper may take it again: a waiting fork
// writer would deadlock the nested read lock.
func withForkReadToken(operation func() error) error {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	return operation()
}

// anchorNamespaceKey is the actual namespace identity: pinned (st_dev,st_ino),
// never a name or configuration alias.
type anchorNamespaceKey struct {
	dev uint64
	ino uint64
}

// anchorNamespaceHandle captures the calling thread's namespace identity and
// returns the owned handle plus its key.
func anchorNamespaceHandle() (int, anchorNamespaceKey, error) {
	handle, err := getThreadNetns()
	if err != nil {
		return -1, anchorNamespaceKey{}, fmt.Errorf("desync: open calling network namespace: %w", err)
	}
	fd := int(handle)
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		_ = handle.Close()
		return -1, anchorNamespaceKey{}, fmt.Errorf("desync: identify calling network namespace: %w", err)
	}
	key := anchorNamespaceKey{dev: uint64(stat.Dev), ino: uint64(stat.Ino)}
	return fd, key, nil
}

// ---------------------------------------------------------------------------
// Owner guard and process identity.
// ---------------------------------------------------------------------------

// anchorGuard is the long-lived abstract owner-liveness socket of one process
// incarnation in one actual namespace.
type anchorGuard struct {
	fd   int
	name string
	// onClose is a test seam: it runs after the fd was released. Production
	// leaves it nil.
	onClose func()
}

func (g *anchorGuard) close() error {
	if g == nil || g.fd < 0 && g.onClose == nil {
		return nil
	}
	var err error
	if g.fd >= 0 {
		err = unix.Close(g.fd)
		g.fd = -1
	}
	if g.onClose != nil {
		g.onClose()
		g.onClose = nil
	}
	return err
}

// bindAbstractDatagram binds one exactly named abstract AF_UNIX datagram
// socket. Binding is exclusive: EADDRINUSE means the name is occupied.
func bindAbstractDatagram(name string) (int, error) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return -1, fmt.Errorf("desync: open abstract socket: %w", err)
	}
	if err = unix.Bind(fd, &unix.SockaddrUnix{Name: name}); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// bindAnchorGuardSocket and probeAnchorGuardAddress are seams so model tests
// can emulate the whole-thread-group and inherited-guard schedules without a
// live cooperating process.
var (
	bindAnchorGuardSocket = func(name string) (*anchorGuard, error) {
		fd, err := bindAbstractDatagram(name)
		if err != nil {
			return nil, err
		}
		return &anchorGuard{fd: fd, name: name}, nil
	}
	probeAnchorGuardAddress = func(name string) (busy bool, err error) {
		fd, bindErr := bindAbstractDatagram(name)
		if bindErr == nil {
			_ = unix.Close(fd)
			return false, nil
		}
		if errors.Is(bindErr, unix.EADDRINUSE) {
			return true, nil
		}
		return false, bindErr
	}
)

// anchorPidNamespace is the recorded PID-namespace identity.
type anchorPidNamespace struct {
	dev uint64
	ino uint64
}

// readPidNamespaceIdentity returns the (st_dev,st_ino) of one namespace path.
func readPidNamespaceIdentity(path string) (anchorPidNamespace, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return anchorPidNamespace{}, err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return anchorPidNamespace{}, err
	}
	return anchorPidNamespace{dev: uint64(stat.Dev), ino: uint64(stat.Ino)}, nil
}

// currentPidNamespace reads the observer's own PID namespace identity.
func currentPidNamespace() (anchorPidNamespace, error) {
	return readPidNamespaceIdentity("/proc/self/ns/pid")
}

// processStartTicks reads field 22 (starttime) of /proc/<pid>/stat.
func processStartTicks(pid int) (uint64, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, err
	}
	// The comm field may contain spaces and parentheses; the last ')' ends it.
	close := strings.LastIndexByte(string(data), ')')
	if close < 0 {
		return 0, errors.New("desync: malformed /proc stat record")
	}
	fields := strings.Fields(string(data[close+1:]))
	// After the comm field, the next field is state (field 3). starttime is
	// field 22, i.e. index 19 of the remaining fields.
	if len(fields) < 20 {
		return 0, errors.New("desync: short /proc stat record")
	}
	return strconv.ParseUint(fields[19], 10, 64)
}

// anchorOwnerVerdict is the whole-thread-group classification of one recorded
// owner incarnation.
type anchorOwnerVerdict int

const (
	anchorOwnerUnknown anchorOwnerVerdict = iota
	anchorOwnerLive
	anchorOwnerDead
)

// anchorOwnerObservation is one nonblocking owner observation.
type anchorOwnerObservation struct {
	verdict anchorOwnerVerdict
	reason  string
}

// observeOwnerProcess classifies the recorded process incarnation. A matching,
// visible PID namespace plus pidfd/startticks evidence decides death; a
// mismatched namespace or an unopenable pidfd without conclusive ESRCH is
// UNKNOWN, never inferred death.
var observeOwnerProcess = func(record anchorRecord) (anchorOwnerObservation, error) {
	if record.ports.tgid == 0 || record.ports.startTicks == 0 {
		return anchorOwnerObservation{verdict: anchorOwnerUnknown, reason: "manifest has no process identity"}, nil
	}
	observer, err := currentPidNamespace()
	if err != nil {
		return anchorOwnerObservation{}, fmt.Errorf("desync: read observer PID namespace: %w", err)
	}
	if observer.dev != record.ports.pidnsDev || observer.ino != record.ports.pidnsIno {
		return anchorOwnerObservation{verdict: anchorOwnerUnknown, reason: "recorded PID namespace is not observable here"}, nil
	}
	pidfd, err := unix.PidfdOpen(int(record.ports.tgid), 0)
	if err != nil {
		if errors.Is(err, unix.ESRCH) {
			return anchorOwnerObservation{verdict: anchorOwnerDead, reason: "recorded process incarnation was reaped"}, nil
		}
		return anchorOwnerObservation{verdict: anchorOwnerUnknown, reason: "pidfd unavailable"}, nil
	}
	defer unix.Close(pidfd)
	ticks, err := processStartTicks(int(record.ports.tgid))
	if err != nil {
		return anchorOwnerObservation{verdict: anchorOwnerUnknown, reason: "start time unavailable"}, nil
	}
	if ticks != record.ports.startTicks {
		// PID reuse: the recorded incarnation is gone; the new process is not
		// its owner and is never signalled or treated as live ownership.
		return anchorOwnerObservation{verdict: anchorOwnerDead, reason: "recorded start time no longer exists"}, nil
	}
	pollFDs := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	count, err := unix.Poll(pollFDs, 0)
	if err != nil {
		if errors.Is(err, unix.EINTR) {
			return anchorOwnerObservation{verdict: anchorOwnerUnknown, reason: "poll interrupted"}, nil
		}
		return anchorOwnerObservation{verdict: anchorOwnerUnknown, reason: "pidfd poll unavailable"}, nil
	}
	if count > 0 && pollFDs[0].Revents&unix.POLLIN != 0 {
		return anchorOwnerObservation{verdict: anchorOwnerDead, reason: "whole thread group exited"}, nil
	}
	return anchorOwnerObservation{verdict: anchorOwnerLive, reason: "matching live incarnation"}, nil
}

// ---------------------------------------------------------------------------
// Anchor owner registry: one owner token P and one guard per process and
// actual namespace. The map keeps no O(n) historical namespace list: entries
// exist only while opening/live/retained captures or transactions reference
// them.
// ---------------------------------------------------------------------------

// anchorOwner is the process incarnation in one actual namespace.
type anchorOwner struct {
	mu     sync.Mutex
	key    anchorNamespaceKey
	nsFD   int
	token  string
	guard  *anchorGuard
	refs   int
	closed bool
	// retiring is set when the last capture started owner retirement: no new
	// reference may be admitted from that point.
	retiring bool
	// ready is closed once the guard binding finished (or failed).
	ready   chan struct{}
	initErr error
	// retained is set when a close or failed open could not prove retirement;
	// no new generation may be appended for this owner while it is set.
	retained bool
}

var anchorOwnerRegistry = struct {
	sync.Mutex
	owners map[anchorNamespaceKey]*anchorOwner
}{owners: make(map[anchorNamespaceKey]*anchorOwner)}

func newAnchorProcessToken() (string, error) { return newAnchorNonce() }

// anchorOwnerAcquire pins the calling thread's actual namespace and returns a
// referenced owner. The first caller of a namespace binds the owner guard; the
// concrete anchor initialization runs on every capture open, not only here.
func anchorOwnerAcquire() (*anchorOwner, error) {
	namespaceFD, key, err := anchorNamespaceHandle()
	if err != nil {
		return nil, err
	}
	anchorOwnerRegistry.Lock()
	if owner, found := anchorOwnerRegistry.owners[key]; found {
		owner.mu.Lock()
		if owner.closed || owner.retiring {
			owner.mu.Unlock()
			anchorOwnerRegistry.Unlock()
			_ = unix.Close(namespaceFD)
			return nil, errors.New("desync: anchor owner is retiring")
		}
		owner.refs++
		ready := owner.ready
		owner.mu.Unlock()
		anchorOwnerRegistry.Unlock()
		_ = unix.Close(namespaceFD)
		<-ready
		owner.mu.Lock()
		initErr := owner.initErr
		owner.mu.Unlock()
		if initErr != nil {
			owner.releaseRef()
			return nil, initErr
		}
		return owner, nil
	}
	token, err := newAnchorProcessToken()
	if err != nil {
		anchorOwnerRegistry.Unlock()
		_ = unix.Close(namespaceFD)
		return nil, err
	}
	owner := &anchorOwner{key: key, nsFD: namespaceFD, token: token, refs: 1, ready: make(chan struct{})}
	anchorOwnerRegistry.owners[key] = owner
	anchorOwnerRegistry.Unlock()
	initErr := withAnchorNamespace(namespaceFD, func() error {
		guard, err := bindAnchorGuardSocket(anchorGuardAddress(token))
		if err != nil {
			return fmt.Errorf("desync: bind anchor owner guard: %w", err)
		}
		owner.guard = guard
		return nil
	})
	owner.mu.Lock()
	owner.initErr = initErr
	owner.mu.Unlock()
	close(owner.ready)
	if initErr != nil {
		owner.mu.Lock()
		owner.closed = true
		owner.mu.Unlock()
		anchorOwnerRegistry.Lock()
		delete(anchorOwnerRegistry.owners, key)
		anchorOwnerRegistry.Unlock()
		_ = owner.guard.close()
		_ = unix.Close(namespaceFD)
		return nil, initErr
	}
	return owner, nil
}

// releaseRef drops one capture reference. The namespace handle is closed at
// zero references; the guard and metadata are retired by the last capture under
// its receipts, so this helper only performs the bookkeeping fallback.
func (o *anchorOwner) releaseRef() {
	if o == nil {
		return
	}
	o.mu.Lock()
	if o.refs > 0 {
		o.refs--
	}
	last := o.refs <= 0
	if last {
		o.closed = true
	}
	o.mu.Unlock()
	if !last {
		return
	}
	anchorOwnerRegistry.Lock()
	if anchorOwnerRegistry.owners[o.key] == o {
		delete(anchorOwnerRegistry.owners, o.key)
	}
	anchorOwnerRegistry.Unlock()
	_ = o.guard.close()
	if o.nsFD >= 0 {
		_ = unix.Close(o.nsFD)
		o.nsFD = -1
	}
}

// isLastCapture reports whether this capture holds the last owner reference.
func (o *anchorOwner) isLastCapture() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.refs <= 1
}

func (o *anchorOwner) markRetained() {
	o.mu.Lock()
	o.retained = true
	o.mu.Unlock()
}

func (o *anchorOwner) retainedState() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.retained
}

// beginCaptureRetirement marks the owner RETIRING when this capture is its last
// reference. From that point no new capture reference is admitted, so the
// guard release probe and the last record removal are ordered against every
// later open.
func (o *anchorOwner) beginCaptureRetirement() (bool, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.retiring {
		return false, errors.New("desync: anchor owner is already retiring")
	}
	if o.refs <= 1 {
		o.retiring = true
		return true, nil
	}
	return false, nil
}

// releaseOwnerRef releases the capture's single owner reference exactly once.
func (c *linuxCapture) releaseOwnerRef() {
	if c == nil || !c.refHeld {
		return
	}
	c.refHeld = false
	c.owner.releaseRef()
}

// ---------------------------------------------------------------------------
// Namespace transaction.
// ---------------------------------------------------------------------------

// withAnchorTransaction runs one short bounded metadata operation under the
// namespace transaction abstract socket and the single fork-read token. The
// transaction fd is created after the fork token and closed before it is
// released, so a child can never inherit it.
func withAnchorTransaction(owner *anchorOwner, operation func(anchorSession) error) error {
	if owner == nil || owner.nsFD < 0 {
		return errors.New("desync: anchor namespace is not open")
	}
	var lastErr error
	for attempt := 0; attempt < anchorTransactionAttempts; attempt++ {
		err := withAnchorNamespace(owner.nsFD, func() error {
			return withForkReadToken(func() error {
				fd, bindErr := bindAbstractDatagram(anchorTransactionAddress)
				if bindErr != nil {
					return bindErr
				}
				defer unix.Close(fd)
				session, sessionErr := openAnchorSession()
				if sessionErr != nil {
					return sessionErr
				}
				defer session.Close()
				return operation(session)
			})
		})
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EADDRINUSE) {
			return err
		}
		lastErr = err
		time.Sleep(anchorTransactionBackoff * time.Duration(attempt+1))
	}
	return fmt.Errorf("desync: namespace transaction stayed busy: %w", lastErr)
}

// ---------------------------------------------------------------------------
// Anchor object readback and validation.
// ---------------------------------------------------------------------------

type anchorTaggedRule struct {
	chain  string
	handle uint64
	role   string
	record anchorRecord
}

type anchorPortRecord struct {
	record anchorRecord
	handle uint64
}

type anchorManifestRecord struct {
	record anchorRecord
	handle uint64
	port   *anchorPortRecord
}

// anchorFamilyState is one fully validated family of the fixed anchors plus
// every captured record that exists in that namespace.
type anchorFamilyState struct {
	family       string
	tableFamily  byte
	epoch        string
	nextTag      uint64
	anchorHandle uint64
	tagHandle    uint64
	captures     map[string]*anchorManifestRecord
	chains       map[string]map[string]uint64 // capture key -> chain name -> handle
	baseRules    map[string][]anchorTaggedRule
}

func captureKey(process, capture string) string { return process + "/" + capture }

func anchorFamilyNames(family Family) (familyName string, tableFamily byte, err error) {
	switch family {
	case FamilyIPv4:
		return "ip", byte(nftables.TableFamilyIPv4), nil
	case FamilyIPv6:
		return "ip6", byte(nftables.TableFamilyIPv6), nil
	default:
		return "", 0, fmt.Errorf("desync: unsupported anchor family %d", family)
	}
}

func anchorTableFamily(family string) (byte, error) {
	switch family {
	case "ip":
		return byte(nftables.TableFamilyIPv4), nil
	case "ip6":
		return byte(nftables.TableFamilyIPv6), nil
	default:
		return 0, fmt.Errorf("desync: unknown anchor family %q", family)
	}
}

// nftRecords returns the table/chain/rule snapshots over one session.
func readAnchorTables(session anchorSession, family byte) ([]nftTableRecord, error) {
	replies, err := session.dump(unix.NFT_MSG_GETTABLE, family, nil)
	if err != nil {
		return nil, err
	}
	tables := make([]nftTableRecord, 0, len(replies))
	for _, reply := range replies {
		_, attrs, parseErr := nftMessageData(reply)
		if parseErr != nil {
			return nil, parseErr
		}
		name, ok := nftAttrString(attrs, unix.NFTA_TABLE_NAME)
		if !ok {
			return nil, errors.New("desync: nftables table readback without a name")
		}
		flags, _ := nftAttrUint32(attrs, unix.NFTA_TABLE_FLAGS)
		tables = append(tables, nftTableRecord{name: name, family: family, flags: flags})
	}
	return tables, nil
}

// nftReplyTableIdentity returns the table a chain or rule dump reply actually
// names. The reply is the only authority on that identity: the exact target
// kernel's GETCHAIN dump walks every table of the requested family and ignores
// the requested NFTA_CHAIN_TABLE attribute (nf_tables_dump_chains compares only
// nfmsg->nfgen_family with table->family), while its GETRULE dump does honour
// the requested table and chain (nf_tables_dump_rules). The kernel always emits
// the attribute, so a missing, empty or repeated identity is a malformed
// readback and is reported: it is never silently attributed to the requested
// table.
func nftReplyTableIdentity(attrs []netlink.Attribute, attr uint16) (string, error) {
	var (
		table string
		seen  bool
	)
	for _, attribute := range attrs {
		if attribute.Type&0x3fff != attr {
			continue
		}
		if seen {
			return "", errors.New("desync: duplicate nftables table identity attribute")
		}
		seen = true
		data := attribute.Data
		if len(data) > 0 && data[len(data)-1] == 0 {
			data = data[:len(data)-1]
		}
		table = string(data)
	}
	if !seen || table == "" {
		return "", errors.New("desync: nftables readback without a table identity")
	}
	return table, nil
}

func readAnchorChains(session anchorSession, family byte, table string) ([]nftChainRecord, error) {
	replies, err := session.dump(unix.NFT_MSG_GETCHAIN, family, []netlink.Attribute{
		{Type: unix.NFTA_TABLE_NAME, Data: []byte(table + "\x00")},
	})
	if err != nil {
		return nil, err
	}
	chains := make([]nftChainRecord, 0, len(replies))
	for _, reply := range replies {
		msgFamily, attrs, parseErr := nftMessageData(reply)
		if parseErr != nil {
			return nil, parseErr
		}
		returnedTable, identityErr := nftReplyTableIdentity(attrs, unix.NFTA_CHAIN_TABLE)
		if identityErr != nil {
			return nil, identityErr
		}
		if returnedTable != table {
			// A chain of another table of the same family. It is not ours: it
			// is neither validated nor recorded, and nothing about it is
			// mutated or adopted.
			continue
		}
		if msgFamily != family {
			return nil, fmt.Errorf("desync: nftables table %q readback has family %d, want %d", table, msgFamily, family)
		}
		name, ok := nftAttrString(attrs, unix.NFTA_CHAIN_NAME)
		if !ok {
			return nil, errors.New("desync: nftables chain readback without a name")
		}
		record := nftChainRecord{table: returnedTable, name: name, family: msgFamily}
		if hookData, hasHook := nftAttrBytes(attrs, unix.NFTA_CHAIN_HOOK); hasHook {
			hookAttrs, hookErr := netlink.UnmarshalAttributes(hookData)
			if hookErr != nil {
				return nil, fmt.Errorf("desync: parse nftables chain hook: %w", hookErr)
			}
			hooknum, hasHooknum := nftAttrUint32(hookAttrs, unix.NFTA_HOOK_HOOKNUM)
			priority, hasPriority := nftAttrUint32(hookAttrs, unix.NFTA_HOOK_PRIORITY)
			if !hasHooknum || !hasPriority {
				return nil, errors.New("desync: nftables base chain without hook/priority")
			}
			record.hasHook, record.hooknum, record.priority = true, hooknum, int32(priority)
		}
		if policy, hasPolicy := nftAttrUint32(attrs, unix.NFTA_CHAIN_POLICY); hasPolicy {
			record.policy = policy
		}
		if kind, hasKind := nftAttrString(attrs, unix.NFTA_CHAIN_TYPE); hasKind {
			record.hasType, record.kind = true, kind
		}
		flags, hasFlags, flagErr := nftChainFlagsAttr(attrs)
		if flagErr != nil {
			return nil, fmt.Errorf("desync: read nftables chain %q: %w", name, flagErr)
		}
		if hasFlags {
			record.flags = flags
		}
		if userdata, hasUserdata := nftAttrBytes(attrs, nftAttrChainUserdata); hasUserdata {
			record.userdata = append([]byte(nil), userdata...)
		}
		chains = append(chains, record)
	}
	return chains, nil
}

func readAnchorRules(session anchorSession, family byte, table string, chain string) ([]nftRuleRecord, error) {
	attrs := []netlink.Attribute{{Type: unix.NFTA_RULE_TABLE, Data: []byte(table + "\x00")}}
	if chain != "" {
		attrs = append(attrs, netlink.Attribute{Type: unix.NFTA_RULE_CHAIN, Data: []byte(chain + "\x00")})
	}
	replies, err := session.dump(unix.NFT_MSG_GETRULE, family, attrs)
	if err != nil {
		return nil, err
	}
	rules := make([]nftRuleRecord, 0, len(replies))
	for _, reply := range replies {
		msgFamily, msgAttrs, parseErr := nftMessageData(reply)
		if parseErr != nil {
			return nil, parseErr
		}
		returnedTable, identityErr := nftReplyTableIdentity(msgAttrs, unix.NFTA_RULE_TABLE)
		if identityErr != nil {
			return nil, identityErr
		}
		if returnedTable != table {
			// A rule of another table. The target kernel filters this dump by
			// table and chain already, so this selection is a redundant guard;
			// it keeps the rule readback from ever recording a foreign-table
			// rule as ours.
			continue
		}
		if msgFamily != family {
			return nil, fmt.Errorf("desync: nftables table %q rule readback has family %d, want %d", table, msgFamily, family)
		}
		record := nftRuleRecord{table: returnedTable}
		record.chain, _ = nftAttrString(msgAttrs, unix.NFTA_RULE_CHAIN)
		record.handle, _ = nftAttrUint64(msgAttrs, unix.NFTA_RULE_HANDLE)
		if userdata, ok := nftAttrBytes(msgAttrs, unix.NFTA_RULE_USERDATA); ok {
			record.userdata = append([]byte(nil), userdata...)
		}
		rules = append(rules, record)
	}
	return rules, nil
}

// ensureTableShape validates the fixed table flags. Any OWNER/PERSIST/DORMANT
// flag means the object is not ours to reuse.
func validateAnchorTable(record nftTableRecord) error {
	if record.name != anchorTableName {
		return fmt.Errorf("desync: anchor table readback name %q", record.name)
	}
	if record.flags&nftTableFlagsDormant != 0 {
		return errors.New("desync: anchor table is dormant")
	}
	if record.flags != 0 {
		return fmt.Errorf("desync: anchor table carries flags %#x", record.flags)
	}
	return nil
}

// The nftables chain flags of the kernel UAPI (linux/netfilter/nf_tables.h,
// enum nft_chain_flags). The pinned x/sys v0.47.0 exports only the complete
// mask NFT_CHAIN_FLAGS (0x7, zerrors_linux.go), so the individual bits are
// spelled here:
//
//	NFT_CHAIN_BASE       = 1 << 0  intrinsic flag of every base chain
//	NFT_CHAIN_HW_OFFLOAD = 1 << 1  nftChainFlagHWOffload
//	NFT_CHAIN_BINDING    = 1 << 2  private anonymous binding chain
//
// The kernel sets NFT_CHAIN_BASE in nft_basechain_init and reports the whole
// nft_chain.flags word in NFTA_CHAIN_FLAGS (nf_tables_fill_chain_info), so a
// software base chain we created reads back with exactly this bit. Userspace
// cannot set it on a regular chain (nf_tables_addchain returns -EINVAL) and
// NFT_CHAIN_BINDING is only used for the anonymous __chain<N> objects.
const (
	nftChainFlagBase    = 0x1
	nftChainFlagBinding = 0x4
)

// nftChainFlagsAttr decodes the optional NFTA_CHAIN_FLAGS attribute of one
// chain dump record. The kernel sends the attribute at most once and only when
// the chain carries flags, so a repeated or wrongly sized attribute is a
// malformed readback, never a silent "no flags": treating it as absent would
// let a truncated reply pass the strict shape validation unchanged.
func nftChainFlagsAttr(attrs []netlink.Attribute) (uint32, bool, error) {
	var (
		flags uint32
		seen  bool
	)
	for _, attr := range attrs {
		if attr.Type&0x3fff != nftAttrChainFlags {
			continue
		}
		if seen {
			return 0, false, errors.New("duplicate NFTA_CHAIN_FLAGS attribute")
		}
		if len(attr.Data) != 4 {
			return 0, false, fmt.Errorf("NFTA_CHAIN_FLAGS attribute has %d bytes, want 4", len(attr.Data))
		}
		flags = binary.BigEndian.Uint32(attr.Data)
		seen = true
	}
	return flags, seen, nil
}

// validateAnchorBaseChain checks family, type, hook, priority, policy and
// flags of one fixed base chain.
func validateAnchorBaseChain(record nftChainRecord, family string, familyByte byte, base string, expectedHook uint32, epoch string) error {
	if record.table != anchorTableName || record.name != base {
		return fmt.Errorf("desync: unexpected base chain %q", record.name)
	}
	if record.family != familyByte {
		return fmt.Errorf("desync: base chain %q has family %d", base, record.family)
	}
	if !record.hasHook || record.hooknum != expectedHook {
		return fmt.Errorf("desync: base chain %q has no matching hook", base)
	}
	if record.priority != anchorBaseHookPriority {
		return fmt.Errorf("desync: base chain %q has priority %d", base, record.priority)
	}
	if !record.hasType || record.kind != "filter" {
		return fmt.Errorf("desync: base chain %q is not a filter chain", base)
	}
	if record.policy != nftVerdictAccept {
		return fmt.Errorf("desync: base chain %q has policy %d, not accept", base, record.policy)
	}
	// NFT_CHAIN_BASE is the kernel's own statement that this object is a base
	// chain: it is set by the kernel on creation and cannot be requested for a
	// regular chain. A dump of a kernel that predates the flag carries no
	// attribute at all, which readAnchorChains reports as zero. Every other
	// bit is a mismatch: an offloaded base chain would leave the software path
	// this capture queues from, a binding chain is a private anonymous chain,
	// and an unknown bit means the readback is not the chain we installed.
	if record.flags&nftChainFlagHWOffload != 0 {
		return fmt.Errorf("desync: base chain %q is hardware offloaded (flags %#x)", base, record.flags)
	}
	if record.flags&nftChainFlagBinding != 0 {
		return fmt.Errorf("desync: base chain %q is a binding chain (flags %#x)", base, record.flags)
	}
	if unknown := record.flags &^ (nftChainFlagBase | nftChainFlagHWOffload | nftChainFlagBinding); unknown != 0 {
		return fmt.Errorf("desync: base chain %q carries unknown flags %#x", base, unknown)
	}
	if string(record.userdata) != anchorBaseUserdata(epoch, base) {
		return fmt.Errorf("desync: base chain %q has foreign userdata", base)
	}
	return nil
}

// validateAnchorRegularChain rejects a chain that is not a plain named regular
// chain of the anchor table. The kernel only ever sets NFT_CHAIN_BASE on base
// chains, refuses NFT_CHAIN_BASE/NFT_CHAIN_HW_OFFLOAD from userspace on a
// regular chain and confines NFT_CHAIN_BINDING to the anonymous __chain<N>
// objects, so one of our named regular chains must read back without hook,
// type or any flag bit.
func validateAnchorRegularChain(record nftChainRecord, label string) error {
	if record.hasHook || record.hasType {
		return fmt.Errorf("desync: %s %q is not a regular chain", label, record.name)
	}
	if record.flags != 0 {
		return fmt.Errorf("desync: %s %q carries flags %#x, want none", label, record.name, record.flags)
	}
	return nil
}

// anchorRecordHandle pairs a parsed record with the exact current handle.
type anchorRecordHandle struct {
	record anchorRecord
	handle uint64
}

// parseMarkerRules parses and cross-validates every rule of the marker chain.
// Exactly one anchor record a and one tag record t are required; every m must
// have exactly one p and every p exactly one m; all epoch fields must match.
func parseMarkerRules(records []nftRuleRecord, family, epoch string) (anchorRecordHandle, anchorRecordHandle, map[string]*anchorManifestRecord, error) {
	var (
		anchorRule *anchorRecordHandle
		tagRule    *anchorRecordHandle
	)
	manifests := make(map[string]*anchorManifestRecord)
	ports := make(map[string]*anchorPortRecord)
	for _, record := range records {
		if record.chain != anchorMarkerChainName {
			continue
		}
		if len(record.userdata) == 0 {
			return anchorRecordHandle{}, anchorRecordHandle{}, nil, fmt.Errorf("desync: untagged rule %d in the marker chain", record.handle)
		}
		parsed, err := parseAnchorUserdata(string(record.userdata))
		if err != nil {
			return anchorRecordHandle{}, anchorRecordHandle{}, nil, err
		}
		handle := anchorRecordHandle{record: parsed, handle: record.handle}
		epochMatches := epoch == "" || parsed.epoch == epoch
		switch parsed.kind {
		case anchorKindAnchor:
			if parsed.family != family {
				return anchorRecordHandle{}, anchorRecordHandle{}, nil, fmt.Errorf("desync: anchor record family %q", parsed.family)
			}
			if !epochMatches {
				return anchorRecordHandle{}, anchorRecordHandle{}, nil, errors.New("desync: anchor epoch mismatch")
			}
			if anchorRule != nil {
				return anchorRecordHandle{}, anchorRecordHandle{}, nil, errors.New("desync: duplicate anchor marker rule")
			}
			copy := handle
			anchorRule = &copy
		case anchorKindTag:
			if !epochMatches {
				return anchorRecordHandle{}, anchorRecordHandle{}, nil, errors.New("desync: tag epoch mismatch")
			}
			if tagRule != nil {
				return anchorRecordHandle{}, anchorRecordHandle{}, nil, errors.New("desync: duplicate tag high-water rule")
			}
			copy := handle
			tagRule = &copy
		case anchorKindManifest:
			if !epochMatches {
				return anchorRecordHandle{}, anchorRecordHandle{}, nil, errors.New("desync: manifest epoch mismatch")
			}
			key := captureKey(parsed.process, parsed.capture)
			if _, found := manifests[key]; found {
				return anchorRecordHandle{}, anchorRecordHandle{}, nil, fmt.Errorf("desync: duplicate manifest for capture %s", parsed.capture)
			}
			if parsed.ports.out == parsed.ports.in ||
				(parsed.ports.icmpSet && (parsed.ports.icmp == parsed.ports.out || parsed.ports.icmp == parsed.ports.in)) {
				return anchorRecordHandle{}, anchorRecordHandle{}, nil, fmt.Errorf("desync: manifest for capture %s reuses a queue identity", parsed.capture)
			}
			manifests[key] = &anchorManifestRecord{record: parsed, handle: record.handle}
		case anchorKindPort:
			if !epochMatches {
				return anchorRecordHandle{}, anchorRecordHandle{}, nil, errors.New("desync: port-record epoch mismatch")
			}
			key := captureKey(parsed.process, parsed.capture)
			if _, found := ports[key]; found {
				return anchorRecordHandle{}, anchorRecordHandle{}, nil, fmt.Errorf("desync: duplicate port record for capture %s", parsed.capture)
			}
			ports[key] = &anchorPortRecord{record: parsed, handle: record.handle}
		case anchorKindBase:
			return anchorRecordHandle{}, anchorRecordHandle{}, nil, errors.New("desync: base-chain record must be chain userdata, not a marker rule")
		case anchorKindCapture:
			return anchorRecordHandle{}, anchorRecordHandle{}, nil, errors.New("desync: capture record found in the marker chain")
		default:
			return anchorRecordHandle{}, anchorRecordHandle{}, nil, fmt.Errorf("desync: unknown marker record %q", string(record.userdata))
		}
	}
	if anchorRule == nil || tagRule == nil {
		return anchorRecordHandle{}, anchorRecordHandle{}, nil, errors.New("desync: anchor table has no matching a/t record pair")
	}
	for key, manifest := range manifests {
		port, found := ports[key]
		if !found {
			// m without p is the metadata-only preparation state; it is a
			// recoverable record, never a collision.
			continue
		}
		if port.record.tag < uint64(anchorTagInitial) {
			return anchorRecordHandle{}, anchorRecordHandle{}, nil, fmt.Errorf("desync: port record of capture %s has a tag from a foreign epoch", manifest.record.capture)
		}
		if port.record.tag >= tagRule.record.tag {
			return anchorRecordHandle{}, anchorRecordHandle{}, nil, fmt.Errorf("desync: port record tag of capture %s is not below the high-water mark", manifest.record.capture)
		}
		manifest.port = port
	}
	for key := range ports {
		if _, found := manifests[key]; !found {
			return anchorRecordHandle{}, anchorRecordHandle{}, nil, errors.New("desync: port record without a manifest")
		}
	}
	return *anchorRule, *tagRule, manifests, nil
}

// readAnchorFamilyState reads and validates one family of the fixed anchors,
// every marker record and every capture-owned chain/rule. The read is
// generation-consistent: the nftables generation is sampled before and after
// the dumps and a changed generation repeats the whole read.
func readAnchorFamilyState(session anchorSession, family Family) (anchorFamilyState, error) {
	_, familyByte, err := anchorFamilyNames(family)
	if err != nil {
		return anchorFamilyState{}, err
	}
	for attempt := 0; attempt < 3; attempt++ {
		before, err := session.generation(familyByte)
		if err != nil {
			return anchorFamilyState{}, err
		}
		state, err := readAnchorFamilyStateOnce(session, family)
		if err != nil {
			return anchorFamilyState{}, err
		}
		after, err := session.generation(familyByte)
		if err != nil {
			return anchorFamilyState{}, err
		}
		if before == after {
			return state, nil
		}
	}
	return anchorFamilyState{}, errors.New("desync: nftables generation changed during anchor readback")
}

func readAnchorFamilyStateOnce(session anchorSession, family Family) (anchorFamilyState, error) {
	familyName, familyByte, err := anchorFamilyNames(family)
	if err != nil {
		return anchorFamilyState{}, err
	}
	tables, err := readAnchorTables(session, familyByte)
	if err != nil {
		return anchorFamilyState{}, err
	}
	found := false
	for _, table := range tables {
		if table.name != anchorTableName {
			continue
		}
		if err = validateAnchorTable(table); err != nil {
			return anchorFamilyState{}, err
		}
		found = true
	}
	if !found {
		return anchorFamilyState{}, fmt.Errorf("desync: anchor table %s is absent", anchorTableName)
	}
	chains, err := readAnchorChains(session, familyByte, anchorTableName)
	if err != nil {
		return anchorFamilyState{}, err
	}
	byName := make(map[string]nftChainRecord, len(chains))
	for _, chain := range chains {
		if _, duplicate := byName[chain.name]; duplicate {
			return anchorFamilyState{}, fmt.Errorf("desync: duplicate anchor chain %q", chain.name)
		}
		byName[chain.name] = chain
	}
	marker, ok := byName[anchorMarkerChainName]
	if !ok {
		return anchorFamilyState{}, errors.New("desync: anchor marker chain is absent")
	}
	if err := validateAnchorRegularChain(marker, "anchor marker chain"); err != nil {
		return anchorFamilyState{}, err
	}
	rules, err := readAnchorRules(session, familyByte, anchorTableName, anchorMarkerChainName)
	if err != nil {
		return anchorFamilyState{}, err
	}
	anchorRule, tagRule, manifests, err := parseMarkerRules(rules, familyName, "")
	if err == nil {
		// The epoch comes from the a record itself; re-validate every record
		// against it, so a mismatch cannot slip through the empty-epoch pass.
		epoch := anchorRule.record.epoch
		anchorRule, tagRule, manifests, err = parseMarkerRules(rules, familyName, epoch)
		if err == nil {
			state := anchorFamilyState{
				family:       familyName,
				tableFamily:  familyByte,
				epoch:        epoch,
				nextTag:      tagRule.record.tag,
				anchorHandle: anchorRule.handle,
				tagHandle:    tagRule.handle,
				captures:     manifests,
				chains:       make(map[string]map[string]uint64),
				baseRules:    make(map[string][]anchorTaggedRule),
			}
			// Validate the fixed base chains and every rule they contain.
			outputHook, inputHook := uint32(unix.NF_INET_LOCAL_OUT), uint32(unix.NF_INET_LOCAL_IN)
			output, hasOutput := byName[anchorBaseOutputName]
			if !hasOutput {
				return anchorFamilyState{}, errors.New("desync: fixed output base chain is missing")
			}
			if chainErr := validateAnchorBaseChain(output, familyName, familyByte, anchorBaseOutputName, outputHook, epoch); chainErr != nil {
				return anchorFamilyState{}, fmt.Errorf("desync: fixed output base chain is mismatched: %w", chainErr)
			}
			input, hasInput := byName[anchorBaseInputName]
			if !hasInput {
				return anchorFamilyState{}, errors.New("desync: fixed input base chain is missing")
			}
			if chainErr := validateAnchorBaseChain(input, familyName, familyByte, anchorBaseInputName, inputHook, epoch); chainErr != nil {
				return anchorFamilyState{}, fmt.Errorf("desync: fixed input base chain is mismatched: %w", chainErr)
			}
			for _, base := range []string{anchorBaseOutputName, anchorBaseInputName} {
				baseRules, ruleErr := readAnchorRules(session, familyByte, anchorTableName, base)
				if ruleErr != nil {
					return anchorFamilyState{}, ruleErr
				}
				for _, rule := range baseRules {
					if len(rule.userdata) == 0 {
						return anchorFamilyState{}, fmt.Errorf("desync: untagged rule %d in base chain %s", rule.handle, base)
					}
					parsed, parseErr := parseAnchorUserdata(string(rule.userdata))
					if parseErr != nil {
						return anchorFamilyState{}, parseErr
					}
					if parsed.kind != anchorKindCapture || parsed.epoch != epoch {
						return anchorFamilyState{}, fmt.Errorf("desync: foreign record in base chain %s", base)
					}
					key := captureKey(parsed.process, parsed.capture)
					if _, found := manifests[key]; !found {
						return anchorFamilyState{}, fmt.Errorf("desync: base-chain rule of unknown capture %s", parsed.capture)
					}
					if parsed.role != "inject" && parsed.role != "entry-o" && parsed.role != "entry-i" && parsed.role != "entry-e" {
						return anchorFamilyState{}, fmt.Errorf("desync: role %q in base chain %s", parsed.role, base)
					}
					if (parsed.role == "inject" || parsed.role == "entry-o") && base != anchorBaseOutputName {
						return anchorFamilyState{}, fmt.Errorf("desync: role %q is not valid in base chain %s", parsed.role, base)
					}
					if (parsed.role == "entry-i" || parsed.role == "entry-e") && base != anchorBaseInputName {
						return anchorFamilyState{}, fmt.Errorf("desync: role %q is not valid in base chain %s", parsed.role, base)
					}
					state.baseRules[key] = append(state.baseRules[key], anchorTaggedRule{
						chain: base, handle: rule.handle, role: parsed.role, record: parsed,
					})
				}
			}
			// Every non-fixed chain must be a capture chain of a recorded
			// capture; an orphan chain is an unproven effect, not ours to reuse.
			for name, chain := range byName {
				if name == anchorMarkerChainName || name == anchorBaseInputName || name == anchorBaseOutputName {
					continue
				}
				capture, role, ok := parseAnchorChainName(name)
				if !ok {
					return anchorFamilyState{}, fmt.Errorf("desync: unknown anchor chain %q", name)
				}
				key := ""
				for manifestKey, manifest := range manifests {
					if manifest.record.capture == capture {
						key = manifestKey
						break
					}
				}
				if key == "" {
					return anchorFamilyState{}, fmt.Errorf("desync: capture chain %q has no manifest", name)
				}
				if err := validateAnchorRegularChain(chain, "capture chain"); err != nil {
					return anchorFamilyState{}, err
				}
				if state.chains[key] == nil {
					state.chains[key] = make(map[string]uint64)
				}
				state.chains[key][name] = 0
				if role != "" {
					_ = role
				}
			}
			return state, nil
		}
	}
	return anchorFamilyState{}, err
}

// parseAnchorChainName splits one capture chain name into its capture token and
// direction suffix. Only c_<C>_o, c_<C>_i and c_<C>_e are ours.
func parseAnchorChainName(name string) (string, string, bool) {
	if !strings.HasPrefix(name, anchorChainPrefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(name, anchorChainPrefix)
	if len(rest) < 34 {
		return "", "", false
	}
	capture := rest[:32]
	if err := validateAnchorToken(capture); err != nil {
		return "", "", false
	}
	suffix := rest[32:]
	switch suffix {
	case "_o", "_i", "_e":
		return capture, suffix[1:], true
	default:
		return "", "", false
	}
}

// ---------------------------------------------------------------------------
// First enable (N-A0) and base-chain creation.
// ---------------------------------------------------------------------------

type anchorClock interface {
	now() time.Time
}

// ensureAnchorFamily creates or validates one family of the fixed anchors.
// Table + marker chain + a + t are one atomic EXCL batch before any hook; the
// base chains are then created each in its own EXCL transaction. A committed
// partial anchor is always preserved. The only accepted rollback is the
// kernel's internal abort of the currently uncommitted initial hook creation.
func ensureAnchorFamily(session anchorSession, family Family, needCreate bool) error {
	familyName, familyByte, err := anchorFamilyNames(family)
	if err != nil {
		return err
	}
	tables, err := readAnchorTables(session, familyByte)
	if err != nil {
		return err
	}
	exists := false
	for _, table := range tables {
		if table.name == anchorTableName {
			if err = validateAnchorTable(table); err != nil {
				return err
			}
			exists = true
		}
	}
	if !exists {
		if !needCreate {
			return fmt.Errorf("desync: anchor table %s is absent", anchorTableName)
		}
		epoch, epochErr := newAnchorEpoch()
		if epochErr != nil {
			return epochErr
		}
		anchorRule, ruleErr := nftRuleMessage(familyByte, anchorTableName, anchorMarkerChainName, nil, []byte(anchorMarkerUserdata(familyName, epoch)))
		if ruleErr != nil {
			return ruleErr
		}
		tagRule, ruleErr := nftRuleMessage(familyByte, anchorTableName, anchorMarkerChainName, nil, []byte(anchorTagUserdata(epoch, uint64(anchorTagInitial))))
		if ruleErr != nil {
			return ruleErr
		}
		requests := []nftRequest{
			nftTableMessage(familyByte, anchorTableName, nil),
			nftRegularChainMessage(familyByte, anchorTableName, anchorMarkerChainName),
			anchorRule,
			tagRule,
		}
		if _, err = session.batch(requests); err != nil {
			// A lost acknowledgement is reconciled by complete readback: a
			// committed marker is preserved, a definitely absent one retried.
			if reconcileErr := validateInitialMarker(session, family); reconcileErr == nil {
				// committed; fall through
			} else if !definitelyAbsentTable(session, family) {
				return err
			} else if _, retryErr := session.batch(requests); retryErr != nil {
				if reconcileErr := validateInitialMarker(session, family); reconcileErr != nil {
					return fmt.Errorf("desync: create anchor table: %w", retryErr)
				}
			}
		}
		if err = validateInitialMarker(session, family); err != nil {
			return fmt.Errorf("desync: anchor table creation did not become visible: %w", err)
		}
	}
	state, err := readAnchorFamilyStateAllowNoBase(session, family)
	if err != nil {
		return err
	}
	// Create each missing fixed base chain in its own EXCL transaction.
	type chainSpec struct {
		name     string
		hooknum  int
		userdata string
	}
	specs := []chainSpec{
		{anchorBaseInputName, int(unix.NF_INET_LOCAL_IN), anchorBaseUserdata(state.epoch, anchorBaseInputName)}, {anchorBaseOutputName, int(unix.NF_INET_LOCAL_OUT), anchorBaseUserdata(state.epoch, anchorBaseOutputName)},
	}
	for _, spec := range specs {
		request := nftBaseChainMessage(familyByte, anchorTableName, spec.name, "filter", spec.hooknum, anchorBaseHookPriority, []byte(spec.userdata))
		if _, err = session.batch([]nftRequest{request}); err != nil {
			// Either the chain was committed before a lost ACK or it is
			// absent. Never compensate by deleting a committed chain.
			if readErr := validateBaseChainPresent(session, family, spec.name, spec.userdata); readErr != nil {
				if !definitelyAbsentChain(session, family, spec.name) {
					return err
				}
				if _, retryErr := session.batch([]nftRequest{request}); retryErr != nil {
					if readErr = validateBaseChainPresent(session, family, spec.name, spec.userdata); readErr != nil {
						return fmt.Errorf("desync: create anchor base chain %s: %w", spec.name, retryErr)
					}
				}
			}
		}
	}
	return nil
}

func validateInitialMarker(session anchorSession, family Family) error {
	_, err := readAnchorFamilyStateAllowNoBase(session, family)
	return err
}

// readAnchorFamilyStateAllowNoBase validates the table, marker chain, a/t and
// marker records only (base-chain creation may still be pending).
func readAnchorFamilyStateAllowNoBase(session anchorSession, family Family) (anchorFamilyState, error) {
	familyName, familyByte, err := anchorFamilyNames(family)
	if err != nil {
		return anchorFamilyState{}, err
	}
	tables, err := readAnchorTables(session, familyByte)
	if err != nil {
		return anchorFamilyState{}, err
	}
	present := false
	for _, table := range tables {
		if table.name == anchorTableName {
			if err = validateAnchorTable(table); err != nil {
				return anchorFamilyState{}, err
			}
			present = true
		}
	}
	if !present {
		return anchorFamilyState{}, errors.New("desync: anchor table is absent")
	}
	rules, err := readAnchorRules(session, familyByte, anchorTableName, anchorMarkerChainName)
	if err != nil {
		return anchorFamilyState{}, err
	}
	anchorRule, tagRule, manifests, err := parseMarkerRules(rules, familyName, "")
	if err != nil {
		return anchorFamilyState{}, err
	}
	epoch := anchorRule.record.epoch
	anchorRule, tagRule, manifests, err = parseMarkerRules(rules, familyName, epoch)
	if err != nil {
		return anchorFamilyState{}, err
	}
	return anchorFamilyState{
		family: familyName, tableFamily: familyByte, epoch: epoch,
		nextTag: tagRule.record.tag, anchorHandle: anchorRule.handle, tagHandle: tagRule.handle,
		captures: manifests,
	}, nil
}

func definitelyAbsentTable(session anchorSession, family Family) bool {
	_, familyByte, err := anchorFamilyNames(family)
	if err != nil {
		return false
	}
	tables, err := readAnchorTables(session, familyByte)
	if err != nil {
		return false
	}
	for _, table := range tables {
		if table.name == anchorTableName {
			return false
		}
	}
	return true
}

func validateBaseChainPresent(session anchorSession, family Family, name, userdata string) error {
	familyName, familyByte, err := anchorFamilyNames(family)
	if err != nil {
		return err
	}
	state, err := readAnchorFamilyStateAllowNoBase(session, family)
	if err != nil {
		return err
	}
	chains, err := readAnchorChains(session, familyByte, anchorTableName)
	if err != nil {
		return err
	}
	hook := uint32(unix.NF_INET_LOCAL_IN)
	if name == anchorBaseOutputName {
		hook = uint32(unix.NF_INET_LOCAL_OUT)
	}
	for _, chain := range chains {
		if chain.name == name {
			if chainErr := validateAnchorBaseChain(chain, familyName, familyByte, name, hook, state.epoch); chainErr != nil {
				return chainErr
			}
			if string(chain.userdata) != userdata {
				return errors.New("desync: base chain userdata mismatch")
			}
			return nil
		}
	}
	return errors.New("desync: base chain is absent")
}

func definitelyAbsentChain(session anchorSession, family Family, name string) bool {
	_, familyByte, err := anchorFamilyNames(family)
	if err != nil {
		return false
	}
	chains, err := readAnchorChains(session, familyByte, anchorTableName)
	if err != nil {
		return false
	}
	for _, chain := range chains {
		if chain.name == name {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Queue/port transport.
// ---------------------------------------------------------------------------

// nfqueueSocketAdapter implements the legacy netlink.Socket surface over the
// directly created, explicitly bound owned fd. It is local to this capture and
// is the only path that wraps a queue socket (never netlink.Dial, whose EINVAL
// fallback would take ForkLock.RLock again).
type nfqueueSocketAdapter struct {
	conn *socket.Conn
}

// The pinned netlink library reaches deadline control and the raw descriptor
// only through its optional deadlineSetter and syscallConner interfaces
// (mdlayher/netlink@v1.11.2/conn.go:422-447 and 561-587). Without them every
// receive-interruption deadline and every RawConn-based readiness check reports
// "operation not supported", which is exactly the stop/drain failure the native
// Linux lifecycle observed. The adapter therefore delegates all four methods to
// the one owning socket.Conn it already wraps: no second owner, descriptor
// export, duplication or lifetime is introduced.
var (
	_ netlink.Socket = (*nfqueueSocketAdapter)(nil)
	_ interface {
		SetDeadline(deadline time.Time) error
		SetReadDeadline(deadline time.Time) error
		SetWriteDeadline(deadline time.Time) error
	} = (*nfqueueSocketAdapter)(nil)
	_ syscall.Conn = (*nfqueueSocketAdapter)(nil)
)

func (a *nfqueueSocketAdapter) SetDeadline(deadline time.Time) error {
	if a.conn == nil {
		// A zero adapter owns no descriptor (capability/model construction):
		// there is no read or write to interrupt, so there is nothing to arm.
		return nil
	}
	return a.conn.SetDeadline(deadline)
}

func (a *nfqueueSocketAdapter) SetReadDeadline(deadline time.Time) error {
	if a.conn == nil {
		return nil
	}
	return a.conn.SetReadDeadline(deadline)
}

func (a *nfqueueSocketAdapter) SetWriteDeadline(deadline time.Time) error {
	if a.conn == nil {
		return nil
	}
	return a.conn.SetWriteDeadline(deadline)
}

// SyscallConn delegates to the owning socket.Conn's runtime-poller RawConn. The
// queue transport's pending() readiness probe and the capture teardown both use
// it; the returned RawConn is the same private descriptor owner, never a
// duplicate or a cached copy.
func (a *nfqueueSocketAdapter) SyscallConn() (syscall.RawConn, error) {
	if a.conn == nil {
		// A zero adapter has no descriptor to expose. Returning a nil RawConn
		// with a nil error would violate syscall.Conn, so the capability exists
		// but every operation reports EBADF, exactly like a closed descriptor.
		return nfqueueNoDescriptorRawConn{}, nil
	}
	return a.conn.SyscallConn()
}

// nfqueueNoDescriptorRawConn is the honest RawConn of an adapter that owns no
// descriptor. Production always delegates to the real socket.Conn above.
type nfqueueNoDescriptorRawConn struct{}

func (nfqueueNoDescriptorRawConn) Control(func(fd uintptr)) error {
	return os.NewSyscallError("rawconn", unix.EBADF)
}

func (nfqueueNoDescriptorRawConn) Read(func(fd uintptr) (done bool)) error {
	return os.NewSyscallError("rawconn", unix.EBADF)
}

func (nfqueueNoDescriptorRawConn) Write(func(fd uintptr) (done bool)) error {
	return os.NewSyscallError("rawconn", unix.EBADF)
}

func (a *nfqueueSocketAdapter) Close() error { return a.conn.Close() }

func (a *nfqueueSocketAdapter) Send(message netlink.Message) error {
	data, err := message.MarshalBinary()
	if err != nil {
		return err
	}
	_, err = a.conn.Sendmsg(contextBackground(), data, nil, nil, 0)
	return err
}

func (a *nfqueueSocketAdapter) SendMessages(messages []netlink.Message) error {
	for _, message := range messages {
		if err := a.Send(message); err != nil {
			return err
		}
	}
	return nil
}

func (a *nfqueueSocketAdapter) Receive() ([]netlink.Message, error) {
	buffer := make([]byte, nftMetadataBuffer)
	length, _, err := a.conn.Recvfrom(contextBackground(), buffer, 0)
	if err != nil {
		return nil, err
	}
	if length == len(buffer) {
		return nil, errors.New("desync: NFQUEUE datagram was truncated")
	}
	return parseNetlinkDatagram(buffer[:length])
}

func (a *nfqueueSocketAdapter) ReceiveIter() iter.Seq2[netlink.Message, error] {
	return func(yield func(netlink.Message, error) bool) {
		messages, err := a.Receive()
		if err != nil {
			yield(netlink.Message{}, err)
			return
		}
		for _, message := range messages {
			if !yield(message, nil) {
				return
			}
		}
	}
}

// contextBackground is a tiny indirection over context.Background for the
// socket adapter.
func contextBackground() context.Context { return context.Background() }

// parseNetlinkDatagram splits one received datagram into netlink messages.
//
// A native nlmsg_len is the exact declared length of one message and is not
// required to be a multiple of four (an actual 127-byte NFQUEUE packet was
// observed). The pinned netlink decoder, however, rejects a byte slice whose
// length is not aligned before it even reads the header. The declared length
// and payload are therefore preserved, while the decoder receives a bounded
// owned copy padded only up to the alignment boundary. A final message that
// ends the datagram without kernel padding is complete and accepted; truncated
// messages, mismatched padding, trailing junk, an empty datagram and an
// overflowing declared length are rejected.
func parseNetlinkDatagram(data []byte) ([]netlink.Message, error) {
	if len(data) == 0 {
		return nil, errors.New("desync: empty netlink datagram")
	}
	messages := make([]netlink.Message, 0, 4)
	for offset := 0; offset < len(data); {
		remaining := len(data) - offset
		if remaining < 16 {
			return nil, errors.New("desync: malformed netlink datagram: trailing bytes")
		}
		length := int(binary.NativeEndian.Uint32(data[offset:]))
		if length < 16 || length > remaining {
			return nil, errors.New("desync: malformed netlink datagram")
		}
		aligned := (length + 3) &^ 3
		if remaining < aligned && remaining != length {
			// The complete declared message is followed by a partial
			// alignment padding: neither a complete final message nor a
			// complete padded one.
			return nil, errors.New("desync: malformed netlink datagram: incomplete padding")
		}
		storage := make([]byte, aligned)
		copy(storage, data[offset:offset+length])
		var message netlink.Message
		if err := message.UnmarshalBinary(storage); err != nil {
			return nil, err
		}
		messages = append(messages, message)
		if remaining <= aligned {
			offset = len(data)
		} else {
			offset += aligned
		}
	}
	return messages, nil
}

// nfqueueConn is the NFQUEUE netlink transport of one capture. Production uses
// the pinned netlink.Conn over the directly created socket; tests substitute a
// deterministic in-memory implementation.
type nfqueueConn interface {
	Receive() ([]netlink.Message, error)
	Execute(netlink.Message) ([]netlink.Message, error)
	Send(netlink.Message) (netlink.Message, error)
	SetReadDeadline(time.Time) error
	pending() (bool, error)
	Close() error
}

// nfqueueTransport adds the explicit bound port to the capture transport.
type nfqueueTransport interface {
	nfqueueConn
	boundPort() uint32
}

// netlinkQueueConn is the production NFQUEUE transport over one nft queue
// socket.
type netlinkQueueConn struct {
	*netlink.Conn
	port uint32
}

func (c netlinkQueueConn) boundPort() uint32 { return c.port }

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

// openQueueTransport creates the capture's private queue-class socket under the
// already-held fork-read token: a direct SOCK_RAW|CLOEXEC|NONBLOCK netlink fd,
// the explicitly reserved high-bit port, a verified Getsockname, and the
// existing pinned socket.New wrapper over the same fd. No netlink.Dial and no
// fallback exist on this path.
var openQueueTransport = func(port uint32) (nfqueueTransport, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("desync: open NFQUEUE netlink socket: %w", err)
	}
	bindErr := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: port})
	if bindErr != nil {
		_ = unix.Close(fd)
		if errors.Is(bindErr, unix.EADDRINUSE) {
			return nil, bindErr
		}
		return nil, fmt.Errorf("desync: bind NFQUEUE netlink port %#x: %w", port, bindErr)
	}
	name, nameErr := unix.Getsockname(fd)
	if nameErr != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("desync: read NFQUEUE netlink port: %w", nameErr)
	}
	bound, ok := name.(*unix.SockaddrNetlink)
	if !ok || bound.Pid != port {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("desync: NFQUEUE netlink port %#x was not bound", port)
	}
	conn, connErr := socket.New(fd, "desync-nfqueue")
	if connErr != nil {
		// socket.New does not duplicate the fd; on error the opener still
		// closes it.
		_ = unix.Close(fd)
		return nil, fmt.Errorf("desync: wrap NFQUEUE netlink socket: %w", connErr)
	}
	return netlinkQueueConn{Conn: netlink.NewConn(&nfqueueSocketAdapter{conn: conn}, port), port: port}, nil
}

// nextQueueClassPort derives one explicit high-bit port candidate.
func nextQueueClassPort(excluded map[uint32]bool, attempt int) (uint32, error) {
	buffer := make([]byte, 4)
	if _, err := cryptoRead(buffer); err != nil {
		return 0, err
	}
	candidate := (binary.BigEndian.Uint32(buffer) + uint32(attempt)*2654435761) & 0x7fffffff
	if candidate == 0 {
		candidate = 1
	}
	candidate |= nftQueuePortBit
	if excluded[candidate] {
		return 0, nil
	}
	return candidate, nil
}

// cryptoRead is the entropy source of explicit port selection.
func cryptoRead(buffer []byte) (int, error) { return rand.Read(buffer) }

// ---------------------------------------------------------------------------
// Capture.
// ---------------------------------------------------------------------------

type linuxBackend struct{}

func NewNativeBackend() Backend { return linuxBackend{} }

func (linuxBackend) Name() string { return "linux-nfqueue" }

type linuxCapture struct {
	lease *Lease
	owner *anchorOwner
	// anchor is the immutable record of this capture's fixed identity.
	anchor captureAnchor
	queue  uint16
	// inQueue is the owned inbound observation queue.
	inQueue uint16
	// icmpQueue is the owned ICMP-error queue (only when configured).
	icmpQueue    uint16
	overrideQnum int
	// outPort is the explicit high-bit netlink port bound to nl.
	outPort uint32
	// outWitnessed reports that p(w) was durably published for outPort.
	outWitnessed bool

	dispatch *captureDispatchGate
	nl       nfqueueTransport

	bound     bool
	unbounded bool
	started   bool
	stopping  atomic.Bool

	sendMu sync.Mutex

	rawMu sync.Mutex

	done      chan struct{}
	closeOnce sync.Once
	closeErr  error

	// manifestHandle and portHandle are the exact current marker-rule handles
	// of this capture's m and p records. They are refreshed from readback
	// before each exact delete, never trusted across a possible change.
	manifestHandle uint64
	portHandle     uint64

	// refHeld reports that this capture still owns one reference of its
	// anchorOwner. It is released exactly once.
	refHeld bool

	// retired is the positive native-retirement receipt of this capture.
	retired atomic.Bool
}

// captureAnchor is the exact identity of one capture in one family.
type captureAnchor struct {
	family  string
	epoch   string
	process string
	capture string
	tag     uint32
	// chainHandles and ruleHandles are refreshed from complete readback before
	// every delete; a remembered handle is never used after the object/tag may
	// have changed.
	chainHandles map[string]uint64
	ruleHandles  map[string]uint64
}

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

// openLinuxCapture is the production entry point: it establishes the fixed
// anchors, recovers provably abandoned captures, publishes this capture's
// metadata/port witness, attaches its rules and only then exposes the capture.
func openLinuxCapture(lease *Lease) (capture Capture, err error) {
	endpoint := lease.Endpoint()
	if !endpoint.Source.IsValid() || endpoint.Source.Port() == 0 {
		return nil, fmt.Errorf("desync: capture requires an owned local endpoint")
	}
	owner, err := anchorOwnerAcquire()
	if err != nil {
		return nil, err
	}
	if owner.retainedState() {
		// The owner has a retained unproven retirement. This fresh reference
		// is dropped again; the retained capture's own reference keeps the
		// owner guard bound and the residue's liveness identity visible.
		owner.releaseRef()
		return nil, errors.New("desync: anchor owner has a retained unproven retirement")
	}
	captureValue := &linuxCapture{
		lease:    lease,
		owner:    owner,
		refHeld:  true,
		done:     make(chan struct{}),
		dispatch: newCaptureDispatchGate(),
	}
	if err = captureValue.open(endpoint); err != nil {
		captureValue.rollbackOpen()
		if !owner.retainedState() {
			captureValue.releaseOwnerRef()
		}
		return nil, err
	}
	return captureValue, nil
}

// open performs the whole publication protocol of §2.
func (c *linuxCapture) open(endpoint Endpoint) error {
	familyName, _, err := anchorFamilyNames(endpoint.Family)
	if err != nil {
		return err
	}
	c.anchor.family = familyName
	var (
		queue, inQueue, icmpQueue uint16
		hasICMP                   bool
	)
	err = withAnchorTransaction(c.owner, func(session anchorSession) error {
		if err := ensureAnchorFamily(session, FamilyIPv4, true); err != nil {
			return err
		}
		if err := ensureAnchorFamily(session, FamilyIPv6, true); err != nil {
			return err
		}
		state4, err := readAnchorFamilyState(session, FamilyIPv4)
		if err != nil {
			return err
		}
		state6, err := readAnchorFamilyState(session, FamilyIPv6)
		if err != nil {
			return err
		}
		if err = c.recoverAbandoned(session, state4, state6); err != nil {
			return err
		}
		state4, err = readAnchorFamilyState(session, FamilyIPv4)
		if err != nil {
			return err
		}
		state6, err = readAnchorFamilyState(session, FamilyIPv6)
		if err != nil {
			return err
		}
		state := state4
		if endpoint.Family == FamilyIPv6 {
			state = state6
		}
		if state.nextTag > uint64(^uint32(0)) {
			return errors.New("desync: injection tag space is exhausted")
		}
		tag := uint32(state.nextTag)
		nextTag := state.nextTag + 1
		c.anchor.epoch = state.epoch
		c.anchor.tag = tag
		captureToken, tokenErr := newAnchorNonce()
		if tokenErr != nil {
			return tokenErr
		}
		c.anchor.process = c.owner.token
		c.anchor.capture = captureToken

		excludedQnums := make(map[int]bool)
		for _, familyState := range []anchorFamilyState{state4, state6} {
			for _, manifest := range familyState.captures {
				excludedQnums[int(manifest.record.ports.out)] = true
				excludedQnums[int(manifest.record.ports.in)] = true
				if manifest.record.ports.icmpSet {
					excludedQnums[int(manifest.record.ports.icmp)] = true
				}
			}
		}
		queue, inQueue, err = c.allocateQueues(endpoint, state, excludedQnums)
		if err != nil {
			return err
		}
		c.queue, c.inQueue = queue, inQueue
		if c.wantsICMPFilter() {
			icmpQueue, err = c.allocateICMPQueue(endpoint, state, excludedQnums)
			if err != nil {
				return err
			}
			c.icmpQueue, hasICMP = icmpQueue, true
		}
		ports := anchorQueuePorts{
			out: queue, in: inQueue, icmp: icmpQueue, icmpSet: hasICMP,
		}
		if obs, obsErr := readProcessIdentity(); obsErr == nil {
			ports.pidnsDev, ports.pidnsIno = obs.pidns.dev, obs.pidns.ino
			ports.tgid, ports.startTicks = obs.tgid, obs.startTicks
		} else {
			return fmt.Errorf("desync: read process incarnation identity: %w", obsErr)
		}
		manifestRule, err := nftRuleMessage(state.tableFamily, anchorTableName, anchorMarkerChainName, nil,
			[]byte(anchorManifestUserdata(state.epoch, c.owner.token, captureToken, ports)))
		if err != nil {
			return err
		}
		// Reserve the queue port before p(o): the record must exist before the
		// socket fd can exist, so a crash is recoverable.
		excludedPorts := make(map[uint32]bool)
		for _, familyState := range []anchorFamilyState{state4, state6} {
			for _, manifest := range familyState.captures {
				if manifest.port != nil {
					excludedPorts[manifest.port.record.port] = true
				}
			}
		}
		port := uint32(0)
		var transport nfqueueTransport
		committed := false
		for attempt := 0; attempt < nftMetadataCandidates; attempt++ {
			candidate, candErr := nextQueueClassPort(excludedPorts, attempt)
			if candErr != nil {
				return candErr
			}
			if candidate == 0 || excludedPorts[candidate] {
				continue
			}
			c.outPort = candidate
			portRule, ruleErr := anchorPortUserdataRecord(state.tableFamily, state.epoch, c.owner.token, captureToken, candidate, "o", tag)
			if ruleErr != nil {
				return ruleErr
			}
			var requests []nftRequest
			if !committed {
				// The original marker-only transaction: m + p(o) + monotone t.
				tagRule, tagErr := nftRuleMessage(state.tableFamily, anchorTableName, anchorMarkerChainName, nil,
					[]byte(anchorTagUserdata(state.epoch, nextTag)))
				if tagErr != nil {
					return tagErr
				}
				requests = []nftRequest{
					nftDeleteRuleMessage(state.tableFamily, anchorTableName, anchorMarkerChainName, state.tagHandle),
					tagRule, manifestRule, portRule,
				}
			} else {
				// The socket could not bind the reserved port: update only the
				// exact p(o) record to the next reserved candidate. t and m
				// stay exactly as committed.
				requests = []nftRequest{
					nftDeleteRuleMessage(state.tableFamily, anchorTableName, anchorMarkerChainName, c.portHandle),
					portRule,
				}
			}
			if _, batchErr := session.batch(requests); batchErr != nil {
				// A lost ACK is reconciled by complete readback; an absent or
				// conflicting effect fails the open without a second table or
				// an invented receipt.
				if readErr := c.readbackCapturePhase(session, state, "o"); readErr != nil {
					return fmt.Errorf("desync: commit capture metadata: %w", batchErr)
				}
			}
			if readErr := c.readbackCapturePhase(session, state, "o"); readErr != nil {
				return readErr
			}
			committed = true
			opened, openErr := openQueueTransport(candidate)
			if openErr != nil {
				if errors.Is(openErr, unix.EADDRINUSE) {
					excludedPorts[candidate] = true
					continue
				}
				return openErr
			}
			transport = opened
			port = candidate
			break
		}
		if transport == nil {
			return errors.New("desync: no free queue-class netlink port")
		}
		c.nl = transport
		c.outPort = port
		// While the same fork-read token is held, make the private queue
		// socket the exclusive owner of outq and publish the durable witness.
		if err = c.bindQueue(queue, endpoint.Family); err != nil {
			_ = transport.Close()
			c.nl = nil
			return err
		}
		c.bound = true
		witnessRule, err := anchorPortUserdataRecord(state.tableFamily, state.epoch, c.owner.token, captureToken, port, "w", tag)
		if err != nil {
			return err
		}
		if _, err = session.batch([]nftRequest{
			nftDeleteRuleMessage(state.tableFamily, anchorTableName, anchorMarkerChainName, c.portHandle),
			witnessRule,
		}); err != nil {
			if readErr := c.readbackCapturePhase(session, state, "w"); readErr != nil {
				// §2: a lost w ACK does not permit dropping the lock while a
				// socket remains open. Close it before releasing the token and
				// retain the o record for recovery.
				_ = closeTransport(c.nl)
				c.nl = nil
				return fmt.Errorf("desync: publish port witness: %w", err)
			}
		}
		if err = c.readbackCapturePhase(session, state, "w"); err != nil {
			_ = closeTransport(c.nl)
			c.nl = nil
			return err
		}
		c.outWitnessed = true
		return nil
	})
	if err != nil {
		return err
	}
	// The transaction fd and its fork token are now closed. Go fork/exec may
	// transiently inherit the queue fd, but the durable witness makes that
	// visible to retirement rather than false.
	if err = c.bindRemainingQueues(endpoint); err != nil {
		return err
	}
	if err = c.attachCaptureRules(endpoint); err != nil {
		return err
	}
	if err = c.verifyCaptureRules(); err != nil {
		return err
	}
	c.started = true
	go c.loop()
	return nil
}

// anchorPortUserdataRecord builds one p record request.
func anchorPortUserdataRecord(tableFamily byte, epoch, process, capture string, port uint32, phase string, tag uint32) (nftRequest, error) {
	userdata, err := anchorPortUserdata(epoch, process, capture, port, phase, tag)
	if err != nil {
		return nftRequest{}, err
	}
	return nftRuleMessage(tableFamily, anchorTableName, anchorMarkerChainName, nil, []byte(userdata))
}

type processIdentity struct {
	pidns      anchorPidNamespace
	tgid       uint64
	startTicks uint64
}

// readProcessIdentity records the process incarnation whose whole-thread-group
// exit is later observed by recovery.
var readProcessIdentity = func() (processIdentity, error) {
	pidns, err := currentPidNamespace()
	if err != nil {
		return processIdentity{}, err
	}
	tgid := os.Getpid()
	ticks, err := processStartTicks(tgid)
	if err != nil {
		return processIdentity{}, err
	}
	return processIdentity{pidns: pidns, tgid: uint64(tgid), startTicks: ticks}, nil
}

func closeTransport(transport nfqueueConn) error {
	if transport == nil {
		return nil
	}
	return transport.Close()
}

// readbackCapturePhase verifies that exactly this capture's m and p records
// exist with the expected queue identity, port and phase. It is the
// reconciliation primitive after a lost metadata ACK, and it refreshes the
// exact current marker-rule handles.
func (c *linuxCapture) readbackCapturePhase(session anchorSession, before anchorFamilyState, phase string) error {
	after, err := readAnchorFamilyStateFor(session, before)
	if err != nil {
		return err
	}
	manifest, found := after.captures[captureKey(c.owner.token, c.anchor.capture)]
	if !found {
		return errors.New("desync: capture manifest did not become visible")
	}
	if manifest.record.ports.out != c.queue || manifest.record.ports.in != c.inQueue {
		return errors.New("desync: capture manifest queue identity mismatch")
	}
	if manifest.port == nil {
		return errors.New("desync: capture port record is absent")
	}
	if manifest.port.record.port != c.outPort {
		return errors.New("desync: capture port record names a foreign port")
	}
	if manifest.port.record.phase != phase {
		return fmt.Errorf("desync: capture port record phase is %q, want %q", manifest.port.record.phase, phase)
	}
	c.portHandle = manifest.port.handle
	c.manifestHandle = manifest.handle
	return nil
}

func readAnchorFamilyStateFor(session anchorSession, before anchorFamilyState) (anchorFamilyState, error) {
	family := FamilyIPv4
	if before.family == "ip6" {
		family = FamilyIPv6
	}
	return readAnchorFamilyState(session, family)
}

// ---------------------------------------------------------------------------
// Recovery.
// ---------------------------------------------------------------------------

// recoverAbandoned validates and retires every provably abandoned capture of
// this namespace before a new generation is admitted. A live matching owner is
// left untouched; an unknown, orphan-guard or inconsistent owner retains its
// record and returns an explicit error.
func (c *linuxCapture) recoverAbandoned(session anchorSession, states ...anchorFamilyState) error {
	for _, state := range states {
		for key, manifest := range state.captures {
			record := manifest.record
			if record.process == c.owner.token {
				// Records of this owner belong to live captures of this
				// process; they are never recovered while the owner is alive.
				continue
			}
			observation, err := observeOwnerProcess(record)
			if err != nil {
				return fmt.Errorf("desync: observe owner of capture %s: %w", record.capture, err)
			}
			busy, err := probeAnchorGuardAddress(anchorGuardAddress(record.process))
			if err != nil {
				return fmt.Errorf("desync: probe owner guard of capture %s: %w", record.capture, err)
			}
			switch {
			case observation.verdict == anchorOwnerUnknown:
				return fmt.Errorf("desync: capture %s has unknown owner visibility: %s", record.capture, observation.reason)
			case observation.verdict == anchorOwnerLive && !busy:
				return fmt.Errorf("desync: live capture %s has no owner guard (inconsistent/retiring owner)", record.capture)
			case observation.verdict == anchorOwnerLive:
				// A healthy independent live owner is left untouched.
				continue
			case observation.verdict == anchorOwnerDead && busy:
				return fmt.Errorf("desync: capture %s has an orphan owner guard (no new generation)", record.capture)
			}
			// Proven whole-group death with a free guard: claim the address for
			// the whole bounded recovery attempt, then retire exactly this
			// record or retain it with its concrete effects.
			guard, err := bindAnchorGuardSocket(anchorGuardAddress(record.process))
			if err != nil {
				return fmt.Errorf("desync: claim abandoned owner guard of capture %s: %w", record.capture, err)
			}
			retireErr := c.retireAbandoned(session, state, key, manifest)
			_ = guard.close()
			if retireErr != nil {
				return fmt.Errorf("desync: recover capture %s: %w", record.capture, retireErr)
			}
		}
	}
	return nil
}

// retireAbandoned removes exactly the recorded capture's reachability and
// metadata after its whole thread group was proven dead and its guard claimed.
func (c *linuxCapture) retireAbandoned(session anchorSession, state anchorFamilyState, key string, manifest *anchorManifestRecord) error {
	record := manifest.record
	// Detach only that capture's exact tagged queue-producing/injection rules.
	if err := detachCaptureRules(session, state, key); err != nil {
		return err
	}
	if _, err := runEnqueueFence(); err != nil {
		return fmt.Errorf("desync: fence abandoned capture: %w", err)
	}
	if manifest.port != nil {
		switch manifest.port.record.phase {
		case "w":
			if _, err := observeReleaseScan(session, manifest.port.record.port, record.ports.out); err != nil {
				return err
			}
		case "o":
			// No fork-created fd escaped for p(o); whole-group exit completes
			// the file release. Foreign current bindings are reported, never
			// touched.
			if err := inspectForeignQueues(manifest.record); err != nil {
				return err
			}
		default:
			return errors.New("desync: unexpected port-record phase")
		}
	}
	if err := deleteCaptureChains(session, state, key, record.capture); err != nil {
		return err
	}
	current, err := readAnchorFamilyStateFor(session, state)
	if err != nil {
		return err
	}
	currentManifest, found := current.captures[key]
	if !found {
		return nil
	}
	requests := []nftRequest{nftDeleteRuleMessage(state.tableFamily, anchorTableName, anchorMarkerChainName, currentManifest.handle)}
	if currentManifest.port != nil {
		requests = append(requests, nftDeleteRuleMessage(state.tableFamily, anchorTableName, anchorMarkerChainName, currentManifest.port.handle))
	}
	if _, err = session.batch(requests); err != nil {
		if err = c.readbackMetadataAbsent(session, state, record.process, record.capture); err != nil {
			return fmt.Errorf("desync: retire abandoned metadata: %w", err)
		}
	}
	return c.readbackMetadataAbsent(session, state, record.process, record.capture)
}

func (c *linuxCapture) readbackMetadataAbsent(session anchorSession, state anchorFamilyState, process, capture string) error {
	after, err := readAnchorFamilyStateFor(session, state)
	if err != nil {
		return err
	}
	if _, found := after.captures[captureKey(process, capture)]; found {
		return errors.New("desync: capture metadata is still present")
	}
	return nil
}

// deleteCaptureChains removes every rule inside the capture-owned regular
// chains and then the chains themselves. The readback of the chain set must
// prove absence; a remembered handle is never used.
func deleteCaptureChains(session anchorSession, state anchorFamilyState, key string, capture string) error {
	after, err := readAnchorFamilyStateFor(session, state)
	if err != nil {
		return err
	}
	chains := after.chains[key]
	if len(chains) == 0 {
		return nil
	}
	names := make([]string, 0, len(chains))
	for name := range chains {
		names = append(names, name)
	}
	sortStrings(names)
	requests := make([]nftRequest, 0, len(names))
	for _, name := range names {
		rules, ruleErr := readAnchorRules(session, state.tableFamily, anchorTableName, name)
		if ruleErr != nil {
			return ruleErr
		}
		for _, rule := range rules {
			requests = append(requests, nftDeleteRuleMessage(state.tableFamily, anchorTableName, name, rule.handle))
		}
	}
	if len(requests) > 0 {
		if _, err = session.batch(requests); err != nil {
			for _, name := range names {
				rules, readErr := readAnchorRules(session, state.tableFamily, anchorTableName, name)
				if readErr != nil {
					return err
				}
				if len(rules) != 0 {
					return fmt.Errorf("desync: capture chain %q still holds %d rules: %w", name, len(rules), err)
				}
			}
		}
	}
	deleteRequests := make([]nftRequest, 0, len(names))
	for _, name := range names {
		deleteRequests = append(deleteRequests, nftDeleteChainMessage(state.tableFamily, anchorTableName, name))
	}
	if _, err = session.batch(deleteRequests); err != nil {
		chainsAfter, readErr := readAnchorChains(session, state.tableFamily, anchorTableName)
		if readErr != nil {
			return err
		}
		for _, chain := range chainsAfter {
			if parseCaptureChain(chain.name) == capture {
				return fmt.Errorf("desync: capture chain %q was not removed: %w", chain.name, err)
			}
		}
	}
	return nil
}

// detachCaptureRules deletes every rule of one capture from the base chains.
func detachCaptureRules(session anchorSession, state anchorFamilyState, key string) error {
	after, err := readAnchorFamilyStateFor(session, state)
	if err != nil {
		return err
	}
	rules := after.baseRules[key]
	if len(rules) == 0 {
		return nil
	}
	requests := make([]nftRequest, 0, len(rules))
	for _, rule := range rules {
		requests = append(requests, nftDeleteRuleMessage(state.tableFamily, anchorTableName, rule.chain, rule.handle))
	}
	if _, err = session.batch(requests); err != nil {
		// Reconcile by readback: every record of this capture must be absent.
		current, readErr := readAnchorFamilyStateFor(session, state)
		if readErr != nil {
			return err
		}
		if len(current.baseRules[key]) != 0 {
			return fmt.Errorf("desync: detach of capture %s is unproven: %w", key, err)
		}
	}
	current, err := readAnchorFamilyStateFor(session, state)
	if err != nil {
		return err
	}
	if len(current.baseRules[key]) != 0 {
		return fmt.Errorf("desync: capture %s still has base-chain rules", key)
	}
	return nil
}

func parseCaptureChain(name string) string {
	capture, _, ok := parseAnchorChainName(name)
	if !ok {
		return ""
	}
	return capture
}

func sortStrings(values []string) {
	for index := 1; index < len(values); index++ {
		for back := index; back > 0 && values[back] < values[back-1]; back-- {
			values[back], values[back-1] = values[back-1], values[back]
		}
	}
}

// inspectForeignQueues parses the fresh netfilter queue report and reports any
// current binding of the recorded queue numbers. It never acts on a row.
func inspectForeignQueues(record anchorRecord) error {
	rows, err := readQueueReportInNamespace()
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.queue == record.ports.out || row.queue == record.ports.in ||
			(record.ports.icmpSet && row.queue == record.ports.icmp) {
			// A foreign current binding is preserved, never configured or
			// unbound. It is not an error of this implementation.
			continue
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Port witness release scan (N-A2 §4.1).
// ---------------------------------------------------------------------------

// releaseScanReceipt is one positive W-ABSENT or W-REPLACED receipt.
type releaseScanReceipt struct {
	kind     string
	port     uint32
	foreign  uint32
	procRows []queueRow
}

// observeReleaseScan proves that the old port's NFQUEUE destruction scan
// finished. W-ABSENT requires the exact no-attribute CONFIG -ENODEV reply
// followed by a fresh successful proc read; W-REPLACED requires a genuine
// different-port row emitted under the instance lock.
func observeReleaseScan(session anchorSession, port uint32, outq uint16) (releaseScanReceipt, error) {
	queryErr := queryQueueAbsence(session, outq)
	rows, readErr := readQueueReportInNamespace()
	if readErr != nil {
		return releaseScanReceipt{}, fmt.Errorf("desync: fresh NFQUEUE report read: %w", readErr)
	}
	row, found := findQueueRow(rows, outq)
	if queueRowCount(rows, outq) > 1 {
		return releaseScanReceipt{}, errors.New("desync: release scan: duplicate NFQUEUE report rows")
	}
	if found {
		if row.port == port {
			return releaseScanReceipt{}, errors.New("desync: release scan: old queue instance still present")
		}
		if queryErr != nil {
			return releaseScanReceipt{}, fmt.Errorf("desync: release scan: old instance removed but absence query did not qualify: %w", queryErr)
		}
		return releaseScanReceipt{kind: "W-REPLACED", port: port, foreign: row.port, procRows: rows}, nil
	}
	if queryErr != nil {
		return releaseScanReceipt{}, fmt.Errorf("desync: release scan: absence query did not qualify: %w", queryErr)
	}
	return releaseScanReceipt{kind: "W-ABSENT", port: port, procRows: rows}, nil
}

// nfqueueQuerySequence assigns operation-unique request sequences to the raw
// no-attribute CONFIG lookups.
var nfqueueQuerySequence atomic.Uint32

// queryQueueAbsence sends the exact no-attribute NFQNL_MSG_CONFIG lookup on a
// fresh control-class socket and requires the sequenced -ENODEV echo. It never
// uses the old port, a verdict or an UNBIND, and never treats EPERM as absence.
func queryQueueAbsence(session anchorSession, outq uint16) error {
	request, err := nfqueueConfigMessage(outq, nil, true)
	if err != nil {
		return err
	}
	request.Header.Sequence = nfqueueQuerySequence.Add(1)
	if request.Header.Sequence == 0 {
		request.Header.Sequence = 1
	}
	request.Header.Length = uint32(16 + len(request.Data))
	datagram := marshalNetlinkMessage(request)
	if err = sendNetlinkRaw(session, datagram); err != nil {
		return err
	}
	reply, peer, err := recvNetlinkRaw(session)
	if err != nil {
		return err
	}
	if peer == nil || peer.Pid != 0 || peer.Groups != 0 {
		return errors.New("desync: queue absence reply came from a foreign peer")
	}
	return parseQueueAbsenceReply(reply, session.boundPort(), request)
}

// parseQueueAbsenceReply validates one sequenced -ENODEV queue lookup reply:
// exactly one untruncated NLMSG_ERROR, no CAPPED/ACK_TLVS, the matching
// sequence and bound port, ENODEV, and the byte-identical embedded request.
func parseQueueAbsenceReply(datagram []byte, boundPort uint32, request netlink.Message) error {
	if len(datagram) < 20 {
		return errors.New("desync: queue absence reply is truncated")
	}
	length := int(binary.NativeEndian.Uint32(datagram))
	if length < 20 || length > len(datagram) || length != len(datagram) {
		return errors.New("desync: queue absence reply has a malformed or trailing length")
	}
	if binary.NativeEndian.Uint16(datagram[4:]) != unix.NLMSG_ERROR {
		return errors.New("desync: queue absence reply is not an error message")
	}
	flags := binary.NativeEndian.Uint16(datagram[6:])
	if flags&(unix.NLM_F_CAPPED|unix.NLM_F_ACK_TLVS) != 0 {
		return errors.New("desync: queue absence reply carries CAPPED/ACK_TLVS")
	}
	if binary.NativeEndian.Uint32(datagram[8:]) != request.Header.Sequence {
		return errors.New("desync: queue absence reply has a foreign sequence")
	}
	if binary.NativeEndian.Uint32(datagram[12:]) != boundPort {
		return errors.New("desync: queue absence reply has a foreign port")
	}
	code := int32(binary.NativeEndian.Uint32(datagram[16:]))
	if code != -int32(unix.ENODEV) {
		return fmt.Errorf("desync: queue absence reply errno is %v, not ENODEV", unix.Errno(-code))
	}
	expected, err := request.MarshalBinary()
	if err != nil {
		return err
	}
	if len(datagram) != 20+len(expected) || !bytesEqual(datagram[20:], expected) {
		return errors.New("desync: queue absence reply does not echo the exact request")
	}
	return nil
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// marshalNetlinkMessage serializes one built message.
func marshalNetlinkMessage(message netlink.Message) []byte {
	if message.Header.Length == 0 {
		message.Header.Length = uint32(16 + len(message.Data))
	}
	data, _ := message.MarshalBinary()
	return data
}

// sendNetlinkRaw and recvNetlinkRaw are hooks over the metadata session so the
// no-attribute CONFIG exchange can be exercised with a deterministic transport.
var (
	sendNetlinkRaw = func(session anchorSession, datagram []byte) error {
		raw, ok := session.(rawNetlinkSession)
		if !ok {
			return errors.New("desync: metadata session cannot send raw netlink")
		}
		return raw.sendRaw(datagram)
	}
	recvNetlinkRaw = func(session anchorSession) ([]byte, *unix.SockaddrNetlink, error) {
		raw, ok := session.(rawNetlinkSession)
		if !ok {
			return nil, nil, errors.New("desync: metadata session cannot receive raw netlink")
		}
		return raw.recvRaw()
	}
)

// rawNetlinkSession is implemented by *nftNetlink.
type rawNetlinkSession interface {
	sendRaw([]byte) error
	recvRaw() ([]byte, *unix.SockaddrNetlink, error)
}

func (c *nftNetlink) sendRaw(datagram []byte) error {
	return unix.Sendto(c.fd, datagram, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
}

func (c *nftNetlink) recvRaw() ([]byte, *unix.SockaddrNetlink, error) {
	return c.recvDatagram()
}

// ---------------------------------------------------------------------------
// Queue configuration on the capture's own connection.
// ---------------------------------------------------------------------------

// nfqueueConfigMessage builds one NFQNL_MSG_CONFIG message with the AF_UNSPEC
// family of the ordered no-op/absence lookup. ack selects NLM_F_ACK. The
// explicit BIND/UNBIND commands keep their own family through messageOn.
func nfqueueConfigMessage(queue uint16, attrs []netlink.Attribute, ack bool) (netlink.Message, error) {
	data, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return netlink.Message{}, err
	}
	header := []byte{unix.AF_UNSPEC, 0, byte(queue >> 8), byte(queue)}
	flags := netlink.Request
	if ack {
		flags |= netlink.Acknowledge
	}
	return netlink.Message{Header: netlink.Header{
		Type: netlink.HeaderType(3<<8 | nfqMessageConfig), Flags: flags,
	}, Data: append(header, data...)}, nil
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

// configureOn performs one NFQNL_MSG_CONFIG request/reply exchange on the
// capture's only connection. It is only reached while the receive loop is not
// running.
func (c *linuxCapture) configureOn(queue uint16, family Family, attrs []netlink.Attribute) error {
	message, err := c.messageOn(queue, family, nfqMessageConfig, attrs, true)
	if err != nil {
		return err
	}
	if c.nl == nil {
		return fmt.Errorf("desync: NFQUEUE connection is not open")
	}
	_, err = c.nl.Execute(message)
	return err
}

// stillBoundQueues is the single ordered enumeration of the queues this capture
// still owns: the outbound witness, the inbound observation queue and, when
// configured, the owned ICMP-error queue. The ordered no-op CONFIG receipts and
// the fresh queue_total=0 observation both consume it, so the two §3.3 receipts
// can never enumerate different sets.
func (c *linuxCapture) stillBoundQueues() []uint16 {
	queues := []uint16{c.queue, c.inQueue}
	if c.icmpQueue != 0 {
		queues = append(queues, c.icmpQueue)
	}
	return queues
}

// observeOwnQueuesEmpty requires a fresh /proc/net/netfilter/nfnetlink_queue
// read inside the capture's actual namespace with queue_total 0 for every still
// bound own queue. A missing row while the queue is bound is an unproven
// receipt, not emptiness.
func (c *linuxCapture) observeOwnQueuesEmpty() error {
	queues := c.stillBoundQueues()
	var rows []queueRow
	err := withAnchorNamespace(c.owner.nsFD, func() error {
		fresh, readErr := readQueueReportInNamespace()
		if readErr != nil {
			return readErr
		}
		rows = fresh
		return nil
	})
	if err != nil {
		return fmt.Errorf("desync: read own NFQUEUE queue total: %w", err)
	}
	bound := c.outPort
	if c.nl != nil {
		if actual := c.nl.boundPort(); actual != 0 {
			bound = actual
		}
	}
	for _, queue := range queues {
		row, found := findQueueRowForPort(rows, queue, bound)
		if !found {
			return fmt.Errorf("desync: own queue %d is missing from the NFQUEUE report (%d rows)", queue, len(rows))
		}
		if row.total != 0 {
			return fmt.Errorf("desync: own queue %d still holds %d packets", queue, row.total)
		}
		if row.port != bound {
			return fmt.Errorf("desync: own queue %d is bound by port %d, not %d", queue, row.port, bound)
		}
	}
	return nil
}

// noOpQueueReceipt issues the own no-attribute CONFIG request and requires its
// matching ACK0 on this same queue connection.
func (c *linuxCapture) noOpQueueReceipt(queue uint16) error {
	if c.nl == nil {
		return fmt.Errorf("desync: NFQUEUE connection is not open")
	}
	message, err := nfqueueConfigMessage(queue, nil, true)
	if err != nil {
		return err
	}
	replies, err := c.nl.Execute(message)
	if err != nil {
		return fmt.Errorf("desync: ordered no-op CONFIG for NFQUEUE %d: %w", queue, err)
	}
	for _, reply := range replies {
		if reply.Header.Type == unix.NLMSG_ERROR {
			if len(reply.Data) < 4 || int32(binary.NativeEndian.Uint32(reply.Data)) != 0 {
				return fmt.Errorf("desync: ordered no-op CONFIG for NFQUEUE %d was rejected", queue)
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Queue allocation.
// ---------------------------------------------------------------------------

// allocateQueues allocates the outbound queue and the inbound observation queue
// from the bounded candidate window. Candidates exclude every valid live or
// retained manifest of this namespace in both families, this process's live
// registry and the kernel report. A kernel bind failure is authority.
func (c *linuxCapture) allocateQueues(endpoint Endpoint, state anchorFamilyState, excluded map[int]bool) (uint16, uint16, error) {
	configured := c.lease.engine.Config().Capture
	if configured.qnumSet {
		qnum := configured.qnum
		if qnum < 0 || qnum > 65535 {
			return 0, 0, fmt.Errorf("desync: capture.linux.qnum %d outside 0..65535", qnum)
		}
		if linuxQueueInUse(uint16(qnum)) {
			return 0, 0, fmt.Errorf("desync: capture.linux.qnum %d is bound by another listener", qnum)
		}
		if err := reserveQnum(qnum); err != nil {
			return 0, 0, err
		}
		out := uint16(qnum)
		c.overrideQnum = qnum
		start := uint16(managedQueueBase + (linuxQueueCounter.Add(1)*7)%managedQueueSpan)
		inCandidates := nextFreeQueues(start, 1, func(queue uint16) bool {
			return int(queue) == qnum || excluded[int(queue)] || qnumLive(int(queue)) || linuxQueueInUse(queue)
		})
		if len(inCandidates) < 1 {
			releaseQnum(qnum)
			return 0, 0, fmt.Errorf("desync: no free inbound NFQUEUE identity")
		}
		return out, inCandidates[0], nil
	}
	start := uint16(managedQueueBase + (linuxQueueCounter.Add(1)*7)%managedQueueSpan)
	candidates := nextFreeQueues(start, 2, func(queue uint16) bool {
		return excluded[int(queue)] || qnumLive(int(queue)) || linuxQueueInUse(queue)
	})
	if len(candidates) < 2 {
		return 0, 0, fmt.Errorf("desync: no free NFQUEUE identity in the managed range")
	}
	return candidates[0], candidates[1], nil
}

func (c *linuxCapture) allocateICMPQueue(endpoint Endpoint, state anchorFamilyState, excluded map[int]bool) (uint16, error) {
	start := uint16(managedQueueBase + (linuxQueueCounter.Add(1)*7)%managedQueueSpan)
	candidates := nextFreeQueues(start, 1, func(queue uint16) bool {
		return int(queue) == int(c.queue) || int(queue) == int(c.inQueue) ||
			excluded[int(queue)] || qnumLive(int(queue)) || linuxQueueInUse(queue)
	})
	if len(candidates) < 1 {
		return 0, fmt.Errorf("desync: no free ICMP NFQUEUE identity in the managed range")
	}
	return candidates[0], nil
}

// linuxQueueReportPath is the kernel's bound-queue report.
var linuxQueueReportPath = "/proc/net/netfilter/nfnetlink_queue"

// namespaceQueueReportPath is the per-thread report read inside the pinned
// actual namespace. It is a seam so the W-ABSENT join and the W-REPLACED row
// are model-testable.
var namespaceQueueReportPath = "/proc/thread-self/net/netfilter/nfnetlink_queue"

// queueRow is one parsed row of the kernel's NFQUEUE instance report. The
// columns are the exact deployed producer shape
// (linux-v6.8 net/netfilter/nfnetlink_queue.c seq_show):
//
//	queue_num peer_portid queue_total copy_mode copy_range queue_dropped
//	queue_user_dropped id_sequence 1
//
// copy_mode is validated against the modes nfqnl_set_mode accepts and the
// trailing column is the producer's hard-coded 1, so an abbreviated,
// extended or foreign report row is never partially adopted.
type queueRow struct {
	queue       uint16
	port        uint32
	total       uint32
	copyMode    uint8
	copyRange   uint32
	dropped     uint32
	userDropped uint32
	idSequence  uint32
}

// Deployed NFQUEUE report producer constants: seq_show prints nine unsigned
// decimal columns and a constant trailing 1; copy_mode comes from the
// NFQNL_COPY_NONE/META/PACKET set accepted by nfqnl_set_mode.
const (
	nfqnlQueueReportColumns  = 9
	nfqnlQueueReportTrailing = 1
	nfqnlCopyNone            = 0
	nfqnlCopyMeta            = 1
	nfqnlCopyPacket          = 2
)

// readQueueReportInNamespace reads a fresh report inside the pinned actual
// namespace. Reading registers and releases instances_lock, which is the
// second half of the W-ABSENT receipt.
func readQueueReportInNamespace() ([]queueRow, error) {
	content, err := os.ReadFile(namespaceQueueReportPath)
	if err != nil {
		return nil, err
	}
	rows := make([]queueRow, 0, 8)
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		row, err := parseQueueReportRow(line, fields)
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// parseQueueReportRow parses one complete deployed-kernel report row. The
// grammar is the exact v6.8 seq_show shape and its unsigned widths; missing,
// extra, non-numeric, out-of-range or unknown-mode columns are rejected, never
// truncated or adopted.
func parseQueueReportRow(line string, fields []string) (queueRow, error) {
	if len(fields) != nfqnlQueueReportColumns {
		return queueRow{}, fmt.Errorf("desync: malformed NFQUEUE report row %q", line)
	}
	var values [nfqnlQueueReportColumns]uint64
	for index, field := range fields {
		bitSize := 32
		switch index {
		case 0:
			// u_int16_t queue_num.
			bitSize = 16
		case 3:
			// u_int8_t copy_mode.
			bitSize = 8
		}
		value, err := strconv.ParseUint(field, 10, bitSize)
		if err != nil {
			return queueRow{}, fmt.Errorf("desync: malformed NFQUEUE report row %q", line)
		}
		values[index] = value
	}
	if values[3] > nfqnlCopyPacket {
		return queueRow{}, fmt.Errorf("desync: malformed NFQUEUE report row %q", line)
	}
	if values[8] != nfqnlQueueReportTrailing {
		return queueRow{}, fmt.Errorf("desync: malformed NFQUEUE report row %q", line)
	}
	return queueRow{
		queue:       uint16(values[0]),
		port:        uint32(values[1]),
		total:       uint32(values[2]),
		copyMode:    uint8(values[3]),
		copyRange:   uint32(values[4]),
		dropped:     uint32(values[5]),
		userDropped: uint32(values[6]),
		idSequence:  uint32(values[7]),
	}, nil
}

// findQueueRow returns the unique row of one queue number. Duplicate rows are
// inconsistent and are rejected by returning not-found with an error-free
// caller check through the row count.
func findQueueRow(rows []queueRow, queue uint16) (queueRow, bool) {
	var found queueRow
	count := 0
	for _, row := range rows {
		if row.queue == queue {
			found = row
			count++
		}
	}
	if count != 1 {
		return queueRow{}, false
	}
	return found, true
}

// findQueueRowForPort returns the unique report row of one queue for one
// specific peer port. Duplicate live rows for the same queue are still invalid;
// a deliberate foreign row with a different port does not hide our own row.
func findQueueRowForPort(rows []queueRow, queue uint16, port uint32) (queueRow, bool) {
	var found queueRow
	count := 0
	for _, row := range rows {
		if row.queue == queue && row.port == port {
			found = row
			count++
		}
	}
	if count != 1 {
		return queueRow{}, false
	}
	return found, true
}

func queueRowCount(rows []queueRow, queue uint16) int {
	count := 0
	for _, row := range rows {
		if row.queue == queue {
			count++
		}
	}
	return count
}

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
// that the inUse report does not list.
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

func (c *linuxCapture) bindQueue(queue uint16, family Family) error {
	return c.bindQueueOn(queue, family, c.nl)
}

func (c *linuxCapture) bindQueueOn(queue uint16, family Family, transport nfqueueConn) error {
	if transport == nil {
		return fmt.Errorf("desync: NFQUEUE connection is not open")
	}
	if err := c.configureQueueOn(transport, queue, family, []netlink.Attribute{
		{Type: nfqCfgAttrCmd, Data: []byte{nfqCfgCmdBind, 0, 0, transactionFamily(family)}},
	}); err != nil {
		return fmt.Errorf("desync: bind NFQUEUE %d: %w", queue, err)
	}
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
	if err := c.configureQueueOn(transport, queue, family, params); err != nil {
		_ = c.unbindQueueOn(transport, queue, family)
		return fmt.Errorf("desync: configure NFQUEUE %d: %w", queue, err)
	}
	return nil
}

func (c *linuxCapture) configureQueueOn(transport nfqueueConn, queue uint16, family Family, attrs []netlink.Attribute) error {
	message, err := c.messageOn(queue, family, nfqMessageConfig, attrs, true)
	if err != nil {
		return err
	}
	_, err = transport.Execute(message)
	return err
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
	c.bound = false
	return firstErr
}

func (c *linuxCapture) unbindQueue(queue uint16, family Family) error {
	return c.unbindQueueOn(c.nl, queue, family)
}

func (c *linuxCapture) unbindQueueOn(transport nfqueueConn, queue uint16, family Family) error {
	if queue == 0 || transport == nil {
		return nil
	}
	return c.configureQueueOn(transport, queue, family, []netlink.Attribute{
		{Type: nfqCfgAttrCmd, Data: []byte{nfqCfgCmdUnbind, 0, 0, transactionFamily(family)}},
	})
}

func transactionFamily(family Family) byte {
	if family == FamilyIPv6 {
		return unix.AF_INET6
	}
	return unix.AF_INET
}

// bindRemainingQueues binds the non-witness queues and their parameters after
// the witness transaction closed.
func (c *linuxCapture) bindRemainingQueues(endpoint Endpoint) error {
	if c.inQueue != c.queue {
		if err := c.bindQueueOn(c.inQueue, endpoint.Family, c.nl); err != nil {
			return err
		}
	}
	if c.icmpQueue != 0 {
		if err := c.bindQueueOn(c.icmpQueue, endpoint.Family, c.nl); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Capture rules.
// ---------------------------------------------------------------------------

// attachCaptureRules creates the capture's regular chains and its exact tagged
// entries. Injection entries are inserted at the head of the output chain so
// every tag accept precedes every ordinary dispatch entry; ordinary entries are
// appended.
func (c *linuxCapture) attachCaptureRules(endpoint Endpoint) error {
	var (
		familyByte byte
		familyName string
		epoch      string
	)
	familyName, familyByte, _ = anchorFamilyNames(endpoint.Family)
	epoch = c.anchor.epoch
	_ = familyName
	chainO := anchorChainPrefix + c.anchor.capture + "_o"
	chainI := anchorChainPrefix + c.anchor.capture + "_i"
	chainE := anchorChainPrefix + c.anchor.capture + "_e"
	role := func(name string) []byte {
		return []byte(anchorCaptureUserdata(epoch, c.owner.token, c.anchor.capture, name))
	}
	marshal := func(expression expr.Any) ([]byte, error) { return expr.Marshal(familyByte, expression) }

	requests := make([]nftRequest, 0, 12)
	addChain := func(name string) {
		requests = append(requests, nftRegularChainMessage(familyByte, anchorTableName, name))
	}
	addRule := func(chain string, expressions []expr.Any, roleName string) error {
		encoded := make([][]byte, 0, len(expressions))
		for _, expression := range expressions {
			data, err := marshal(expression)
			if err != nil {
				return err
			}
			encoded = append(encoded, data)
		}
		request, err := nftRuleMessage(familyByte, anchorTableName, chain, encoded, role(roleName))
		if err != nil {
			return err
		}
		requests = append(requests, request)
		return nil
	}
	// The capture's own regular chains exist before the jump rules that name
	// them; a single batch preserves the kernel order.
	outboundEnabled := c.lease.engine.Config().Capture.limits.direction(endpoint.Transport, true).enabled()
	if outboundEnabled {
		addChain(chainO)
	}
	if c.inboundEnabled(endpoint) {
		addChain(chainI)
	}
	if c.wantsICMPFilter() {
		addChain(chainE)
	}

	// 1. Exact-tag injection bypass, head of the output base chain. All tags
	// are allocation values of this family's monotone high-water mark, never
	// qnum-derived or recycled.
	bypass, bypassErr := c.injectionExpressions(endpoint, c.anchor.tag)
	if bypassErr != nil {
		return bypassErr
	}
	injectRule, err := c.appendHeadRule(anchorBaseOutputName, bypass, role("inject"))
	if err != nil {
		return err
	}
	requests = append(requests, injectRule)

	// 2. Ordinary dispatch entries: output tuple -> c_o; reverse tuple -> c_i;
	// optional quoted ICMP -> c_e.
	if outboundEnabled {
		entryO, err := c.dispatchExpressions(endpoint, true)
		if err != nil {
			return err
		}
		entryO = append(entryO, &expr.Verdict{Kind: expr.VerdictJump, Chain: chainO})
		if err = addRule(anchorBaseOutputName, entryO, "entry-o"); err != nil {
			return err
		}
	}
	if c.inboundEnabled(endpoint) {
		entryI, dispatchErr := c.dispatchExpressions(endpoint, false)
		if dispatchErr != nil {
			return dispatchErr
		}
		entryI = append(entryI, &expr.Verdict{Kind: expr.VerdictJump, Chain: chainI})
		if err = addRule(anchorBaseInputName, entryI, "entry-i"); err != nil {
			return err
		}
	}
	if c.wantsICMPFilter() {
		entryE, dispatchErr := c.icmpDispatchExpressions(endpoint)
		if dispatchErr != nil {
			return dispatchErr
		}
		entryE = append(entryE, &expr.Verdict{Kind: expr.VerdictJump, Chain: chainE})
		if err = addRule(anchorBaseInputName, entryE, "entry-e"); err != nil {
			return err
		}
	}

	// 3. Queue rules inside the capture-owned regular chains.
	if outboundEnabled {
		if err = addRule(chainO, []expr.Any{&expr.Queue{Num: c.queue, Flag: expr.QueueFlagBypass}}, "queue-o"); err != nil {
			return err
		}
	}
	if c.inboundEnabled(endpoint) {
		inboundLimit := c.lease.engine.Config().Capture.limits.direction(endpoint.Transport, false)
		queueExpressions := make([]expr.Any, 0, 3)
		if inboundLimit.bounded() {
			ctExpression, comparison, ctErr := replyLimitExpressions(inboundLimit)
			if ctErr != nil {
				return ctErr
			}
			encoded := make([][]byte, 0, 3)
			encoded = append(encoded, ctExpression, comparison)
			queue, marshalErr := marshal(&expr.Queue{Num: c.inQueue, Flag: expr.QueueFlagBypass})
			if marshalErr != nil {
				return marshalErr
			}
			encoded = append(encoded, queue)
			request, ruleErr := nftRuleMessage(familyByte, anchorTableName, chainI, encoded, role("queue-i"))
			if ruleErr != nil {
				return ruleErr
			}
			requests = append(requests, request)
			_ = queueExpressions
		} else if err = addRule(chainI, []expr.Any{&expr.Queue{Num: c.inQueue, Flag: expr.QueueFlagBypass}}, "queue-i"); err != nil {
			return err
		}
	}
	if c.wantsICMPFilter() {
		if err = addRule(chainE, []expr.Any{&expr.Queue{Num: c.icmpQueue, Flag: expr.QueueFlagBypass}}, "queue-e"); err != nil {
			return err
		}
	}
	if _, err = c.batchAnchor(requests); err != nil {
		return err
	}
	c.anchor.chainHandles = make(map[string]uint64)
	if outboundEnabled {
		c.anchor.chainHandles[chainO] = 0
	}
	if c.inboundEnabled(endpoint) {
		c.anchor.chainHandles[chainI] = 0
	}
	if c.wantsICMPFilter() {
		c.anchor.chainHandles[chainE] = 0
	}
	return nil
}

// injectionExpressions builds the exact-tag accept rule of the output base
// chain. For IPv4 the ALT11 zero-IPID write stays here, after the kernel
// normalized the raw-socket header.
func (c *linuxCapture) injectionExpressions(endpoint Endpoint, tag uint32) ([]expr.Any, error) {
	priority := make([]byte, 4)
	binary.NativeEndian.PutUint32(priority, tag)
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
	return bypass, nil
}

// appendHeadRule adds one tagged rule at the head of a base chain.
func (c *linuxCapture) appendHeadRule(chain string, expressions []expr.Any, userdata []byte) (nftRequest, error) {
	_, familyByte, err := anchorFamilyNames(c.lease.Endpoint().Family)
	if err != nil {
		return nftRequest{}, err
	}
	encoded := make([][]byte, 0, len(expressions))
	for _, expression := range expressions {
		data, marshalErr := expr.Marshal(familyByte, expression)
		if marshalErr != nil {
			return nftRequest{}, marshalErr
		}
		encoded = append(encoded, data)
	}
	return nftRuleMessageHead(familyByte, anchorTableName, chain, encoded, userdata)
}

// tupleAddressExpressions builds the address predicates of one capture
// direction. The families store the addresses at different network-header
// offsets: IPv4 source/destination at 12/16 are contiguous, so the established
// single 8-byte comparison is kept byte-identical. IPv6 source/destination are
// at 8/24 with the flow label and payload length between them; a kernel
// comparison value is bounded to sizeof(struct nft_data) (16 bytes), so one
// combined 32-byte value is rejected at rule-install time with EOVERFLOW. The
// IPv6 form therefore uses two bounded 16-byte loads and comparisons at the
// family-correct offsets, without weakening either address predicate.
func tupleAddressExpressions(family Family, source, destination netip.Addr) ([]expr.Any, error) {
	switch family {
	case FamilyIPv4:
		if !source.Is4() || !destination.Is4() {
			return nil, errors.New("desync: IPv4 capture tuple carries a non-IPv4 address")
		}
		addresses := make([]byte, 0, 8)
		addresses = append(addresses, source.AsSlice()...)
		addresses = append(addresses, destination.AsSlice()...)
		return []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 8},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addresses},
		}, nil
	case FamilyIPv6:
		if !source.Is6() || !destination.Is6() {
			return nil, errors.New("desync: IPv6 capture tuple carries a non-IPv6 address")
		}
		return []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: source.AsSlice()},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: destination.AsSlice()},
		}, nil
	default:
		return nil, fmt.Errorf("desync: unsupported capture address family %d", family)
	}
}

// dispatchExpressions builds the ordinary tuple match of one direction. The
// direction limit stays in the entry rule, before the jump, so an unlimited
// capture does not use the reply counter path.
func (c *linuxCapture) dispatchExpressions(endpoint Endpoint, outbound bool) ([]expr.Any, error) {
	protocol := byte(unix.IPPROTO_TCP)
	if endpoint.Transport == TransportUDP {
		protocol = unix.IPPROTO_UDP
	}
	expressions := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocol}},
	}
	sourceAddressSpecified := endpoint.Source.IsValid() && !endpoint.Source.Addr().IsUnspecified()
	if outbound {
		if endpoint.Interface != "" {
			expressions = append(expressions, interfaceNameCompare(expr.MetaKeyOIFNAME, endpoint.Interface)...)
		}
		if sourceAddressSpecified && endpoint.Destination.IsValid() {
			addresses, err := tupleAddressExpressions(endpoint.Family, endpoint.Source.Addr(), endpoint.Destination.Addr())
			if err != nil {
				return nil, err
			}
			expressions = append(expressions, addresses...)
		}
		ports := make([]byte, 4)
		binary.BigEndian.PutUint16(ports[:2], endpoint.Source.Port())
		binary.BigEndian.PutUint16(ports[2:], endpoint.Destination.Port())
		if endpoint.Destination.IsValid() {
			expressions = append(expressions,
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 4},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ports})
		} else {
			expressions = append(expressions,
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ports[:2]})
		}
		outboundLimit := c.lease.engine.Config().Capture.limits.direction(endpoint.Transport, true)
		if outboundLimit.enabled() {
			if limitExpressions := c.outboundLimitExpressions(endpoint, outboundLimit); len(limitExpressions) > 0 {
				expressions = append(expressions, limitExpressions...)
			}
		}
		return expressions, nil
	}
	if endpoint.Interface != "" {
		expressions = append(expressions, interfaceNameCompare(expr.MetaKeyIIFNAME, endpoint.Interface)...)
	}
	if sourceAddressSpecified && endpoint.Destination.IsValid() {
		reverse, err := tupleAddressExpressions(endpoint.Family, endpoint.Destination.Addr(), endpoint.Source.Addr())
		if err != nil {
			return nil, err
		}
		expressions = append(expressions, reverse...)
	}
	ports := make([]byte, 4)
	binary.BigEndian.PutUint16(ports[:2], endpoint.Destination.Port())
	binary.BigEndian.PutUint16(ports[2:], endpoint.Source.Port())
	if endpoint.Destination.IsValid() {
		expressions = append(expressions,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ports})
	} else {
		expressions = append(expressions,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ports[2:]})
	}
	return expressions, nil
}

func (c *linuxCapture) inboundEnabled(endpoint Endpoint) bool {
	return c.lease.engine.Config().Capture.limits.direction(endpoint.Transport, false).enabled()
}

// icmpDispatchExpressions builds the quoted time-exceeded match (without the
// queue verdict) for the capture's ICMP chain.
func (c *linuxCapture) icmpDispatchExpressions(endpoint Endpoint) ([]expr.Any, error) {
	rule := c.icmpErrorRule(endpoint)
	if len(rule) == 0 {
		return nil, errors.New("desync: empty ICMP rule")
	}
	return rule[:len(rule)-1], nil
}

// batchAnchor commits one capture-owned metadata batch outside the open
// transaction (rule attachment).
func (c *linuxCapture) batchAnchor(requests []nftRequest) ([]nftReply, error) {
	var replies []nftReply
	err := withAnchorTransaction(c.owner, func(session anchorSession) error {
		var batchErr error
		replies, batchErr = session.batch(requests)
		return batchErr
	})
	return replies, err
}

// verifyCaptureRules reads back every capture-owned object and requires exact
// presence before the capture becomes visible.
func (c *linuxCapture) verifyCaptureRules() error {
	return withAnchorTransaction(c.owner, func(session anchorSession) error {
		state, err := readAnchorFamilyState(session, c.lease.Endpoint().Family)
		if err != nil {
			return err
		}
		key := captureKey(c.owner.token, c.anchor.capture)
		manifest, found := state.captures[key]
		if !found || manifest.port == nil || manifest.port.record.phase != "w" {
			return errors.New("desync: capture metadata is not visible as witnessed")
		}
		rules := state.baseRules[key]
		roles := make(map[string]bool, len(rules))
		for _, rule := range rules {
			roles[rule.role] = true
		}
		if !roles["inject"] {
			return errors.New("desync: capture injection entry is missing")
		}
		expected := 1
		if c.lease.engine.Config().Capture.limits.direction(c.lease.Endpoint().Transport, true).enabled() {
			expected++
			if !roles["entry-o"] {
				return errors.New("desync: capture output entry is missing")
			}
		}
		if c.inboundEnabled(c.lease.Endpoint()) {
			expected++
			if !roles["entry-i"] {
				return errors.New("desync: capture input entry is missing")
			}
		}
		if c.wantsICMPFilter() {
			expected++
			if !roles["entry-e"] {
				return errors.New("desync: capture ICMP entry is missing")
			}
		}
		if len(rules) != expected {
			return fmt.Errorf("desync: capture has %d base entries, want %d", len(rules), expected)
		}
		chains := state.chains[key]
		if len(chains) != len(c.anchor.chainHandles) {
			return errors.New("desync: capture regular chains are incomplete")
		}
		for name := range c.anchor.chainHandles {
			if _, found := chains[name]; !found {
				return fmt.Errorf("desync: capture chain %q is missing", name)
			}
			rules, ruleErr := readAnchorRules(session, state.tableFamily, anchorTableName, name)
			if ruleErr != nil {
				return ruleErr
			}
			if len(rules) == 0 {
				return fmt.Errorf("desync: capture chain %q is empty", name)
			}
		}
		c.anchor.chainHandles = chains
		return nil
	})
}

// ---------------------------------------------------------------------------
// Packet handling (unchanged semantics).
// ---------------------------------------------------------------------------

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

func (c *linuxCapture) wantsICMPFilter() bool {
	return c.lease.engine.Config().Capture.filterTTLExpiredICMP
}

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
				rules = append(rules,
					&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 0, Len: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x45}})
			}
			rules = append(rules, innerQuotedSourceCompare(endpoint.Family, address)...)
		}
	}
	return rules
}

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

// sendVerdict delivers the one terminal disposition of a captured packet.
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
		attributes = append(attributes, netlink.Attribute{Type: 1, Data: modified})
	}
	message, err := c.messageOn(queue, c.lease.Endpoint().Family, 1, attributes, false)
	if err != nil {
		c.lease.ReportNativeFailure(fmt.Errorf("desync: build NFQUEUE verdict for captured packet: %w", err))
		return
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if _, err = c.nl.Send(message); err != nil {
		c.lease.ReportNativeFailure(fmt.Errorf("desync: send NFQUEUE verdict for captured packet: %w", err))
	}
}

func (c *linuxCapture) loop() {
	defer close(c.done)
	for {
		messages, err := c.nl.Receive()
		if err != nil {
			// The intentional stop interruption is a read deadline armed by
			// stopReceive after this capture published its closing state. It
			// is not a native failure and must not poison the lease.
			if c.stopping.Load() && errors.Is(err, os.ErrDeadlineExceeded) {
				return
			}
			// Any other receive error (a kernel error message, an
			// undecodable native datagram, a transport failure) ends this
			// receive lane. The lease is the durable diagnostic owner of the
			// attempt, so the failure must be visible there before Close
			// instead of disappearing with a silently retired goroutine.
			c.lease.ReportNativeFailure(fmt.Errorf("desync: receive NFQUEUE datagram: %w", err))
			return
		}
		if !c.handleBatch(messages) {
			c.lease.ReportNativeFailure(errors.New("desync: receive NFQUEUE datagram: malformed message batch"))
			return
		}
		if c.stopping.Load() {
			if err := c.nl.SetReadDeadline(time.Now().Add(queueStopDrain)); err != nil {
				c.lease.ReportNativeFailure(fmt.Errorf("desync: rearm NFQUEUE receive deadline for stop: %w", err))
				return
			}
		}
	}
}

func (c *linuxCapture) handleBatch(messages []netlink.Message) bool {
	for _, message := range messages {
		if uint16(message.Header.Type) != 3<<8 || len(message.Data) < 4 {
			continue
		}
		queue := binary.BigEndian.Uint16(message.Data[2:4])
		if queue != c.queue && queue != c.inQueue && queue != c.icmpQueue {
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
			c.sendVerdict(packetQueue, packetID, verdict, reason, modified)
		}
		if !c.dispatch.beginDispatch() {
			c.dispatch.awaitPassThrough()
			c.sendVerdict(packetQueue, packetID, VerdictPass, "", nil)
			continue
		}
		verdict := c.lease.HandlePacket(frame, direction, c.inject, complete)
		c.dispatch.endDispatch()
		if verdict == VerdictHold {
			continue
		}
		modified := []byte(nil)
		if verdict == VerdictModify {
			modified = c.lease.TakeModified(DirectionOutbound)
		}
		preFence := c.dispatch.beginSend()
		if !preFence {
			c.dispatch.awaitPassThrough()
		}
		c.sendVerdict(packetQueue, packetID, verdict, "", modified)
		if preFence {
			c.dispatch.endSend()
		}
	}
	return true
}

// inject performs one operation-scoped raw send in the capture owner's pinned
// namespace. rawMu serializes the entire save/enter/send/close/restore operation;
// the single fork-read token covers raw fd creation through its actual Close.
// The short-lived helper exits even if namespace restoration fails, allowing
// withAnchorNamespace's still-locked thread to be discarded, not reused by the
// caller. Nothing is cached, exported, queued or retried.
func (c *linuxCapture) inject(packet []byte) error {
	parsed, err := ParsePacket(packet)
	if err != nil {
		return err
	}
	c.rawMu.Lock()
	defer c.rawMu.Unlock()
	done := make(chan error)
	go func() {
		done <- withAnchorNamespace(c.owner.nsFD, func() error {
			return withForkReadToken(func() error {
				return c.sendInjected(parsed, packet)
			})
		})
	}()
	return <-done
}

// Raw injection syscall seams keep the operation-scoped path testable without
// CAP_NET_RAW or changes to the calling thread's actual network namespace.
var (
	openInjectionSocket       = unix.Socket
	setInjectionSockoptInt    = unix.SetsockoptInt
	setInjectionSockoptString = unix.SetsockoptString
	bindInjectionSocket       = unix.Bind
	sendInjectionPacket       = unix.Sendto
	closeInjectionSocket      = unix.Close
)

func (c *linuxCapture) sendInjected(parsed *Packet, packet []byte) error {
	family := parsed.Family
	var (
		fd        int
		sendErr   error
		sockProto int
	)
	switch family {
	case FamilyIPv4:
		fd, sendErr = openInjectionSocket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
		sockProto = unix.IPPROTO_IP
	case FamilyIPv6:
		fd, sendErr = openInjectionSocket(unix.AF_INET6, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
		sockProto = unix.IPPROTO_IPV6
	default:
		return fmt.Errorf("desync: unsupported injection family")
	}
	_ = sockProto
	if sendErr != nil {
		return sendErr
	}
	defer closeInjectionSocket(fd)
	if family == FamilyIPv4 {
		if err := setInjectionSockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
			return err
		}
	}
	if bindSource(c.lease.engine.Config().Capture, family) {
		bindInjectionSource(fd, family, parsed.Src)
	}
	if mark := injectionMark(c.lease.socketMark(), c.lease.engine.Config().Capture); mark != 0 {
		_ = setInjectionSockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, mark)
	}
	if device := c.lease.socketDevice(); device != "" {
		_ = setInjectionSockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, device)
	}
	if err := setInjectionSockoptInt(fd, unix.SOL_SOCKET, unix.SO_PRIORITY, int(c.anchor.tag)); err != nil {
		return err
	}
	var destination unix.Sockaddr
	switch family {
	case FamilyIPv4:
		value := &unix.SockaddrInet4{Port: int(parsed.DstPort)}
		value.Addr = parsed.Dst.As4()
		destination = value
	case FamilyIPv6:
		// Raw IPv6 interprets sin6_port as an IP protocol, not a transport
		// port. Zero selects the socket protocol; UDP/TCP ports stay in packet.
		value := &unix.SockaddrInet6{}
		value.Addr = parsed.Dst.As16()
		destination = value
	}
	if err := sendInjectionPacket(fd, packet, 0, destination); err != nil {
		return err
	}
	c.lease.noteInjection()
	return nil
}

// bindInjectionSource ports upstream bind-fix4/bind-fix6: bind the raw socket
// to the generated packet's source address; a refused bind is ignored.
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
		_ = setInjectionSockoptInt(fd, unix.IPPROTO_IP, unix.IP_FREEBIND, 1)
		sockaddr = value
	case FamilyIPv6:
		if !source.Is6() {
			return
		}
		value := &unix.SockaddrInet6{Addr: source.As16()}
		_ = setInjectionSockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_FREEBIND, 1)
		sockaddr = value
	default:
		return
	}
	_ = bindInjectionSocket(fd, sockaddr)
}

// ---------------------------------------------------------------------------
// Receive shutdown and drain.
// ---------------------------------------------------------------------------

func (c *linuxCapture) stopReceive() error {
	if c.nl == nil || !c.started {
		return nil
	}
	c.stopping.Store(true)
	if err := c.nl.SetReadDeadline(time.Now().Add(queueStopDrain)); err != nil {
		_ = closeTransport(c.nl)
		<-c.done
		return fmt.Errorf("desync: stop NFQUEUE receive: %w", err)
	}
	<-c.done
	drainErr := c.drainQueued()
	if err := c.nl.SetReadDeadline(time.Time{}); err != nil && drainErr == nil {
		drainErr = fmt.Errorf("desync: clear NFQUEUE read deadline: %w", err)
	}
	return drainErr
}

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

func (c *linuxCapture) FenceDispatch() { c.dispatch.fence() }

func (c *linuxCapture) Quiesce() error {
	c.dispatch.quiesce()
	return nil
}

func (c *linuxCapture) AllowPassThrough() { c.dispatch.allowPassThrough() }

// ---------------------------------------------------------------------------
// Close: the exact N-A1/N-A2 retirement protocol.
// ---------------------------------------------------------------------------

func (c *linuxCapture) Close() error {
	c.closeOnce.Do(func() {
		if c.owner == nil {
			// A bare capture (gate-only model tests) has no anchor ownership.
			// It still releases the ordered pass-through exactly once.
			c.dispatch.allowPassThrough()
			if !c.started && c.done != nil {
				close(c.done)
			}
			return
		}
		if !c.outWitnessed {
			// Opening failed before the durable witness: only exact own
			// unexposed resources are closed here. Any durable effect is left
			// to open-time reconciliation and recovery.
			c.closeErr = c.closeUnwitnessed()
			if c.closeErr == nil && !c.owner.retainedState() {
				c.releaseOwnerRef()
			}
			return
		}
		c.closeErr = c.retire()
	})
	return c.closeErr
}

// closeUnwitnessed releases a capture that never published p(w): the private
// socket is closed (the fork token already guaranteed no child inherited it),
// non-witness queues are unbound when reachable, and the p(o)/m records are
// removed only after a complete readback.
func (c *linuxCapture) closeUnwitnessed() error {
	var firstErr error
	if c.nl != nil {
		if err := closeTransport(c.nl); err != nil {
			firstErr = err
		}
		c.nl = nil
	}
	if firstErr != nil {
		c.owner.markRetained()
		if c.overrideQnum != 0 {
			// Keep the reservation while the effect is unproven.
			c.overrideQnum = 0
		}
		return firstErr
	}
	err := withAnchorTransaction(c.owner, func(session anchorSession) error {
		state, err := readAnchorFamilyState(session, c.lease.Endpoint().Family)
		if err != nil {
			return err
		}
		key := captureKey(c.owner.token, c.anchor.capture)
		manifest, found := state.captures[key]
		if !found {
			return nil
		}
		// The p(o) capture was never attached; still run the separate
		// no-mutation fence before erasing its record, so an old reader
		// cannot interleave.
		if _, err = runEnqueueFence(); err != nil {
			return err
		}
		return c.removeMetadata(session, state, key, manifest)
	})
	if err != nil {
		c.owner.markRetained()
		return err
	}
	if c.overrideQnum != 0 {
		releaseQnum(c.overrideQnum)
	}
	return nil
}

// retire is the ordered positive-retirement protocol of §3.3/§4.
func (c *linuxCapture) retire() error {
	endpoint := c.lease.Endpoint()
	// 1. Exact own entry detach and the separate no-mutation fence.
	detachErr := c.detachAndFence()
	if detachErr != nil {
		c.owner.markRetained()
		return detachErr
	}
	// 2. Join and drain the receive lane.
	if err := c.stopReceive(); err != nil {
		c.owner.markRetained()
		return err
	}
	// 3. Ordered no-op CONFIG ACK0 for every still-bound own queue, including
	// the outbound witness: §3.3 requires the matching ACK0 for EACH bound own
	// queue, not only for the non-witness ones.
	for _, queue := range c.stillBoundQueues() {
		if err := c.noOpQueueReceipt(queue); err != nil {
			c.owner.markRetained()
			return err
		}
	}
	// 3b. Fresh exact own queue_total=0 observation for every still-bound own
	// queue, including the outq witness: the no-op ACK proves the control
	// round-trip, the kernel report proves no packet of ours is still held.
	if err := c.observeOwnQueuesEmpty(); err != nil {
		c.owner.markRetained()
		return err
	}
	// 4. UNBIND only the non-witness queues; outq stays bound until its owning
	// socket is released.
	if err := c.unbindQueues(); err != nil {
		c.owner.markRetained()
		return err
	}
	// 5. Close the owning socket with outq still bound and obtain the
	// release-scan receipt for its port.
	if c.nl != nil {
		closeErr := closeTransport(c.nl)
		c.nl = nil
		if closeErr != nil {
			c.owner.markRetained()
			return fmt.Errorf("desync: close owning NFQUEUE socket: %w", closeErr)
		}
	}
	var scanErr error
	scanErr = withAnchorTransaction(c.owner, func(session anchorSession) error {
		_, err := observeReleaseScan(session, c.outPort, c.queue)
		return err
	})
	if scanErr != nil {
		c.owner.markRetained()
		return scanErr
	}
	// 6. Last-owner guard release probe, BEFORE the last m/p record is
	// erased: a busy inherited guard retains that record, its reservation and
	// the native charge of this attempt.
	last, lastErr := c.owner.beginCaptureRetirement()
	if lastErr != nil {
		c.owner.markRetained()
		return lastErr
	}
	if last {
		if err := c.retireOwnerGuard(); err != nil {
			c.owner.markRetained()
			return err
		}
	}
	// 7. Remove exact own regular chains and m+p. The irreversible t
	// high-water and the fixed anchors stay.
	var metadataErr error
	metadataErr = withAnchorTransaction(c.owner, func(session anchorSession) error {
		state, err := readAnchorFamilyState(session, endpoint.Family)
		if err != nil {
			return err
		}
		key := captureKey(c.owner.token, c.anchor.capture)
		manifest, found := state.captures[key]
		if !found {
			return nil
		}
		return c.removeMetadata(session, state, key, manifest)
	})
	if metadataErr != nil {
		c.owner.markRetained()
		return metadataErr
	}
	if c.overrideQnum != 0 {
		releaseQnum(c.overrideQnum)
		c.overrideQnum = 0
	}
	c.releaseOwnerRef()
	c.retired.Store(true)
	return nil
}

// detachAndFence removes every exact own entry, proves absence by readback and
// then runs the separate BEGIN/GETGEN/END fence. A lost fence reply is retried
// as a fresh identical no-mutation operation; only a typed receipt succeeds.
func (c *linuxCapture) detachAndFence() error {
	var fenceErr error
	err := withAnchorTransaction(c.owner, func(session anchorSession) error {
		state, err := readAnchorFamilyState(session, c.lease.Endpoint().Family)
		if err != nil {
			return err
		}
		key := captureKey(c.owner.token, c.anchor.capture)
		if err = detachCaptureRules(session, state, key); err != nil {
			return err
		}
		// The fence is a separate no-mutation operation on a fresh control
		// socket, still under this namespace transaction.
		for attempt := 0; attempt < anchorReceiptAttempts; attempt++ {
			_, fenceErr = runEnqueueFence()
			if fenceErr == nil {
				return nil
			}
			if !errors.Is(fenceErr, errEnqueueFenceNoReceipt) && !errors.Is(fenceErr, errNftMetadataTimeout) {
				return fenceErr
			}
		}
		return fenceErr
	})
	return err
}

// removeMetadata deletes the capture's regular chains, m and p by their current
// handles and verifies complete absence. It never touches the fixed anchors or
// the t high-water.
func (c *linuxCapture) removeMetadata(session anchorSession, state anchorFamilyState, key string, manifest *anchorManifestRecord) error {
	if err := deleteCaptureChains(session, state, key, manifest.record.capture); err != nil {
		return err
	}
	requests := []nftRequest{nftDeleteRuleMessage(state.tableFamily, anchorTableName, anchorMarkerChainName, manifest.handle)}
	if manifest.port != nil {
		requests = append(requests, nftDeleteRuleMessage(state.tableFamily, anchorTableName, anchorMarkerChainName, manifest.port.handle))
	}
	if _, err := session.batch(requests); err != nil {
		if readErr := c.readbackMetadataAbsent(session, state, c.owner.token, c.anchor.capture); readErr != nil {
			return fmt.Errorf("desync: remove capture metadata: %w", err)
		}
	}
	return c.readbackMetadataAbsent(session, state, c.owner.token, c.anchor.capture)
}

// retireOwnerGuard closes the last local guard fd and probes the exact abstract
// name inside one short fork-excluded transaction. A busy inherited guard
// retains the final record instead of manufacturing a positive receipt.
func (c *linuxCapture) retireOwnerGuard() error {
	guard := c.owner.guard
	name := ""
	if guard != nil {
		name = guard.name
	}
	if err := guard.close(); err != nil {
		return fmt.Errorf("desync: close owner guard: %w", err)
	}
	var busy bool
	err := withAnchorNamespace(c.owner.nsFD, func() error {
		return withForkReadToken(func() error {
			var probeErr error
			busy, probeErr = probeAnchorGuardAddress(name)
			return probeErr
		})
	})
	if err != nil {
		return fmt.Errorf("desync: probe owner guard release: %w", err)
	}
	if busy {
		return errors.New("desync: owner guard is still held by an inherited descriptor")
	}
	return nil
}

// rollbackOpen releases a capture whose open failed. Exact own effects are
// reconciled; an unproven effect marks the owner retained so no new generation
// is appended while it exists.
func (c *linuxCapture) rollbackOpen() {
	if c.retired.Load() {
		return
	}
	if c.outWitnessed {
		if err := c.retire(); err != nil {
			c.owner.markRetained()
		}
		return
	}
	if err := c.closeUnwitnessed(); err != nil {
		c.owner.markRetained()
	}
}

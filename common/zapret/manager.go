package zapret

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/sing/common"
	N "github.com/sagernet/sing/common/network"
)

const (
	// DefaultReservationPorts is the number of TCP and UDP ports reserved per
	// socket family and per outbound. Four anchors are held per outbound:
	// TCP/IPv4, TCP/IPv6, UDP/IPv4 and UDP/IPv6.
	DefaultReservationPorts = 256
	// DefaultStartupTimeout bounds the whole engine startup including the
	// version probe, reservations and Lua initialization.
	DefaultStartupTimeout = 15 * time.Second
	// DefaultStopTimeout bounds child termination and anchor release.
	DefaultStopTimeout = 10 * time.Second
)

// ErrUnsupported is returned when a zapret profile is configured on a platform
// where this slice does not implement engine ownership.
var ErrUnsupported = errors.New("zapret: original engine ownership is implemented for Windows and Linux only in this slice; remove the zapret field for the ordinary direct path")

// Logger is the subset of the sing-box logger used by the manager. All engine
// output is forwarded at debug level so ordinary product logs stay bounded.
type Logger interface {
	Info(args ...any)
	Debug(args ...any)
	Error(args ...any)
}

type State uint8

const (
	StateNew State = iota
	StateStarting
	StateReady
	StateStopping
	StateClosed
	StateFailed
)

func (s State) String() string {
	switch s {
	case StateNew:
		return "new"
	case StateStarting:
		return "starting"
	case StateReady:
		return "ready"
	case StateStopping:
		return "stopping"
	case StateClosed:
		return "closed"
	case StateFailed:
		return "failed"
	default:
		return "unknown"
	}
}

type Options struct {
	// Tag is the outbound tag used in diagnostics.
	Tag string
	// ProfilePath is the absolute path of a zapret profile file.
	ProfilePath string
	// BindInterface is the outbound physical interface name. It is required:
	// the same interface pins ordinary sockets and the WinDivert capture.
	BindInterface    string
	Logger           Logger
	StartupTimeout   time.Duration
	StopTimeout      time.Duration
	ReservationPorts int
}

type Manager struct {
	tag              string
	profile          *profile
	bindInterface    string
	logger           Logger
	startupTimeout   time.Duration
	stopTimeout      time.Duration
	reservationPorts uint16

	mutex          sync.Mutex
	state          State
	failure        error
	interfaceIndex int
	engine         platformEngine
	flows          map[*flowHandle]struct{}
	closed         chan struct{}
	closeOnce      sync.Once
}

func NewManager(options Options) (*Manager, error) {
	if options.Logger == nil {
		return nil, fmt.Errorf("zapret: outbound %q: missing logger", options.Tag)
	}
	loadedProfile, err := loadProfile(options.ProfilePath)
	if err != nil {
		return nil, err
	}
	if !engineSupported() {
		return nil, ErrUnsupported
	}
	if options.BindInterface == "" {
		return nil, fmt.Errorf("zapret: outbound %q: bind_interface is required: the physical interface pins ordinary sockets and the engine capture", options.Tag)
	}
	reservationPorts := options.ReservationPorts
	if reservationPorts == 0 {
		reservationPorts = loadedProfile.reservationPorts
	}
	if reservationPorts == 0 {
		reservationPorts = DefaultReservationPorts
	}
	if reservationPorts < 16 || reservationPorts > 4096 {
		return nil, fmt.Errorf("zapret: outbound %q: reservation port count %d is outside 16..4096", options.Tag, reservationPorts)
	}
	startupTimeout := options.StartupTimeout
	if startupTimeout == 0 {
		startupTimeout = DefaultStartupTimeout
	}
	stopTimeout := options.StopTimeout
	if stopTimeout == 0 {
		stopTimeout = DefaultStopTimeout
	}
	return &Manager{
		tag:              options.Tag,
		profile:          loadedProfile,
		bindInterface:    options.BindInterface,
		logger:           options.Logger,
		startupTimeout:   startupTimeout,
		stopTimeout:      stopTimeout,
		reservationPorts: uint16(reservationPorts),
		state:            StateNew,
		flows:            make(map[*flowHandle]struct{}),
		closed:           make(chan struct{}),
	}, nil
}

func (m *Manager) Tag() string {
	return m.tag
}

func (m *Manager) State() State {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.state
}

// InterfaceIndex returns the physical interface index captured at Start.
func (m *Manager) InterfaceIndex() int {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.interfaceIndex
}

// Start validates the engine version, acquires the outbound port reservations,
// starts the original engine with a manager-composed argv and waits for the
// post-Lua readiness markers. It never falls back to an unowned socket path.
func (m *Manager) Start(ctx context.Context, interfaceIndex int) error {
	if interfaceIndex <= 0 {
		return fmt.Errorf("zapret: outbound %q: invalid physical interface index %d", m.tag, interfaceIndex)
	}
	m.mutex.Lock()
	if m.state != StateNew {
		state := m.state
		m.mutex.Unlock()
		return fmt.Errorf("zapret: outbound %q: cannot start manager in state %s", m.tag, state)
	}
	m.state = StateStarting
	m.interfaceIndex = interfaceIndex
	m.mutex.Unlock()

	engine, err := newPlatformEngine(platformOptions{
		tag:              m.tag,
		profile:          m.profile,
		bindInterface:    m.bindInterface,
		interfaceIndex:   interfaceIndex,
		reservationPorts: m.reservationPorts,
		startupTimeout:   m.startupTimeout,
		stopTimeout:      m.stopTimeout,
		logger:           m.logger,
	})
	if err == nil {
		err = engine.Start(ctx)
	}
	if err != nil {
		if engine != nil {
			closeErr := engine.Close()
			if closeErr != nil {
				err = fmt.Errorf("%w (cleanup: %v)", err, closeErr)
			}
		}
		m.mutex.Lock()
		if m.state == StateStarting {
			m.state = StateFailed
		}
		if m.failure == nil {
			m.failure = err
		}
		m.mutex.Unlock()
		m.closeOnce.Do(func() { close(m.closed) })
		return err
	}
	m.mutex.Lock()
	if m.state != StateStarting {
		state := m.state
		failure := m.failure
		m.mutex.Unlock()
		_ = engine.Close()
		return fmt.Errorf("zapret: outbound %q: start aborted in state %s: %v", m.tag, state, failure)
	}
	m.state = StateReady
	m.engine = engine
	m.mutex.Unlock()
	m.logger.Info("zapret[", m.tag, "]: engine ready on interface ", m.bindInterface, " (", interfaceIndex, ")")
	go m.watchEngine(engine)
	return nil
}

func (m *Manager) watchEngine(engine platformEngine) {
	select {
	case err := <-engine.Exited():
		if err == nil {
			err = errors.New("engine exited unexpectedly")
		}
		m.fail(fmt.Errorf("zapret: outbound %q: original engine stopped: %w", m.tag, err))
	case <-m.closed:
	}
}

// Fail transitions a running manager into the failed state: admission stops,
// owned flows are closed, the child is terminated and reservations are
// released. It is used for unrecoverable events such as a physical interface
// index change.
func (m *Manager) Fail(err error) {
	if err == nil {
		return
	}
	m.fail(err)
}

func (m *Manager) fail(err error) {
	m.mutex.Lock()
	if m.state != StateReady && m.state != StateStarting {
		m.mutex.Unlock()
		return
	}
	m.state = StateFailed
	m.failure = err
	flows := m.detachFlowsLocked()
	engine := m.engine
	m.mutex.Unlock()

	m.logger.Error(err)
	for _, flow := range flows {
		closeErr := flow.Close()
		if closeErr != nil {
			m.logger.Debug("zapret[", m.tag, "]: close owned flow: ", closeErr)
		}
	}
	if engine != nil {
		closeErr := engine.Close()
		if closeErr != nil {
			m.logger.Error(fmt.Errorf("zapret: outbound %q: engine cleanup after failure: %w", m.tag, closeErr))
		}
	}
	m.closeOnce.Do(func() { close(m.closed) })
}

func (m *Manager) CheckAdmission() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	switch m.state {
	case StateReady:
		return nil
	case StateFailed:
		return fmt.Errorf("zapret: outbound %q is failed: %w", m.tag, m.failure)
	default:
		return fmt.Errorf("zapret: outbound %q is not ready (state %s)", m.tag, m.state)
	}
}

func (m *Manager) Control(network string, address string, conn syscall.RawConn) error {
	m.mutex.Lock()
	state := m.state
	failure := m.failure
	engine := m.engine
	m.mutex.Unlock()
	if state != StateReady {
		if state == StateFailed {
			return fmt.Errorf("zapret: outbound %q is failed: %w", m.tag, failure)
		}
		return fmt.Errorf("zapret: outbound %q is not ready (state %s)", m.tag, state)
	}
	if engine == nil {
		return fmt.Errorf("zapret: outbound %q has no engine", m.tag)
	}
	err := engine.Control(network, address, conn)
	if err != nil {
		return fmt.Errorf("zapret: outbound %q: %w", m.tag, err)
	}
	return nil
}

func (m *Manager) TrackConn(conn net.Conn) net.Conn {
	if conn == nil {
		return nil
	}
	handle := m.trackFlow(conn)
	if handle == nil {
		_ = conn.Close()
		return conn
	}
	return &ownedConn{Conn: conn, handle: handle}
}

func (m *Manager) TrackPacketConn(conn net.PacketConn) net.PacketConn {
	if conn == nil {
		return nil
	}
	handle := m.trackFlow(conn)
	if handle == nil {
		_ = conn.Close()
		return conn
	}
	return &ownedPacketConn{PacketConn: conn, handle: handle}
}

func (m *Manager) trackFlow(closer interface{ Close() error }) *flowHandle {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.state != StateReady {
		return nil
	}
	flow := &flowHandle{manager: m, closeFn: closer.Close}
	m.flows[flow] = struct{}{}
	return flow
}

func (m *Manager) removeFlow(flow *flowHandle) {
	m.mutex.Lock()
	delete(m.flows, flow)
	m.mutex.Unlock()
}

func (m *Manager) detachFlowsLocked() []*flowHandle {
	if len(m.flows) == 0 {
		return nil
	}
	flows := make([]*flowHandle, 0, len(m.flows))
	for flow := range m.flows {
		flows = append(flows, flow)
	}
	m.flows = make(map[*flowHandle]struct{})
	return flows
}

// Close implements the normal stop path: admission stops first, owned flows are
// closed, the original engine is terminated and waited for, and only then are
// the port reservation anchors released.
func (m *Manager) Close() error {
	m.mutex.Lock()
	switch m.state {
	case StateClosed:
		m.mutex.Unlock()
		return nil
	case StateFailed:
		m.mutex.Unlock()
		// Failure cleanup already ran (or is running); wait for it.
		<-m.closed
		m.mutex.Lock()
		m.state = StateClosed
		m.mutex.Unlock()
		return nil
	}
	m.state = StateStopping
	flows := m.detachFlowsLocked()
	engine := m.engine
	m.mutex.Unlock()

	var errs []error
	for _, flow := range flows {
		closeErr := flow.Close()
		if closeErr != nil {
			errs = append(errs, fmt.Errorf("close owned flow: %w", closeErr))
		}
	}
	if engine != nil {
		closeErr := engine.Close()
		if closeErr != nil {
			errs = append(errs, closeErr)
		}
	}
	m.closeOnce.Do(func() { close(m.closed) })
	m.mutex.Lock()
	m.state = StateClosed
	m.mutex.Unlock()
	if len(errs) > 0 {
		return fmt.Errorf("zapret: outbound %q: stop reported remaining resources: %w", m.tag, errors.Join(errs...))
	}
	return nil
}

type flowHandle struct {
	manager *Manager
	closeFn func() error
	once    sync.Once
	err     error
}

func (h *flowHandle) Close() error {
	h.once.Do(func() {
		h.manager.removeFlow(h)
		h.err = h.closeFn()
	})
	return h.err
}

type ownedConn struct {
	net.Conn
	handle *flowHandle
}

func (c *ownedConn) Close() error {
	return c.handle.Close()
}

func (c *ownedConn) Upstream() any {
	return c.Conn
}

// SyscallConn preserves the raw socket of the real connection. The immediate
// value is normally a trackedConn or a counter wrapper (implements Upstream,
// not syscall.Conn), so the lookup uses the same upstream-aware traversal as
// sing's raw-socket callers instead of shadowing that capability. Tracking and
// counter wrappers stay in place; only the raw descriptor lookup is forwarded.
// The counter callbacks of a wrapper below this one are forwarded separately by
// UnwrapReader/UnwrapWriter, because raw copying never calls the wrapper's Read
// or Write.
func (c *ownedConn) SyscallConn() (syscall.RawConn, error) {
	if syscallConn, isSyscallConn := common.Cast[syscall.Conn](c.Conn); isSyscallConn {
		return syscallConn.SyscallConn()
	}
	return nil, errors.New("zapret: underlying connection does not expose a raw socket")
}

// UnwrapReader and UnwrapWriter forward the counter protocol used by sing's
// bufio.CounterConn to the inner connection. An active power-report recorder
// puts that counter wrapper below this ownership wrapper, while the raw socket
// lookup above makes splice and vectorised copying eligible. The copy paths
// collect these callbacks before moving bytes through the descriptor, so a
// successful raw copy still reports the inner read/write bytes and activity.
// When no counter wrapper is present both expose the upstream connection
// without callbacks; socket, tracking and Close semantics are unchanged.
func (c *ownedConn) UnwrapReader() (io.Reader, []N.CountFunc) {
	return N.UnwrapCountReader(c.Conn, nil)
}

func (c *ownedConn) UnwrapWriter() (io.Writer, []N.CountFunc) {
	return N.UnwrapCountWriter(c.Conn, nil)
}

func (c *ownedConn) ReaderReplaceable() bool {
	if replaceable, isReplaceable := c.Conn.(interface{ ReaderReplaceable() bool }); isReplaceable {
		return replaceable.ReaderReplaceable()
	}
	return false
}

func (c *ownedConn) WriterReplaceable() bool {
	if replaceable, isReplaceable := c.Conn.(interface{ WriterReplaceable() bool }); isReplaceable {
		return replaceable.WriterReplaceable()
	}
	return false
}

type ownedPacketConn struct {
	net.PacketConn
	handle *flowHandle
}

func (c *ownedPacketConn) Close() error {
	return c.handle.Close()
}

func (c *ownedPacketConn) Upstream() any {
	return c.PacketConn
}

// SyscallConn mirrors ownedConn.SyscallConn for packet connections: the
// tracked wrapper (and the bufio/counter packet wrappers it exposes through
// Upstream) still reach the real UDP socket, so the raw descriptor is resolved
// through the upstream-aware traversal.
func (c *ownedPacketConn) SyscallConn() (syscall.RawConn, error) {
	if syscallConn, isSyscallConn := common.Cast[syscall.Conn](c.PacketConn); isSyscallConn {
		return syscallConn.SyscallConn()
	}
	return nil, errors.New("zapret: underlying packet connection does not expose a raw socket")
}

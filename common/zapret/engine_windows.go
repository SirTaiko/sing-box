//go:build windows

package zapret

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// mstcpip.h: #define SIO_ACQUIRE_PORT_RESERVATION _WSAIOW(IOC_VENDOR, 100)
	// _WSAIOW(x, y) == IOC_IN | x | y == 0x80000000 | 0x18000000 | y.
	sioAcquirePortReservation   = 0x98000064
	sioReleasePortReservation   = 0x98000065
	sioAssociatePortReservation = 0x98000066

	// INET_PORT_RANGE is two USHORTs; INET_PORT_RESERVATION_INSTANCE is that
	// range followed by an aligned ULONG64 token (offset 8, size 16).
	// StartPort uses network byte order in both structures, NumberOfPorts and
	// the token use the native structure layout; see the field comments at the
	// request and the decode sites.
	portRangeSize    = 4
	portInstanceSize = 16
	portTokenOffset  = 8
	portTokenSize    = 8

	winCreateNoWindow = 0x08000000

	requiredVersionPrefix = "github version v1.0.7 ("
	requiredLuaCompat     = "lua_compat_ver 6"

	captureReadinessMarker = "windivert initialized. capture is started."
	luaReadinessMarker     = "LUA INIT DONE"

	versionProbeTimeout = 5 * time.Second
	maxVersionOutput    = 64 * 1024
	outputTailLines     = 24
	// params.h: #define WINDIVERT_MAX 16384, the engine truncates the raw
	// filter at that size, so a longer generated filter is an explicit error.
	maxWindivertFilterLength = 16384 - 1
)

func engineSupported() bool {
	return true
}

var (
	winsockOnce sync.Once
	winsockErr  error
)

// ensureWinsock makes the reservation anchor sockets independent of any
// other package having initialized Winsock. The node is process-wide and is
// intentionally not paired with WSACleanup: the anchors live until shutdown.
func ensureWinsock() error {
	winsockOnce.Do(func() {
		var data syscall.WSAData
		winsockErr = syscall.WSAStartup(0x202, &data)
	})
	return winsockErr
}

type portReservation struct {
	name     string
	protocol string
	ipv6     bool
	start    uint16
	count    uint16
	token    uint64
	handle   syscall.Handle
}

type windowsEngine struct {
	options platformOptions

	reservations []*portReservation
	filter       string

	cmd       *exec.Cmd
	done      chan struct{}
	exitCh    chan error
	closeOnce sync.Once
	closeErr  error

	mutex       sync.Mutex
	waitErr     error
	captureSeen bool
	luaSeen     bool
	tail        []string
	readyOnce   sync.Once
	readyCh     chan struct{}
}

func newPlatformEngine(options platformOptions) (platformEngine, error) {
	return &windowsEngine{
		options: options,
		done:    make(chan struct{}),
		exitCh:  make(chan error, 1),
		readyCh: make(chan struct{}),
	}, nil
}

func (e *windowsEngine) Start(ctx context.Context) error {
	version, err := e.probeVersion()
	if err != nil {
		return err
	}
	e.options.logger.Debug("zapret[", e.options.tag, "]: engine version: ", version)
	err = e.acquireReservations()
	if err != nil {
		return err
	}
	e.filter = e.buildFilter()
	if len(e.filter) >= maxWindivertFilterLength {
		filterErr := fmt.Errorf("zapret: outbound %q: generated WinDivert filter is %d bytes, engine limit is %d", e.options.tag, len(e.filter), maxWindivertFilterLength)
		if releaseErr := e.releaseReservations(); releaseErr != nil {
			filterErr = fmt.Errorf("%w; cleanup: %v", filterErr, releaseErr)
		}
		return filterErr
	}
	e.options.logger.Info("zapret[", e.options.tag, "]: reserved ", e.describeReservations(), " on interface ", e.options.bindInterface, " (", e.options.interfaceIndex, "), capture priority 0")
	e.options.logger.Debug("zapret[", e.options.tag, "]: winws2 filter: ", e.filter)
	arguments := e.arguments()
	e.cmd = exec.Command(e.options.profile.executable, arguments...)
	e.cmd.Dir = e.options.profile.strategyDir
	e.cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: winCreateNoWindow}
	writer := &lineWriter{onLine: e.handleLine}
	e.cmd.Stdout = writer
	e.cmd.Stderr = writer
	err = e.cmd.Start()
	if err != nil {
		startErr := fmt.Errorf("zapret: outbound %q: start original engine %q: %w", e.options.tag, e.options.profile.executable, err)
		if releaseErr := e.releaseReservations(); releaseErr != nil {
			startErr = fmt.Errorf("%w; cleanup: %v", startErr, releaseErr)
		}
		return startErr
	}
	go func() {
		waitErr := e.cmd.Wait()
		e.mutex.Lock()
		e.waitErr = waitErr
		e.mutex.Unlock()
		close(e.done)
		e.exitCh <- waitErr
		close(e.exitCh)
	}()
	select {
	case <-e.readyCh:
		return nil
	case <-e.done:
		return fmt.Errorf("zapret: outbound %q: original engine exited before readiness: %v; output: %s", e.options.tag, e.waitError(), e.outputTail())
	case <-time.After(e.options.startupTimeout):
		return fmt.Errorf("zapret: outbound %q: original engine did not reach Lua readiness within %s; output: %s", e.options.tag, e.options.startupTimeout, e.outputTail())
	case <-ctx.Done():
		return fmt.Errorf("zapret: outbound %q: original engine startup canceled: %w", e.options.tag, ctx.Err())
	}
}

func (e *windowsEngine) probeVersion() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), versionProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, e.options.profile.executable, "--version")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: winCreateNoWindow}
	output, err := cmd.CombinedOutput()
	if len(output) > maxVersionOutput {
		output = output[:maxVersionOutput]
	}
	text := strings.TrimSpace(string(output))
	if err != nil {
		return "", fmt.Errorf("zapret: outbound %q: version probe of %q failed: %w; output: %q", e.options.tag, e.options.profile.executable, err, text)
	}
	if !strings.HasPrefix(text, requiredVersionPrefix) || !strings.Contains(text, requiredLuaCompat) {
		return "", fmt.Errorf("zapret: outbound %q: unsupported engine %q: expected %q with %q, got %q", e.options.tag, e.options.profile.executable, requiredVersionPrefix, requiredLuaCompat, text)
	}
	return text, nil
}

func (e *windowsEngine) acquireReservations() error {
	if err := ensureWinsock(); err != nil {
		return fmt.Errorf("zapret: outbound %q: initialize Winsock: %w", e.options.tag, err)
	}
	specifications := []struct {
		name     string
		protocol string
		family   int
		sockType int
		proto    int
		ipv6     bool
	}{
		{"tcp4", "tcp", syscall.AF_INET, syscall.SOCK_STREAM, 6, false},
		{"tcp6", "tcp", syscall.AF_INET6, syscall.SOCK_STREAM, 6, true},
		{"udp4", "udp", syscall.AF_INET, syscall.SOCK_DGRAM, 17, false},
		{"udp6", "udp", syscall.AF_INET6, syscall.SOCK_DGRAM, 17, true},
	}
	reservations := make([]*portReservation, 0, len(specifications))
	for _, specification := range specifications {
		reservation, err := acquirePortReservation(specification.name, specification.protocol, specification.family, specification.sockType, specification.proto, specification.ipv6, e.options.reservationPorts)
		if err != nil {
			_ = releaseReservations(reservations)
			return fmt.Errorf("zapret: outbound %q: %w", e.options.tag, err)
		}
		reservations = append(reservations, reservation)
	}
	if err := validatePortReservationUnion(reservations); err != nil {
		_ = releaseReservations(reservations)
		return fmt.Errorf("zapret: outbound %q: %w", e.options.tag, err)
	}
	e.reservations = reservations
	return nil
}

func acquirePortReservation(name string, protocol string, family int, sockType int, proto int, ipv6 bool, requested uint16) (*portReservation, error) {
	handle, err := syscall.Socket(family, sockType, proto)
	if err != nil {
		return nil, fmt.Errorf("create %s reservation anchor socket: %w", name, err)
	}
	input := make([]byte, portRangeSize)
	// INET_PORT_RANGE.StartPort is in network byte order in the request too:
	// the official sample stores htons(startPort). A zero StartPort asks for a
	// wildcard runtime reservation from the OS.
	binary.BigEndian.PutUint16(input[0:2], 0)
	// NumberOfPorts is a plain host-order count.
	binary.LittleEndian.PutUint16(input[2:4], requested)
	output := make([]byte, portInstanceSize)
	var returned uint32
	err = syscall.WSAIoctl(handle, sioAcquirePortReservation, &input[0], uint32(len(input)), &output[0], uint32(len(output)), &returned, nil, 0)
	if err != nil {
		_ = syscall.Closesocket(handle)
		return nil, fmt.Errorf("SIO_ACQUIRE_PORT_RESERVATION for %s failed: %w (requires Windows Vista or later; runtime reservations are per process)", name, err)
	}
	if returned < portInstanceSize {
		_ = syscall.Closesocket(handle)
		return nil, fmt.Errorf("SIO_ACQUIRE_PORT_RESERVATION for %s returned %d bytes, expected %d", name, returned, portInstanceSize)
	}
	reservation := &portReservation{
		name:     name,
		protocol: protocol,
		ipv6:     ipv6,
		// Only StartPort is in network byte order in the returned
		// INET_PORT_RESERVATION_INSTANCE; NumberOfPorts and the token keep the
		// native structure layout.
		start:  binary.BigEndian.Uint16(output[0:2]),
		count:  binary.LittleEndian.Uint16(output[2:4]),
		token:  binary.LittleEndian.Uint64(output[portTokenOffset : portTokenOffset+portTokenSize]),
		handle: handle,
	}
	if err := reservation.validate(requested); err != nil {
		_ = syscall.Closesocket(handle)
		return nil, fmt.Errorf("SIO_ACQUIRE_PORT_RESERVATION for %s returned an invalid reservation: %w", name, err)
	}
	return reservation, nil
}

// end returns the last port of the reservation. validate guarantees that the
// value fits into the port space before end is called.
func (r *portReservation) end() uint32 {
	return uint32(r.start) + uint32(r.count) - 1
}

// validate rejects an OS answer that cannot describe a single usable port block
// or that would silently widen the generated capture filter beyond the size the
// outbound asked for.
func (r *portReservation) validate(requested uint16) error {
	if r.token == 0 {
		return errors.New("zero reservation token")
	}
	if r.start == 0 {
		return errors.New("start port 0 (port 0 is not assignable and a zero lower bound would match every port)")
	}
	if r.count == 0 {
		return fmt.Errorf("empty range at start port %d", r.start)
	}
	if r.count > requested {
		return fmt.Errorf("range %d-%d contains %d ports, more than the %d requested", r.start, r.end(), r.count, requested)
	}
	if r.end() > 65535 {
		return fmt.Errorf("range %d+%d wraps past the last port 65535", r.start, r.count)
	}
	return nil
}

// validatePortReservationUnion rejects same-protocol reservations that overlap.
// The generated WinDivert filter unions the IPv4 and IPv6 ranges of one protocol
// (tcp.SrcPort, tcp.DstPort and the UDP fields are family independent), so an
// overlapping OS answer would make the engine capture ports outside its own
// reservation. TCP and UDP predicates are separate and may legitimately share a
// port, so a cross-protocol match is not a defect.
func validatePortReservationUnion(reservations []*portReservation) error {
	for _, protocol := range []string{"tcp", "udp"} {
		for index, left := range reservations {
			if left.protocol != protocol {
				continue
			}
			for _, right := range reservations[index+1:] {
				if right.protocol != protocol {
					continue
				}
				if uint32(left.start) <= right.end() && uint32(right.start) <= left.end() {
					return fmt.Errorf("%s reservations %s=%d-%d and %s=%d-%d overlap; the generated filter unions IPv4 and IPv6 for one protocol", protocol, left.name, left.start, left.end(), right.name, right.start, right.end())
				}
			}
		}
	}
	return nil
}

func (e *windowsEngine) releaseReservations() error {
	err := releaseReservations(e.reservations)
	e.reservations = nil
	return err
}

func releaseReservations(reservations []*portReservation) error {
	var errs []error
	for _, reservation := range reservations {
		if reservation == nil || reservation.handle == 0 {
			continue
		}
		err := syscall.Closesocket(reservation.handle)
		if err != nil {
			errs = append(errs, fmt.Errorf("remaining %s reservation anchor %d: %w", reservation.name, reservation.start, err))
		}
		reservation.handle = 0
	}
	return errors.Join(errs...)
}

func (e *windowsEngine) reservationFor(network string, address string) (*portReservation, error) {
	base := network
	ipv6Known := false
	ipv6 := false
	if strings.HasSuffix(base, "4") {
		base = strings.TrimSuffix(base, "4")
		ipv6Known = true
	} else if strings.HasSuffix(base, "6") {
		base = strings.TrimSuffix(base, "6")
		ipv6Known = true
		ipv6 = true
	}
	if base != "tcp" && base != "udp" {
		return nil, fmt.Errorf("unsupported socket network %q for port reservation association", network)
	}
	if !ipv6Known {
		host, _, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			host = address
		}
		host = strings.Trim(host, "[]")
		parsed, parseErr := netip.ParseAddr(host)
		if parseErr != nil {
			return nil, fmt.Errorf("cannot determine socket family for %q %q", network, address)
		}
		ipv6 = parsed.Is6()
	}
	for _, reservation := range e.reservations {
		if reservation.protocol == base && reservation.ipv6 == ipv6 {
			return reservation, nil
		}
	}
	return nil, fmt.Errorf("no %s reservation for socket network %q", base, network)
}

func (e *windowsEngine) Control(network string, address string, conn syscall.RawConn) error {
	reservation, err := e.reservationFor(network, address)
	if err != nil {
		return err
	}
	token := make([]byte, portTokenSize)
	binary.LittleEndian.PutUint64(token, reservation.token)
	var associateErr error
	controlErr := conn.Control(func(fd uintptr) {
		var returned uint32
		associateErr = syscall.WSAIoctl(syscall.Handle(fd), sioAssociatePortReservation, &token[0], uint32(len(token)), nil, 0, &returned, nil, 0)
	})
	if controlErr != nil {
		return fmt.Errorf("raw socket control for %s reservation association: %w", reservation.name, controlErr)
	}
	if associateErr != nil {
		return fmt.Errorf("SIO_ASSOCIATE_PORT_RESERVATION %s before bind: %w", reservation.name, associateErr)
	}
	return nil
}

func (e *windowsEngine) buildFilter() string {
	tcpSource := portRangePredicate("tcp.SrcPort", e.reservationsFor("tcp"))
	udpSource := portRangePredicate("udp.SrcPort", e.reservationsFor("udp"))
	tcpDestination := portRangePredicate("tcp.DstPort", e.reservationsFor("tcp"))
	udpDestination := portRangePredicate("udp.DstPort", e.reservationsFor("udp"))
	return fmt.Sprintf(
		"!impostor and !loopback and ifIdx == %d and subIfIdx == 0 and ((outbound and ((%s) or (%s))) or (inbound and ((%s) or (%s))))",
		e.options.interfaceIndex,
		tcpSource, udpSource,
		tcpDestination, udpDestination,
	)
}

func (e *windowsEngine) reservationsFor(protocol string) []*portReservation {
	var reservations []*portReservation
	for _, reservation := range e.reservations {
		if reservation.protocol == protocol {
			reservations = append(reservations, reservation)
		}
	}
	return reservations
}

func portRangePredicate(field string, reservations []*portReservation) string {
	var clauses []string
	for _, reservation := range reservations {
		clauses = append(clauses, fmt.Sprintf("(%s >= %d and %s <= %d)", field, reservation.start, field, reservation.end()))
	}
	return strings.Join(clauses, " or ")
}

func (e *windowsEngine) arguments() []string {
	arguments := []string{
		"--debug=1",
		"--intercept=1",
		"--wf-priority=0",
		"--wf-raw=" + e.filter,
	}
	return append(arguments, e.options.profile.tokens...)
}

func (e *windowsEngine) describeReservations() string {
	parts := make([]string, 0, len(e.reservations))
	for _, reservation := range e.reservations {
		parts = append(parts, fmt.Sprintf("%s=%d-%d", reservation.name, reservation.start, reservation.end()))
	}
	return strings.Join(parts, ",")
}

func (e *windowsEngine) handleLine(line string) {
	trimmed := strings.TrimSpace(line)
	if trimmed != "" {
		e.options.logger.Debug("zapret[", e.options.tag, "]: ", trimmed)
	}
	e.mutex.Lock()
	if trimmed != "" {
		e.tail = append(e.tail, trimmed)
		if len(e.tail) > outputTailLines {
			e.tail = e.tail[len(e.tail)-outputTailLines:]
		}
	}
	captureSeen := e.captureSeen
	luaSeen := e.luaSeen
	if strings.Contains(trimmed, captureReadinessMarker) {
		e.captureSeen = true
		captureSeen = true
	}
	if strings.Contains(trimmed, luaReadinessMarker) {
		e.luaSeen = true
		luaSeen = true
	}
	e.mutex.Unlock()
	if captureSeen && luaSeen {
		e.readyOnce.Do(func() { close(e.readyCh) })
	}
}

func (e *windowsEngine) outputTail() string {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	if len(e.tail) == 0 {
		return "<no output>"
	}
	return strings.Join(e.tail, " | ")
}

func (e *windowsEngine) waitError() error {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	return e.waitErr
}

func (e *windowsEngine) Exited() <-chan error {
	return e.exitCh
}

func (e *windowsEngine) Close() error {
	e.closeOnce.Do(func() {
		var errs []error
		if e.cmd != nil && e.cmd.Process != nil {
			killErr := e.cmd.Process.Kill()
			if killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
				e.options.logger.Debug("zapret[", e.options.tag, "]: terminate engine: ", killErr)
			}
			select {
			case <-e.done:
			case <-time.After(e.options.stopTimeout):
				errs = append(errs, fmt.Errorf("zapret: outbound %q: original engine did not exit within %s", e.options.tag, e.options.stopTimeout))
			}
			waitErr := e.waitError()
			if waitErr != nil && !isExpectedTermination(waitErr) {
				e.options.logger.Debug("zapret[", e.options.tag, "]: engine exit: ", waitErr)
			}
		}
		errs = append(errs, e.releaseReservations())
		e.closeErr = errors.Join(errs...)
	})
	return e.closeErr
}

func isExpectedTermination(err error) bool {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return true
	}
	return errors.Is(err, os.ErrProcessDone)
}

type lineWriter struct {
	mutex  sync.Mutex
	buffer []byte
	onLine func(line string)
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.buffer = append(w.buffer, p...)
	for {
		index := bytes.IndexByte(w.buffer, '\n')
		if index < 0 {
			break
		}
		line := string(w.buffer[:index])
		w.buffer = w.buffer[index+1:]
		if w.onLine != nil {
			w.onLine(line)
		}
	}
	if len(w.buffer) > 8192 {
		w.buffer = w.buffer[len(w.buffer)-4096:]
	}
	return len(p), nil
}

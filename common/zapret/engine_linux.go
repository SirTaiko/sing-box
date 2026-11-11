//go:build linux

package zapret

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// generatedMark is the original engine's default fwmark for packets it
	// generates (nfqws2 --fwmark, default 0x40000000). Owner marks keep this
	// bit clear, so the output notrack rule can recognise generated packets
	// and the exact outbound mark never matches one.
	generatedMark uint32 = 0x40000000
	// ownerMarkBase is combined with the ownership queue number to form the
	// per-outbound socket mark: O_i = ownerMarkBase | Q_i. The base keeps O_i
	// non-zero and O_i & generatedMark == 0.
	ownerMarkBase uint32 = 0x20000000
	// linuxQueueBase and linuxQueueCount bound the finite ownership queue
	// pool. One queue number and one mark are allocated per zapret outbound;
	// the values are never chosen by a profile.
	linuxQueueBase  = 10000
	linuxQueueCount = 64

	// requiredVersionPrefix and requiredLuaCompat pin the original release
	// this slice was designed and verified against.
	requiredVersionPrefix = "github version v1.0.7 ("
	requiredLuaCompat     = "lua_compat_ver 6"

	versionProbeTimeout = 5 * time.Second
	maxVersionOutput    = 64 * 1024
	outputTailLines     = 24
	pidfilePollInterval = 50 * time.Millisecond
	maxPidfileSize      = 64
)

// interfaceNamePattern accepts only characters that are valid in a Linux
// interface name and that cannot break the generated nftables script. The
// kernel limit is IFNAMSIZ-1 = 15 bytes.
var interfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

func engineSupported() bool {
	return true
}

type linuxEngine struct {
	options platformOptions

	mark    uint32
	queue   int
	table   string
	nftPath string

	// tableInstalled records a successful atomic nft transaction so shutdown
	// only ever attempts to delete a table this engine created.
	tableInstalled bool

	cmd        *exec.Cmd
	pidfileDir string
	pidfile    string

	done      chan struct{}
	exitCh    chan error
	closeOnce sync.Once
	closeErr  error

	stopping atomic.Bool

	mutex   sync.Mutex
	waitErr error
	tail    []string
}

var (
	linuxQueueMutex sync.Mutex
	linuxQueueUsed  = make(map[int]struct{})
)

func newPlatformEngine(options platformOptions) (platformEngine, error) {
	return &linuxEngine{
		options: options,
		done:    make(chan struct{}),
		exitCh:  make(chan error, 1),
	}, nil
}

// Start verifies the original release, allocates the per-outbound queue and
// mark, starts the engine without --daemon and waits for the pidfile the
// original binary writes after Lua initialization and NFQUEUE binding. Only
// then is the ownership nft table installed atomically and the manager allowed
// to create sockets.
func (e *linuxEngine) Start(ctx context.Context) error {
	version, err := e.probeVersion()
	if err != nil {
		return err
	}
	e.options.logger.Debug("zapret[", e.options.tag, "]: engine version: ", version)
	err = e.verifyInterface()
	if err != nil {
		return err
	}
	nftPath, err := exec.LookPath("nft")
	if err != nil {
		return fmt.Errorf("zapret: outbound %q: the nftables user space tool `nft` is required to own the NFQUEUE rules: %w", e.options.tag, err)
	}
	e.nftPath = nftPath
	e.table = tableNameFor(e.options.tag)
	state, err := e.readNftState(ctx)
	if err != nil {
		return err
	}
	if state.tableExists("inet", e.table) {
		return fmt.Errorf("zapret: outbound %q: nft table %q already exists; it was left by an earlier unclean stop and is never overwritten, reflushed or replaced by a different queue; remove it manually with `nft delete table inet %s` before starting again", e.options.tag, e.table, e.table)
	}
	err = e.allocateQueue(state)
	if err != nil {
		return err
	}
	pidfileDir, err := os.MkdirTemp("", "sing-box-zapret-")
	if err != nil {
		return fmt.Errorf("zapret: outbound %q: create the engine runtime directory: %w", e.options.tag, err)
	}
	e.pidfileDir = pidfileDir
	e.pidfile = filepath.Join(pidfileDir, "nfqws2.pid")
	arguments := e.arguments()
	e.options.logger.Debug("zapret[", e.options.tag, "]: nfqws2 argv: ", strings.Join(arguments, " "))
	e.cmd = exec.Command(e.options.profile.executable, arguments...)
	e.cmd.Dir = e.options.profile.strategyDir
	writer := &linuxLineWriter{onLine: e.handleLine}
	e.cmd.Stdout = writer
	e.cmd.Stderr = writer
	err = e.cmd.Start()
	if err != nil {
		return fmt.Errorf("zapret: outbound %q: start original engine %q: %w", e.options.tag, e.options.profile.executable, err)
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
	err = e.waitReady(ctx)
	if err != nil {
		return err
	}
	err = e.installTable(ctx)
	if err != nil {
		return err
	}
	e.tableInstalled = true
	err = e.verifyTable(ctx)
	if err != nil {
		return err
	}
	e.options.logger.Info("zapret[", e.options.tag, "]: linux ownership ready: mark 0x", fmt.Sprintf("%08x", e.mark), " queue ", e.queue, " table ", e.table, " interface ", e.options.bindInterface, " (", e.options.interfaceIndex, "), generated mark 0x", fmt.Sprintf("%08x", generatedMark))
	return nil
}

func (e *linuxEngine) probeVersion() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), versionProbeTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, e.options.profile.executable, "--version").CombinedOutput()
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

// verifyInterface re-reads the physical interface and requires the same index
// the manager resolved. An interface rename or index change must not silently
// continue with an ownership table that points at the wrong device.
func (e *linuxEngine) verifyInterface() error {
	if !interfaceNamePattern.MatchString(e.options.bindInterface) {
		return fmt.Errorf("zapret: outbound %q: bind_interface %q contains characters that are not supported in a Linux interface name", e.options.tag, e.options.bindInterface)
	}
	networkInterface, err := net.InterfaceByName(e.options.bindInterface)
	if err != nil {
		return fmt.Errorf("zapret: outbound %q: bind_interface %q: %w", e.options.tag, e.options.bindInterface, err)
	}
	if networkInterface.Index != e.options.interfaceIndex {
		return fmt.Errorf("zapret: outbound %q: bind_interface %q index changed from %d to %d; refusing to install an ownership table for a stale egress", e.options.tag, e.options.bindInterface, e.options.interfaceIndex, networkInterface.Index)
	}
	return nil
}

// allocateQueue picks the first free queue number of the finite process pool.
// A candidate is skipped when the queue or the derived mark is already used by
// an existing nftables rule, when another process has the queue bound, or when
// this process already allocated it. Nothing foreign is modified; exhaustion
// or a name conflict is an explicit error.
func (e *linuxEngine) allocateQueue(state *nftState) error {
	boundQueues := readBoundNfqueues()
	linuxQueueMutex.Lock()
	defer linuxQueueMutex.Unlock()
	for queue := linuxQueueBase; queue < linuxQueueBase+linuxQueueCount; queue++ {
		mark := ownerMarkBase | uint32(queue)
		if _, used := linuxQueueUsed[queue]; used {
			e.options.logger.Debug("zapret[", e.options.tag, "]: ownership queue ", queue, " is already allocated in this process")
			continue
		}
		usedByRule, err := state.queueUsed(queue)
		if err != nil {
			return fmt.Errorf("zapret: outbound %q: %w", e.options.tag, err)
		}
		if usedByRule {
			e.options.logger.Debug("zapret[", e.options.tag, "]: ownership queue ", queue, " is referenced by an existing nftables rule")
			continue
		}
		if _, used := boundQueues[queue]; used {
			e.options.logger.Debug("zapret[", e.options.tag, "]: ownership queue ", queue, " is already bound by a process")
			continue
		}
		if state.markUsed(mark) {
			e.options.logger.Debug("zapret[", e.options.tag, "]: ownership mark 0x", fmt.Sprintf("%08x", mark), " is selected by an existing nftables rule")
			continue
		}
		linuxQueueUsed[queue] = struct{}{}
		e.queue = queue
		e.mark = mark
		return nil
	}
	return fmt.Errorf("zapret: outbound %q: no free ownership queue in %d..%d: every candidate queue or mark is already used by an existing nftables rule, a bound queue or another outbound of this process", e.options.tag, linuxQueueBase, linuxQueueBase+linuxQueueCount-1)
}

func (e *linuxEngine) releaseQueue() {
	if e.queue == 0 {
		return
	}
	linuxQueueMutex.Lock()
	delete(linuxQueueUsed, e.queue)
	linuxQueueMutex.Unlock()
}

// readBoundNfqueues returns the queue numbers already bound by user space
// processes. The file exists only when the nfnetlink_queue module is loaded;
// an unreadable file means no queue can be bound here, and the per-rule scan
// above plus the child's own bind failure still protect the invariant.
func readBoundNfqueues() map[int]struct{} {
	content, err := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
	if err != nil {
		return nil
	}
	queues := make(map[int]struct{})
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		queue, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		queues[queue] = struct{}{}
	}
	return queues
}

func (e *linuxEngine) arguments() []string {
	arguments := []string{
		"--debug=1",
		"--intercept=1",
		"--qnum=" + strconv.Itoa(e.queue),
		"--fwmark=" + fmt.Sprintf("0x%08x", generatedMark),
		"--pidfile=" + e.pidfile,
		"--bind-fix4",
		"--bind-fix6",
	}
	return append(arguments, e.options.profile.tokens...)
}

// waitReady waits for the fresh non-empty pidfile the original binary writes
// after Lua initialization and NFQUEUE binding. A partial write is tolerated by
// waiting while the content is a prefix of the expected child pid.
func (e *linuxEngine) waitReady(ctx context.Context) error {
	childPID := e.cmd.Process.Pid
	timeout := time.NewTimer(e.options.startupTimeout)
	defer timeout.Stop()
	ticker := time.NewTicker(pidfilePollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-e.done:
			return fmt.Errorf("zapret: outbound %q: original engine exited before reporting Lua/NFQUEUE readiness: %v; output: %s", e.options.tag, e.waitError(), e.outputTail())
		case <-timeout.C:
			return fmt.Errorf("zapret: outbound %q: original engine did not report Lua/NFQUEUE readiness within %s (pidfile %q); output: %s", e.options.tag, e.options.startupTimeout, e.pidfile, e.outputTail())
		case <-ctx.Done():
			return fmt.Errorf("zapret: outbound %q: original engine startup canceled: %w; output: %s", e.options.tag, ctx.Err(), e.outputTail())
		case <-ticker.C:
			ready, err := e.pidfileReady(childPID)
			if err != nil {
				return fmt.Errorf("zapret: outbound %q: %w", e.options.tag, err)
			}
			if ready {
				return nil
			}
		}
	}
}

func (e *linuxEngine) pidfileReady(childPID int) (bool, error) {
	info, err := os.Stat(e.pidfile)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect readiness pidfile %q: %w", e.pidfile, err)
	}
	if info.Size() > maxPidfileSize {
		return false, fmt.Errorf("readiness pidfile %q is unexpectedly large (%d bytes)", e.pidfile, info.Size())
	}
	content, err := os.ReadFile(e.pidfile)
	if err != nil {
		return false, fmt.Errorf("read readiness pidfile %q: %w", e.pidfile, err)
	}
	text := strings.TrimSpace(string(content))
	if text == "" {
		return false, nil
	}
	pid, parseErr := strconv.Atoi(text)
	if parseErr != nil {
		return false, fmt.Errorf("readiness pidfile %q contains %q instead of a pid", e.pidfile, text)
	}
	if pid == childPID {
		return true, nil
	}
	if strings.HasPrefix(strconv.Itoa(childPID), text) {
		// The file is still being written, one digit at a time.
		return false, nil
	}
	return false, fmt.Errorf("readiness pidfile %q contains pid %d, but the engine child is pid %d", e.pidfile, pid, childPID)
}

// Control applies the unique owner mark to every real TCP and UDP socket
// before bind/connect. An existing foreign mark is reported, never silently
// overwritten.
func (e *linuxEngine) Control(network string, address string, conn syscall.RawConn) error {
	base := network
	switch {
	case strings.HasSuffix(base, "4"), strings.HasSuffix(base, "6"):
		base = base[:len(base)-1]
	}
	if base != "tcp" && base != "udp" {
		return fmt.Errorf("unsupported socket network %q: zapret ownership covers TCP and UDP only", network)
	}
	if e.stopping.Load() {
		return errors.New("the zapret engine is stopping")
	}
	if e.mark == 0 {
		return errors.New("the zapret engine has no ownership mark yet")
	}
	var operationErr error
	rawErr := conn.Control(func(fd uintptr) {
		current, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK)
		if err != nil {
			operationErr = fmt.Errorf("read the existing socket mark: %w (CAP_NET_ADMIN is required)", err)
			return
		}
		if current != 0 {
			if uint32(current) == e.mark {
				return
			}
			operationErr = fmt.Errorf("socket already carries SO_MARK 0x%08x; refusing to overwrite it with the zapret ownership mark 0x%08x (remove routing_mark/protect_path/auto_redirect from this outbound)", uint32(current), e.mark)
			return
		}
		err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(e.mark))
		if err != nil {
			operationErr = fmt.Errorf("set the ownership SO_MARK 0x%08x before bind/connect: %w (CAP_NET_ADMIN is required)", e.mark, err)
		}
	})
	if rawErr != nil {
		return fmt.Errorf("raw socket control: %w", rawErr)
	}
	return operationErr
}

func (e *linuxEngine) Exited() <-chan error {
	return e.exitCh
}

// Close implements the normal stop path: admission is already closed by the
// manager, the child is terminated and waited for, then only the managed nft
// table and runtime pidfile directory are removed. Leftovers are reported.
func (e *linuxEngine) Close() error {
	e.closeOnce.Do(func() {
		e.stopping.Store(true)
		var errs []error
		if e.cmd != nil && e.cmd.Process != nil {
			signalErr := e.cmd.Process.Signal(syscall.SIGTERM)
			if signalErr != nil && !errors.Is(signalErr, os.ErrProcessDone) {
				e.options.logger.Debug("zapret[", e.options.tag, "]: terminate engine: ", signalErr)
			}
			select {
			case <-e.done:
			case <-time.After(e.options.stopTimeout):
				killErr := e.cmd.Process.Kill()
				if killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
					errs = append(errs, fmt.Errorf("zapret: outbound %q: kill original engine pid %d: %w", e.options.tag, e.cmd.Process.Pid, killErr))
				}
				select {
				case <-e.done:
				case <-time.After(e.options.stopTimeout):
					errs = append(errs, fmt.Errorf("zapret: outbound %q: original engine pid %d did not exit within %s after SIGKILL", e.options.tag, e.cmd.Process.Pid, e.options.stopTimeout))
				}
			}
			if waitErr := e.waitError(); waitErr != nil && !linuxExpectedTermination(waitErr) {
				e.options.logger.Debug("zapret[", e.options.tag, "]: engine exit: ", waitErr)
			}
		}
		if e.tableInstalled {
			removeErr := e.removeTable(context.Background())
			if removeErr != nil {
				errs = append(errs, removeErr)
			} else {
				e.tableInstalled = false
			}
		}
		if e.pidfileDir != "" {
			removeErr := os.RemoveAll(e.pidfileDir)
			if removeErr != nil {
				errs = append(errs, fmt.Errorf("zapret: outbound %q: remove engine runtime directory %q: %w", e.options.tag, e.pidfileDir, removeErr))
			}
		}
		e.releaseQueue()
		e.closeErr = errors.Join(errs...)
	})
	return e.closeErr
}

func linuxExpectedTermination(err error) bool {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return true
	}
	return errors.Is(err, os.ErrProcessDone)
}

func (e *linuxEngine) handleLine(line string) {
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
	e.mutex.Unlock()
}

func (e *linuxEngine) outputTail() string {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	if len(e.tail) == 0 {
		return "<no output>"
	}
	return strings.Join(e.tail, " | ")
}

func (e *linuxEngine) waitError() error {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	return e.waitErr
}

// tableNameFor derives the single managed table name from the outbound tag.
// The name is stable across restarts, so a stale table is detected instead of
// silently accumulating one table per run.
func tableNameFor(tag string) string {
	var builder strings.Builder
	for _, character := range strings.ToLower(tag) {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			builder.WriteRune(character)
		} else {
			builder.WriteByte('_')
		}
	}
	name := builder.String()
	if len(name) > 40 {
		name = name[:40]
	}
	if name == "" {
		name = "outbound"
	}
	return "sb_zapret_" + name
}

type linuxLineWriter struct {
	mutex  sync.Mutex
	buffer []byte
	onLine func(line string)
}

func (w *linuxLineWriter) Write(p []byte) (int, error) {
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

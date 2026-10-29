//go:build desync_windows_model && !windows

package direct

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/desync"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/windivert"
	"github.com/sagernet/sing-box/option"
)

type receivePressureRaw struct {
	write   func(func(uintptr) bool) error
	control atomic.Int32
}

func (r *receivePressureRaw) Write(f func(uintptr) bool) error { return r.write(f) }
func (r *receivePressureRaw) Read(f func(uintptr) bool) error  { f(7); return nil }
func (r *receivePressureRaw) Control(f func(uintptr)) error    { r.control.Add(1); f(7); return nil }

type receivePressureSocket struct {
	receiveModelConn
	raw syscall.RawConn
}

func (s *receivePressureSocket) SyscallConn() (syscall.RawConn, error) { return s.raw, nil }
func (s *receivePressureSocket) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("not used")
}
func (s *receivePressureSocket) WriteTo(p []byte, _ net.Addr) (int, error) { return s.Write(p) }
func pressureWait(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
		runtime.Gosched()
	}
}

func TestWindowsReceivePressureReturnedAndCachedMultiSend(t *testing.T) {
	var opt option.DirectDesyncOptions
	if err := json.Unmarshal([]byte(`{"enabled":true,"limits":{"max_leases":1},"rules":[{"network":["udp"],"methods":["fake"],"fake":{"repeats":1,"payloads":[{"protocol":"unknown","hex":"ab"}]}}]}`), &opt); err != nil {
		t.Fatal(err)
	}
	cfg, err := desync.Compile(&opt, "")
	if err != nil {
		t.Fatal(err)
	}
	input := make(chan byte, 300)
	receivePermit := make(chan struct{})
	entered, sendRelease, writerRelease := make(chan struct{}), make(chan struct{}), make(chan struct{})
	stopped, nativeDone := make(chan struct{}), make(chan struct{})
	var receiveOnce, enterOnce, stopOnce, doneOnce, sendOnce, writerOnce sync.Once
	unblockSend := func() { sendOnce.Do(func() { close(sendRelease) }) }
	unblockWriter := func() { writerOnce.Do(func() { close(writerRelease) }) }
	defer unblockSend()
	defer unblockWriter()
	var receives, sends, shutdowns, syscalls atomic.Int32
	h := &windivert.Handle{RecvFunc: func(p []byte) (int, windivert.Address, error) {
		receiveOnce.Do(func() { <-receivePermit })
		select {
		case b := <-input:
			p[0] = b
			receives.Add(1)
			return 1, windivert.Address{}, nil
		default:
			select {
			case b := <-input:
				p[0] = b
				receives.Add(1)
				return 1, windivert.Address{}, nil
			case <-stopped:
				return 0, windivert.Address{}, windivert.ReplayDrained
			}
		}
	}, SendFunc: func(p []byte, _ *windivert.Address) (int, error) {
		enterOnce.Do(func() { close(entered); <-sendRelease })
		sends.Add(1)
		return len(p), nil
	}, ShutdownFunc: func() error { shutdowns.Add(1); stopOnce.Do(func() { close(stopped) }); return nil }, CloseFunc: func() error { doneOnce.Do(func() { close(nativeDone) }); return nil }, DoneChan: nativeDone}
	windivert.ReplayOpen = func(*windivert.Filter, windivert.Layer, int16, windivert.Flag) (*windivert.Handle, error) {
		return h, nil
	}
	defer func() { windivert.ReplayOpen = nil }()
	e, err := desync.NewEngine(cfg, desync.NewWindowsReplayBackend())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { unblockSend(); unblockWriter(); _ = e.Close() }()
	l, err := e.NewAttempt(desync.Intent{Family: desync.FamilyIPv4, Transport: desync.TransportUDP, Source: netip.MustParseAddrPort("192.0.2.10:40000")})
	if err != nil {
		t.Fatal(err)
	}
	l.SetLocalAddress(netip.MustParseAddrPort("192.0.2.10:40000"))
	if err = l.StartCapture(); err != nil {
		t.Fatal(err)
	}
	nativeResult := errors.New("actual modeled RawConn return")
	partialResult := errors.New("actual bypass partial result")
	raw := &receivePressureRaw{write: func(f func(uintptr) bool) error {
		syscalls.Add(1)
		if !f(7) {
			t.Error("callback unexpectedly requested retry")
		}
		return nativeResult
	}}
	socket := &receivePressureSocket{raw: raw}
	socket.write = func(p []byte) (int, error) {
		syscalls.Add(1)
		if string(p) == "bypass" {
			return 2, partialResult
		}
		input <- 0xf3
		return len(p), nil
	}
	bridge := &desyncLease{lease: l, ctx: context.Background(), intent: dialer.AttemptIntent{Network: "udp"}}
	returned, err := bridge.AttachConn(socket)
	if err != nil {
		t.Fatal(err)
	}
	cached, err := returned.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if n, x := returned.Write([]byte("bypass")); n != 2 || !errors.Is(x, partialResult) {
		t.Fatalf("bypass native result fabricated: %d %v", n, x)
	}
	if n, x := returned.Write([]byte{0xf3}); n != 1 || x != nil {
		t.Fatal(n, x)
	}
	if receives.Load() != 0 {
		t.Fatal("fixture failed: returned write was already received")
	}
	close(receivePermit)
	receiveModelWait(t, entered, "first Send missing")
	callbackActive := make(chan struct{})
	writerDone := make(chan error, 1)
	go func() {
		writerDone <- cached.Write(func(uintptr) bool {
			for i := 0; i < 259; i++ {
				input <- 0xf3
			}
			close(callbackActive)
			<-writerRelease
			return true
		})
	}()
	receiveModelWait(t, callbackActive, "multi-send callback missing")
	pressureWait(t, "actual R limit did not fail gate", func() bool { return l.Err() != nil })
	calls := syscalls.Load()
	var callbackCalled atomic.Bool
	if n, x := returned.Write([]byte{0xf3}); n != 0 || x == nil {
		t.Fatal("post-pressure Write succeeded")
	}
	if x := cached.Write(func(uintptr) bool { callbackCalled.Store(true); return true }); x == nil || callbackCalled.Load() {
		t.Fatal("cached capability bypassed failure")
	}
	listener := &leasePacketConn{PacketConn: socket, lease: l}
	if n, x := listener.WriteTo([]byte{0xf3}, nil); n != 0 || x == nil {
		t.Fatal("listener bypassed failure")
	}
	if n, x := listener.Write([]byte{0xf3}); n != 0 || x == nil {
		t.Fatal("io.Writer listener bypassed failure")
	}
	if syscalls.Load() != calls {
		t.Fatal("failed admission performed syscall")
	}
	if err = cached.Control(func(uintptr) {}); err != nil || raw.control.Load() != 1 {
		t.Fatal("Control blocked behind failure")
	}
	var readCalled bool
	if err = cached.Read(func(uintptr) bool { readCalled = true; return true }); err != nil || !readCalled {
		t.Fatal("Read blocked behind failure")
	}
	unblockSend()
	pressureWait(t, "scratch drain missing", func() bool { return sends.Load() == 260 })
	if shutdowns.Load() != 0 {
		t.Fatal("capacity failure skipped already-active RawConn join")
	}
	unblockWriter()
	if !errors.Is(<-writerDone, nativeResult) {
		t.Fatal("active operation lost actual return")
	}
	if err = l.Close(nil); err == nil {
		t.Fatal("capacity Close returned success")
	}
	if err = l.WaitCaptureRetired(); err != nil {
		t.Fatal(err)
	}
	if n, x := returned.Write([]byte{0xf3}); n != 0 || x == nil {
		t.Fatal("safe retirement cleared sticky admission")
	}
	if err = returned.Close(); err == nil {
		t.Fatal("endpoint Close erased capacity diagnostic")
	}
	if socket.closed.Load() != 1 || e.ActiveLeases() != 0 {
		t.Fatal("safe endpoint/native charge not retired")
	}
}

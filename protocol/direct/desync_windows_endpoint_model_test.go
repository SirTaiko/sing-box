//go:build desync_windows_model && !windows

package direct

import (
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/common/desync"
	"github.com/sagernet/sing-box/common/windivert"
	"github.com/sagernet/sing-box/option"
)

type receiveRootEndpoint struct {
	net.Conn
	closed  *atomic.Int32
	padding [128]byte
}

func (e *receiveRootEndpoint) Close() error { e.closed.Add(1); return nil }

func TestWindowsReceiveUnsafeReturnedEndpointSurvivesWrapperDrop(t *testing.T) {
	cfg, err := desync.Compile(&option.DirectDesyncOptions{Rules: []option.DirectDesyncRule{{Network: []string{"udp"}}}}, "")
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	sent := make(chan struct{})
	ready := make(chan struct{})
	var stopOnce sync.Once
	first := true
	failure := errors.New("unknown native completion")
	h := &windivert.Handle{RecvFunc: func(p []byte) (int, windivert.Address, error) {
		if first {
			<-ready
			first = false
			p[0] = 0xf3
			return 1, windivert.Address{}, nil
		}
		<-stop
		return 0, windivert.Address{}, windivert.ReplayDrained
	}, SendFunc: func([]byte, *windivert.Address) (int, error) { close(sent); return -1, failure }, ShutdownFunc: func() error { stopOnce.Do(func() { close(stop) }); return nil }, CloseFunc: func() error { t.Error("unsafe native Close"); return nil }, DoneChan: make(chan struct{})}
	windivert.ReplayOpen = func(*windivert.Filter, windivert.Layer, int16, windivert.Flag) (*windivert.Handle, error) {
		return h, nil
	}
	defer func() { windivert.ReplayOpen = nil }()
	e, err := desync.NewEngine(cfg, desync.NewWindowsReplayBackend())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	l, err := e.NewAttempt(desync.Intent{Family: desync.FamilyIPv4, Transport: desync.TransportUDP, Source: netip.MustParseAddrPort("192.0.2.10:40000")})
	if err != nil {
		t.Fatal(err)
	}
	l.SetLocalAddress(netip.MustParseAddrPort("192.0.2.10:40000"))
	if err = l.StartCapture(); err != nil {
		t.Fatal(err)
	}
	close(ready)
	receiveModelWait(t, sent, "native unknown Send absent")
	finalized := make(chan struct{}, 1)
	var closed atomic.Int32
	// The wrapper reference and endpoint local die at this helper boundary. The
	// final unsafe Lease must own the endpoint itself after the bridge returns.
	func() {
		ep := &receiveRootEndpoint{closed: &closed}
		runtime.SetFinalizer(ep, func(*receiveRootEndpoint) { finalized <- struct{}{} })
		wrapped := &leaseUDPConn{Conn: ep, lease: l}
		if x := wrapped.Close(); !errors.Is(x, failure) {
			t.Fatalf("wrong Close result: %v", x)
		}
	}()
	if !desync.WindowsModelEndpointRooted(l) || e.ActiveLeases() != 1 || closed.Load() != 0 {
		t.Fatal("charged tombstone did not root actual endpoint")
	}
	for i := 0; i < 3; i++ {
		runtime.GC()
		runtime.Gosched()
		select {
		case <-finalized:
			t.Fatal("endpoint finalized after caller dropped wrapper")
		default:
		}
	}
	runtime.KeepAlive(e)
}

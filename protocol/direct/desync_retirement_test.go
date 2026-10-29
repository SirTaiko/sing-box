package direct

import (
	"errors"
	"github.com/sagernet/sing-box/common/desync"
	"github.com/sagernet/sing-box/option"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type retirementEndpoint struct {
	udpLifetimePacket
	entered, release chan struct{}
	writes           atomic.Int32
}

func (c *retirementEndpoint) Read([]byte) (int, error) { return 0, net.ErrClosed }
func (c *retirementEndpoint) RemoteAddr() net.Addr     { return c.LocalAddr() }
func (c *retirementEndpoint) Write(p []byte) (int, error) {
	c.writes.Add(1)
	close(c.entered)
	<-c.release
	return len(p), nil
}
func (c *retirementEndpoint) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }
func (c *retirementEndpoint) SyscallConn() (syscall.RawConn, error)     { return retirementRaw{c}, nil }

type retirementRaw struct{ c *retirementEndpoint }

func (r retirementRaw) Control(f func(uintptr)) error    { f(17); return nil }
func (r retirementRaw) Read(f func(uintptr) bool) error  { f(17); return nil }
func (r retirementRaw) Write(f func(uintptr) bool) error { f(17); return nil }

// Exercise actual AttachConn/AttachPacketConn and a cached RawConn after pure
// Lease retirement: endpoint Close must still join an admitted bypass writer.
func TestReturnedEndpointCloseJoinsAdmittedProducer(t *testing.T) {
	for _, kind := range []string{"connected", "listener", "cached-raw-connected", "cached-raw-listener"} {
		t.Run(kind, func(t *testing.T) {
			_, hook, _ := newUDPLeaseEngine(t, 1, option.DirectDesyncRule{Network: []string{"udp"}, Methods: []string{}})
			listener := kind == "listener" || kind == "cached-raw-listener"
			attempt := packetUDPAttempt(t, hook, listener)
			endpoint := &retirementEndpoint{entered: make(chan struct{}), release: make(chan struct{})}
			var closeEndpoint func() error
			var write func() error
			if listener {
				returned := attempt.AttachPacketConn(endpoint)
				closeEndpoint = returned.Close
				raw, err := returned.(syscall.Conn).SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				write = func() error { _, err := returned.WriteTo([]byte("O2"), endpoint.LocalAddr()); return err }
				if kind == "cached-raw-listener" {
					write = func() error {
						return raw.Write(func(fd uintptr) bool {
							if fd != 17 {
								t.Error("descriptor changed")
							}
							_, _ = endpoint.Write([]byte("O2"))
							return true
						})
					}
				}
			} else {
				returned, err := attempt.AttachConn(endpoint)
				if err != nil {
					t.Fatal(err)
				}
				closeEndpoint = returned.Close
				raw, err := returned.(syscall.Conn).SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				write = func() error { _, err := returned.Write([]byte("O2")); return err }
				if kind == "cached-raw-connected" {
					write = func() error {
						return raw.Write(func(fd uintptr) bool {
							if fd != 17 {
								t.Error("descriptor changed")
							}
							_, _ = endpoint.Write([]byte("O2"))
							return true
						})
					}
				}
			}
			if err := attempt.lease.Close(nil); err != nil {
				t.Fatal(err)
			}
			if endpoint.closes.Load() != 0 {
				t.Fatal("pure Lease.Close closed caller socket")
			}
			wrote := make(chan error, 1)
			go func() { wrote <- write() }()
			<-endpoint.entered
			closed := make(chan error, 1)
			go func() { closed <- closeEndpoint() }()
			time.Sleep(20 * time.Millisecond)
			if endpoint.closes.Load() != 0 {
				t.Error("endpoint closed while admitted actual operation was active")
			}
			close(endpoint.release)
			if err := <-wrote; err != nil {
				t.Error(err)
			}
			if err := <-closed; err != nil {
				t.Error(err)
			}
			if endpoint.closes.Load() != 1 || endpoint.writes.Load() != 1 {
				t.Error("operation/endpoint not exactly once")
			}
			if err := closeEndpoint(); err != nil {
				t.Error(err)
			}
			if endpoint.closes.Load() != 1 {
				t.Error("repeated endpoint close")
			}
		})
	}
}

type diagnosticRetirementCapture struct{ err error }

func (c *diagnosticRetirementCapture) Quiesce() error { return c.err }
func (c *diagnosticRetirementCapture) Close() error   { return nil }

type diagnosticRetirementBackend struct{ c *diagnosticRetirementCapture }

func (b diagnosticRetirementBackend) Name() string                               { return "diagnostic-retirement" }
func (b diagnosticRetirementBackend) Open(*desync.Lease) (desync.Capture, error) { return b.c, nil }

func TestEndpointRetiresDespiteDiagnosticCloseError(t *testing.T) {
	failure := errors.New("completed operation diagnostic")
	cfg, err := desync.Compile(&option.DirectDesyncOptions{Rules: []option.DirectDesyncRule{{Network: []string{"udp"}, Methods: []string{}}}}, "")
	if err != nil {
		t.Fatal(err)
	}
	e, err := desync.NewEngine(cfg, diagnosticRetirementBackend{&diagnosticRetirementCapture{failure}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	l, err := e.NewAttempt(desync.Intent{Family: desync.FamilyIPv4, Transport: desync.TransportUDP})
	if err != nil {
		t.Fatal(err)
	}
	if err = l.StartCapture(); err != nil {
		t.Fatal(err)
	}
	var closes atomic.Int32
	if err = closeLeasedEndpoint(l, func() error { closes.Add(1); return nil }); !errors.Is(err, failure) {
		t.Fatalf("diagnostic lost: %v", err)
	}
	if err = l.WaitCaptureRetired(); err != nil {
		t.Fatalf("safe receipt=%v", err)
	}
	deadline := time.Now().Add(time.Second)
	for closes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if closes.Load() != 1 {
		t.Fatal("safe endpoint retained solely because Close carried a diagnostic")
	}
}

func TestReturnedEndpointCloseBoundsAdmittedProducerWait(t *testing.T) {
	_, hook, _ := newUDPLeaseEngine(t, 1, option.DirectDesyncRule{Network: []string{"udp"}, Methods: []string{}})
	attempt := packetUDPAttempt(t, hook, false)
	endpoint := &retirementEndpoint{entered: make(chan struct{}), release: make(chan struct{})}
	returned, err := attempt.AttachConn(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if err := attempt.lease.Close(nil); err != nil {
		t.Fatal(err)
	}
	writer := make(chan error, 1)
	go func() { _, err := returned.Write([]byte("O2")); writer <- err }()
	<-endpoint.entered
	closed := make(chan error, 1)
	go func() { closed <- returned.Close() }()
	select {
	case err := <-closed:
		if !errors.Is(err, desync.ErrLeaseCloseIncomplete) {
			t.Errorf("Close=%v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("endpoint caller exceeded 2s bound")
	}
	if endpoint.closes.Load() != 0 {
		t.Error("early close of socket with active producer")
	}
	close(endpoint.release)
	if err := <-writer; err != nil {
		t.Error(err)
	}
	deadline := time.Now().Add(time.Second)
	for endpoint.closes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if endpoint.closes.Load() != 1 {
		t.Error("same endpoint owner failed to finish after producer returned")
	}
}

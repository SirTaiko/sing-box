//go:build linux

package desync

// Permanent regressions for the actual NFQUEUE netlink adapter's optional
// capabilities. Model tests: the pinned netlink.Conn and the production
// nfqueueSocketAdapter are the real composed objects; the descriptor underneath
// is an unprivileged AF_UNIX socket pair, so no netfilter object is created and
// no host networking is used. Every case says so.
//
// The native default lifecycle (task t_68efb1c5, run557) failed on
// "desync: stop NFQUEUE receive: netlink set-read-deadline: operation not
// supported" although the owning pinned socket.Conn supports all three deadline
// methods and syscall.Conn. mdlayher/netlink@v1.11.2 reaches those capabilities
// only through its optional unexported deadlineSetter/syscallConner interfaces
// (conn.go:422-447 and 561-587), which the wrapper did not satisfy.

import (
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/socket"
	"golang.org/x/sys/unix"
)

// newAdapterSocketPair builds one pinned socket.Conn over an unprivileged
// AF_UNIX stream pair and returns the production adapter around it plus the
// peer descriptor the model kernel writes replies to.
func newAdapterSocketPair(t *testing.T) (*nfqueueSocketAdapter, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	conn, err := socket.New(fds[0], "desync-adapter-capability-test")
	if err != nil {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
		t.Fatalf("wrap pinned socket.Conn: %v", err)
	}
	adapter := &nfqueueSocketAdapter{conn: conn}
	t.Cleanup(func() {
		_ = adapter.Close()
		_ = unix.Close(fds[1])
	})
	return adapter, fds[1]
}

// TestNFQueueSocketAdapterCapabilitySurface is the exact optional-dispatch
// surface the pinned library needs. On the exact submission24 blobs it fails
// behaviorally ("operation not supported") without any missing symbol.
func TestNFQueueSocketAdapterCapabilitySurface(t *testing.T) {
	t.Run("zero-adapter", func(t *testing.T) {
		// A zero adapter is the capability-only construction the library and
		// QA surface use. It owns no descriptor, so the deadline methods have
		// nothing to arm and RawConn reports EBADF instead of a nil value.
		link := netlink.NewConn(&nfqueueSocketAdapter{}, 0xf1557001)
		if err := link.SetDeadline(time.Now()); err != nil {
			t.Fatalf("zero adapter SetDeadline: %v", err)
		}
		if err := link.SetReadDeadline(time.Now()); err != nil {
			t.Fatalf("zero adapter SetReadDeadline: %v", err)
		}
		if err := link.SetWriteDeadline(time.Now()); err != nil {
			t.Fatalf("zero adapter SetWriteDeadline: %v", err)
		}
		raw, err := link.SyscallConn()
		if err != nil {
			t.Fatalf("zero adapter SyscallConn: %v", err)
		}
		if raw == nil {
			t.Fatal("zero adapter SyscallConn returned a nil RawConn with a nil error")
		}
		if err := raw.Control(func(uintptr) {}); !errors.Is(err, os.ErrClosed) && !errors.Is(err, unix.EBADF) {
			t.Fatalf("zero adapter RawConn Control error = %v, want EBADF/closed", err)
		}
	})

	t.Run("owning-socket", func(t *testing.T) {
		adapter, peer := newAdapterSocketPair(t)
		link := netlink.NewConn(adapter, 0xf1557002)

		if err := link.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatalf("owning adapter SetDeadline: %v", err)
		}
		if err := link.SetReadDeadline(time.Time{}); err != nil {
			t.Fatalf("owning adapter SetReadDeadline(clear): %v", err)
		}
		if err := link.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatalf("owning adapter SetWriteDeadline: %v", err)
		}

		// The RawConn must be the owning socket.Conn's real descriptor, not an
		// empty placeholder: Control reports the same fd the adapter wraps.
		raw, err := link.SyscallConn()
		if err != nil {
			t.Fatalf("owning adapter SyscallConn: %v", err)
		}
		if raw == nil {
			t.Fatal("owning adapter SyscallConn returned a nil RawConn")
		}
		var controlled uintptr
		controlCalls := 0
		if err := raw.Control(func(fd uintptr) {
			controlCalls++
			controlled = fd
		}); err != nil {
			t.Fatalf("owning adapter RawConn Control: %v", err)
		}
		if controlCalls != 1 {
			t.Fatalf("RawConn Control callbacks = %d, want 1", controlCalls)
		}
		if controlled == 0 || controlled == ^uintptr(0) {
			t.Fatalf("RawConn Control exposed fd %#x, want the owning descriptor", controlled)
		}

		// The composed transport's readiness probe is the caller that failed
		// natively. It must use the same RawConn and report "not readable"
		// without consuming anything or reporting an unsupported capability.
		transport := netlinkQueueConn{Conn: link, port: 0xf1557002}
		pending, err := transport.pending()
		if err != nil {
			t.Fatalf("composed transport pending on an empty queue: %v", err)
		}
		if pending {
			t.Fatal("composed transport reported a readable empty queue")
		}

		// One well-formed datagram from the model kernel must become readable,
		// stay in the socket across the readiness probe, and parse through the
		// actual adapter's receive surface.
		message := netlink.Message{Header: netlink.Header{Length: 20, Type: netlink.Noop}, Data: []byte{1, 2, 3, 4}}
		wire, err := message.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal model kernel message: %v", err)
		}
		if _, err := unix.Write(peer, wire); err != nil {
			t.Fatalf("model kernel write: %v", err)
		}
		pending, err = transport.pending()
		if err != nil {
			t.Fatalf("composed transport pending with a queued message: %v", err)
		}
		if !pending {
			t.Fatal("composed transport did not see the queued message as readable")
		}
		received, err := link.Receive()
		if err != nil {
			t.Fatalf("receive through the actual adapter: %v", err)
		}
		if len(received) != 1 || received[0].Header.Type != netlink.Noop || len(received[0].Data) != 4 {
			t.Fatalf("received messages = %+v, want one Noop with 4 payload bytes", received)
		}

		// Drain-side readiness is deadline-independent: with the deadline
		// cleared, the model kernel's next datagram is still observed by
		// pending() and then consumed.
		if err := link.SetReadDeadline(time.Time{}); err != nil {
			t.Fatalf("clear read deadline before drain: %v", err)
		}
		second := netlink.Message{Header: netlink.Header{Length: 20, Type: netlink.Noop}, Data: []byte{5}}
		wire, err = second.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal second model kernel message: %v", err)
		}
		if _, err := unix.Write(peer, wire); err != nil {
			t.Fatalf("model kernel second write: %v", err)
		}
		pending, err = transport.pending()
		if err != nil || !pending {
			t.Fatalf("deadline-independent drain readiness = %v, %v; want true, nil", pending, err)
		}
		if _, err := link.Receive(); err != nil {
			t.Fatalf("drain receive: %v", err)
		}
	})
}

// TestNFQueueSocketAdapterDeadlineInterruptsBlockedReceive is the composed
// stop-signal model of capture.loop/stopReceive: the deadline set from the
// closing caller must reach the blocked actual-adapter read, exactly like the
// pinned socket.Conn does natively.
func TestNFQueueSocketAdapterDeadlineInterruptsBlockedReceive(t *testing.T) {
	adapter, _ := newAdapterSocketPair(t)
	link := netlink.NewConn(adapter, 0xf1557003)

	type readResult struct {
		messages []netlink.Message
		err      error
	}
	result := make(chan readResult, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		messages, err := link.Receive()
		result <- readResult{messages: messages, err: err}
	}()
	<-started

	// The reader blocks on the empty owned socket. The closing caller arms the
	// same one-millisecond-class bound the capture uses; the blocking read must
	// return the deadline, not an unsupported-capability error and not hang.
	if err := link.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("arm interrupting read deadline: %v", err)
	}
	select {
	case got := <-result:
		if got.err == nil {
			t.Fatalf("interrupted receive returned %d messages and no error", len(got.messages))
		}
		if !errors.Is(got.err, os.ErrDeadlineExceeded) {
			t.Fatalf("interrupted receive error = %v, want deadline exceeded", got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked actual-adapter receive was not interrupted by the read deadline")
	}
	// Clearing the deadline must let the same connection read again: the drain
	// path relies on it.
	if err := link.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear interrupting read deadline: %v", err)
	}
}

// TestNFQueueSocketAdapterPreservesGenuineErrors pins that the new delegation
// does not turn a real descriptor failure into a silent success: after the
// owning socket is closed, both the deadline capability and SyscallConn report
// the closed descriptor.
func TestNFQueueSocketAdapterPreservesGenuineErrors(t *testing.T) {
	adapter, _ := newAdapterSocketPair(t)
	link := netlink.NewConn(adapter, 0xf1557004)
	if err := link.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("arm deadline before close: %v", err)
	}
	if err := adapter.Close(); err != nil {
		t.Fatalf("close owning socket: %v", err)
	}
	if err := link.SetReadDeadline(time.Now()); err == nil {
		t.Fatal("closed owning socket accepted a read deadline")
	}
	if _, err := link.SyscallConn(); err == nil {
		t.Fatal("closed owning socket exposed a RawConn without an error")
	}
}

// TestNFQueueSocketAdapterConcurrentDeadlineAndPending exercises the two
// caller classes that overlap during teardown - the interrupting deadline arm
// and the readiness probe - against the actual adapter and pinned connection.
// It is a race-detector target, not a timing assertion.
func TestNFQueueSocketAdapterConcurrentDeadlineAndPending(t *testing.T) {
	adapter, _ := newAdapterSocketPair(t)
	link := netlink.NewConn(adapter, 0xf1557005)
	transport := netlinkQueueConn{Conn: link, port: 0xf1557005}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := transport.pending(); err != nil {
					t.Errorf("concurrent pending: %v", err)
					return
				}
			}
		}()
	}
	for arm := 0; arm < 100; arm++ {
		if err := link.SetReadDeadline(time.Time{}); err != nil {
			t.Fatalf("concurrent deadline clear %d: %v", arm, err)
		}
		if err := link.SetReadDeadline(time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("concurrent deadline arm %d: %v", arm, err)
		}
	}
	close(stop)
	wg.Wait()
	if err := link.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("final deadline clear: %v", err)
	}
}

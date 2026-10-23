//go:build windows

package desync

import (
	"errors"
	"net"
	"sync"
	"testing"

	"golang.org/x/sys/windows"
)

// testAdmissionHolder is the memory-only admission capability of the existing
// Windows sender fixtures. Production senders always receive their capability
// from the direct bridge's leaseConn; the fixtures model that reference without
// an engine, a socket or a native operation.
type testAdmissionHolder struct {
	mu       sync.Mutex
	acquired int
	released int
	refuse   error
}

func newTestAdmissionHolder() *testAdmissionHolder { return &testAdmissionHolder{} }

func (h *testAdmissionHolder) AcquireNativeHold() (func(), error) {
	h.mu.Lock()
	if h.refuse != nil {
		err := h.refuse
		h.mu.Unlock()
		return nil, err
	}
	h.acquired++
	h.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			h.mu.Lock()
			h.released++
			h.mu.Unlock()
		})
	}, nil
}

func (h *testAdmissionHolder) counts() (acquired int, released int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.acquired, h.released
}

// testAdmissionConn carries the capability and exposes an already-owned native
// connection, exactly like the direct bridge's leaseConn.
type testAdmissionConn struct {
	net.Conn
	holder *testAdmissionHolder
	native net.Conn
}

func (c *testAdmissionConn) AcquireNativeHold() (func(), error) {
	return c.holder.AcquireNativeHold()
}

func (c *testAdmissionConn) NativeStreamConn() net.Conn {
	if c.native != nil {
		return c.native
	}
	return c.Conn
}

// R15 (Windows factory body): a connection without an admission owner is
// refused before CreateEvent, so no native resource exists.
func TestWindowsFactoryRequiresAdmissionOwner(t *testing.T) {
	plain := &retainedFakeConn{}
	if _, err := newPlatformStreamNative().NewSender(plain, nil); err == nil {
		t.Fatalf("NewSender accepted a connection without an admission owner")
	}
}

// R08 (Windows submission gate): a refused operation reference returns the
// refusal and never submits a WSASend.
func TestWindowsSenderRefusedOperationHasNoSubmission(t *testing.T) {
	holder := newTestAdmissionHolder()
	holder.refuse = admissionRefused(errLeaseClosed)
	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		t.Skipf("CreateEvent unavailable: %v", err)
	}
	sender := &windowsSender{handle: 8, event: event, holder: holder}
	sender.overlapped.HEvent = event
	defer sender.Release()
	submitted := 0
	previous := windowsWSASend
	windowsWSASend = func(windows.Handle, *windows.WSABuf, uint32, *uint32, uint32, *windows.Overlapped, *byte) error {
		submitted++
		return nil
	}
	defer func() { windowsWSASend = previous }()
	if _, sendErr := sender.Send([]byte("abcdef"), sendOptions{}); !errors.Is(sendErr, ErrAdmissionRefused) {
		t.Fatalf("Send error = %v, want admission refusal", sendErr)
	}
	if submitted != 0 {
		t.Fatalf("WSASend submitted %d times after a refused admission, want 0", submitted)
	}
}

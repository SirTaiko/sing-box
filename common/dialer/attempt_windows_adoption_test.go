//go:build windows

package dialer

import (
	"errors"
	"net"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fakeConsumeAdopter replaces the direct-owned bridge at the outer adoption
// seam. It records the exact carrier it was given and models the new ownership:
// the adopter consumes the carrier, so a success publishes a connection without
// any separate carrier close, and an error publishes nothing.
type fakeConsumeAdopter struct {
	carrier windows.Handle
	events  *[]string
	conn    net.Conn
	err     error
	calls   int
	inputs  []windows.Handle
}

func (f *fakeConsumeAdopter) adopt(carrier windows.Handle, _ time.Time) (net.Conn, error) {
	*f.events = append(*f.events, "adopt")
	f.calls++
	f.inputs = append(f.inputs, carrier)
	if f.err != nil {
		return nil, f.err
	}
	return f.conn, nil
}

// adoptionSeams installs the fake carrier acquisition and consume-adopter seams
// for one subtest and restores the production values afterwards.
type adoptionSeams struct {
	carrier     windows.Handle
	adopter     *fakeConsumeAdopter
	dupInputs   []windows.Handle
	closeInputs []windows.Handle
	closeErrors []error
	closeCalls  int
	// peer is the other end of the adopted duplex fixture. It lets a test
	// complete a write deterministically instead of blocking forever on an
	// unread net.Pipe.
	peer net.Conn
	conn net.Conn
}

func installAdoptionSeams(t *testing.T, carrier windows.Handle, adoptErr error) *adoptionSeams {
	t.Helper()
	seams := &adoptionSeams{carrier: carrier}
	var events []string
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	seams.peer = server
	seams.conn = client
	seams.adopter = &fakeConsumeAdopter{
		carrier: carrier,
		events:  &events,
		conn:    client,
		err:     adoptErr,
	}
	originalDuplicate := duplicateForAdoption
	originalAdopter := adoptOwnedCarrier
	originalClose := closeCarrierSocket
	t.Cleanup(func() {
		duplicateForAdoption = originalDuplicate
		adoptOwnedCarrier = originalAdopter
		closeCarrierSocket = originalClose
	})
	duplicateForAdoption = func(handle windows.Handle) (windows.Handle, error) {
		seams.dupInputs = append(seams.dupInputs, handle)
		return carrier, nil
	}
	adoptOwnedCarrier = seams.adopter.adopt
	closeCarrierSocket = func(handle windows.Handle) error {
		seams.closeInputs = append(seams.closeInputs, handle)
		var err error
		if seams.closeCalls < len(seams.closeErrors) {
			err = seams.closeErrors[seams.closeCalls]
		}
		seams.closeCalls++
		return err
	}
	return seams
}

// scriptedSocketAdoption is the inert six-function API behind the actual
// production bridge routine. The FD token is a genuinely allocated Go object
// reached through unsafe.Pointer; no integer is converted into a pointer.
type scriptedSocketAdoption struct {
	family        int
	local, remote *net.TCPAddr
	addressesErr  error
	tokenPtr      *int
	token         unsafe.Pointer
	newFDNil      bool
	newFDErr      error
	initErr       error
	closeFDErrors []error
	conn          net.Conn

	addressesCalls, newFDCalls, initCalls, setAddrCalls, tcpCalls, closeFDCalls int
	addressInputs                                                               []windows.Handle
	newFDInputs                                                                 []scriptedNewFDInput
	initInputs, setAddrInputs, tcpInputs, closeInputs                           []unsafe.Pointer
	setAddrLocal, setAddrRemote                                                 net.Addr
}

type scriptedNewFDInput struct {
	handle         syscall.Handle
	family, sotype int
	network        string
}

func newScriptedSocketAdoption() *scriptedSocketAdoption {
	scripted := &scriptedSocketAdoption{
		family: windows.AF_INET,
		local:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000},
		remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443},
	}
	scripted.tokenPtr = new(int)
	scripted.token = unsafe.Pointer(scripted.tokenPtr)
	return scripted
}

func (s *scriptedSocketAdoption) api() socketAdoptionAPI {
	return socketAdoptionAPI{
		addresses: func(carrier windows.Handle) (int, *net.TCPAddr, *net.TCPAddr, error) {
			s.addressesCalls++
			s.addressInputs = append(s.addressInputs, carrier)
			if s.addressesErr != nil {
				return 0, nil, nil, s.addressesErr
			}
			return s.family, s.local, s.remote, nil
		},
		newFD: func(sysfd syscall.Handle, family, sotype int, network string) (unsafe.Pointer, error) {
			s.newFDCalls++
			s.newFDInputs = append(s.newFDInputs, scriptedNewFDInput{handle: sysfd, family: family, sotype: sotype, network: network})
			if s.newFDNil {
				return nil, s.newFDErr
			}
			return s.token, s.newFDErr
		},
		initFD: func(fd unsafe.Pointer) error {
			s.initCalls++
			s.initInputs = append(s.initInputs, fd)
			return s.initErr
		},
		setAddr: func(fd unsafe.Pointer, local, remote net.Addr) {
			s.setAddrCalls++
			s.setAddrInputs = append(s.setAddrInputs, fd)
			s.setAddrLocal, s.setAddrRemote = local, remote
		},
		tcpConn: func(fd unsafe.Pointer) net.Conn {
			s.tcpCalls++
			s.tcpInputs = append(s.tcpInputs, fd)
			return s.conn
		},
		closeFD: func(fd unsafe.Pointer) error {
			s.closeFDCalls++
			s.closeInputs = append(s.closeInputs, fd)
			if s.closeFDCalls <= len(s.closeFDErrors) {
				return s.closeFDErrors[s.closeFDCalls-1]
			}
			return nil
		},
	}
}

// installAdoptionCloseSeam replaces the raw carrier disposal seam and records
// every closesocket it received.
func installCarrierCloseSeam(t *testing.T, errs ...error) *[]windows.Handle {
	t.Helper()
	original := closeCarrierSocket
	t.Cleanup(func() { closeCarrierSocket = original })
	var calls []windows.Handle
	closeCarrierSocket = func(handle windows.Handle) error {
		calls = append(calls, handle)
		if len(calls) <= len(errs) {
			return errs[len(calls)-1]
		}
		return nil
	}
	return &calls
}

// TestWA1DirectBridgeSuccess pins the DA-OWN ownership transfer: one genuine
// carrier identity reaches addresses/newFD/init/setAddr/tcpConn, the original
// socket never does, no carrier close happens on success, and the returned
// connection is the ordinary duplex connection the adapter built.
func TestWA1DirectBridgeSuccess(t *testing.T) {
	original := windows.Handle(0x42)
	carrier := windows.Handle(0x99)
	client, peer := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = peer.Close()
	})
	scripted := newScriptedSocketAdoption()
	scripted.conn = client
	closeCalls := installCarrierCloseSeam(t)
	installAdoptionClock(t, time.Now(), time.Now().Add(time.Millisecond))

	conn, err := bridgeOwnedCarrier(scripted.api(), carrier, time.Now().Add(time.Second))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn != client {
		t.Fatalf("returned connection = %v, want the adapter's TCPConn fixture", conn)
	}
	if scripted.addressesCalls != 1 || len(scripted.addressInputs) != 1 || scripted.addressInputs[0] != carrier {
		t.Fatalf("address calls = %d inputs = %v, want exactly the carrier %#x", scripted.addressesCalls, scripted.addressInputs, carrier)
	}
	if scripted.newFDCalls != 1 || scripted.newFDInputs[0].handle != syscall.Handle(carrier) {
		t.Fatalf("newFD calls = %d inputs = %+v, want exactly the carrier %#x", scripted.newFDCalls, scripted.newFDInputs, carrier)
	}
	if input := scripted.newFDInputs[0]; input.family != windows.AF_INET || input.sotype != syscall.SOCK_STREAM || input.network != "tcp" {
		t.Fatalf("newFD input = %+v, want AF_INET/SOCK_STREAM/tcp", input)
	}
	if scripted.initCalls != 1 || scripted.initInputs[0] != scripted.token {
		t.Fatalf("init calls = %d, want exactly one init of the allocated FD token", scripted.initCalls)
	}
	if scripted.setAddrCalls != 1 || scripted.setAddrInputs[0] != scripted.token || scripted.setAddrLocal != scripted.local || scripted.setAddrRemote != scripted.remote {
		t.Fatalf("setAddr = %d inputs=%v local=%v remote=%v, want the exact carrier addresses on the FD", scripted.setAddrCalls, scripted.setAddrInputs, scripted.setAddrLocal, scripted.setAddrRemote)
	}
	if scripted.tcpCalls != 1 || scripted.tcpInputs[0] != scripted.token {
		t.Fatalf("tcpConn calls = %d, want exactly one TCPConn construction", scripted.tcpCalls)
	}
	if scripted.closeFDCalls != 0 || len(*closeCalls) != 0 {
		t.Fatalf("FD closes = %d raw closes = %v, want no carrier close after a successful transfer", scripted.closeFDCalls, *closeCalls)
	}
	if scripted.addressInputs[0] == original {
		t.Fatal("the original socket reached the adoption bridge")
	}
	// The fixture is an ordinary duplex net.Pipe: it must remain usable.
	received := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1)
		_, readErr := peer.Read(buffer)
		if readErr == nil && buffer[0] != 'x' {
			readErr = errors.New("unexpected payload")
		}
		received <- readErr
	}()
	if _, writeErr := conn.Write([]byte("x")); writeErr != nil {
		t.Fatalf("adopted connection unusable: %v", writeErr)
	}
	if readErr := <-received; readErr != nil {
		t.Fatalf("adopted connection payload: %v", readErr)
	}
}

// TestWA1DirectBridgePreFDFailures pins DA-PRE: every failure before an FD
// exists closes the raw carrier exactly once through the existing retirement
// helper, creates no FD/TCPConn and keeps the exact cause; an invalid sentinel
// has no native effect at all.
func TestWA1DirectBridgePreFDFailures(t *testing.T) {
	carrier := windows.Handle(0x99)
	ambiguous := errors.New("injected ambiguous carrier close failure")

	t.Run("invalid-sentinel-no-effect", func(t *testing.T) {
		for _, handle := range []windows.Handle{0, windows.InvalidHandle} {
			scripted := newScriptedSocketAdoption()
			closeCalls := installCarrierCloseSeam(t)
			conn, err := bridgeOwnedCarrier(scripted.api(), handle, time.Now().Add(time.Second))
			if conn != nil || err == nil {
				t.Fatalf("bridge(%#x) = (%v, %v), want a rejected sentinel", handle, conn, err)
			}
			if scripted.addressesCalls != 0 || scripted.newFDCalls != 0 || len(*closeCalls) != 0 {
				t.Fatalf("bridge(%#x) native effects: address=%d newFD=%d closes=%v, want none", handle, scripted.addressesCalls, scripted.newFDCalls, *closeCalls)
			}
		}
	})

	t.Run("address-observation-failure-retires-raw-once", func(t *testing.T) {
		sentinel := errors.New("injected address observation failure")
		scripted := newScriptedSocketAdoption()
		scripted.addressesErr = sentinel
		closeCalls := installCarrierCloseSeam(t)
		conn, err := bridgeOwnedCarrier(scripted.api(), carrier, time.Now().Add(time.Second))
		if conn != nil || !errors.Is(err, sentinel) {
			t.Fatalf("bridge = (%v, %v), want the address cause with no connection", conn, err)
		}
		if scripted.addressesCalls != 1 || scripted.newFDCalls != 0 || scripted.initCalls != 0 {
			t.Fatalf("address=%d newFD=%d init=%d, want one failed observation and no FD", scripted.addressesCalls, scripted.newFDCalls, scripted.initCalls)
		}
		if len(*closeCalls) != 1 || (*closeCalls)[0] != carrier {
			t.Fatalf("raw closes = %v, want exactly the carrier %#x", *closeCalls, carrier)
		}
	})

	t.Run("expired-deadline-closes-raw-without-init", func(t *testing.T) {
		scripted := newScriptedSocketAdoption()
		closeCalls := installCarrierCloseSeam(t)
		installAdoptionClock(t, time.Now().Add(adoptContextBudget))
		conn, err := bridgeOwnedCarrier(scripted.api(), carrier, time.Now().Add(-time.Second))
		if conn != nil || err == nil || !strings.Contains(err.Error(), "connected socket context not observable within the adoption budget") {
			t.Fatalf("bridge = (%v, %v), want the shared budget error", conn, err)
		}
		if scripted.addressesCalls != 1 || scripted.newFDCalls != 0 || scripted.initCalls != 0 {
			t.Fatalf("address=%d newFD=%d init=%d, want no FD entry after expiry", scripted.addressesCalls, scripted.newFDCalls, scripted.initCalls)
		}
		if len(*closeCalls) != 1 || (*closeCalls)[0] != carrier {
			t.Fatalf("raw closes = %v, want exactly the carrier %#x", *closeCalls, carrier)
		}
	})

	t.Run("newfd-error-without-fd-closes-raw-once", func(t *testing.T) {
		sentinel := errors.New("injected newFD failure")
		scripted := newScriptedSocketAdoption()
		scripted.newFDNil = true
		scripted.newFDErr = sentinel
		closeCalls := installCarrierCloseSeam(t)
		conn, err := bridgeOwnedCarrier(scripted.api(), carrier, time.Now().Add(time.Second))
		if conn != nil || !errors.Is(err, sentinel) {
			t.Fatalf("bridge = (%v, %v), want the newFD cause", conn, err)
		}
		if scripted.closeFDCalls != 0 || scripted.initCalls != 0 {
			t.Fatalf("FD closes = %d init = %d, want no FD ownership without a descriptor", scripted.closeFDCalls, scripted.initCalls)
		}
		if len(*closeCalls) != 1 || (*closeCalls)[0] != carrier {
			t.Fatalf("raw closes = %v, want exactly the carrier %#x", *closeCalls, carrier)
		}
	})

	t.Run("newfd-nil-without-error-closes-raw-once", func(t *testing.T) {
		scripted := newScriptedSocketAdoption()
		scripted.newFDNil = true
		closeCalls := installCarrierCloseSeam(t)
		conn, err := bridgeOwnedCarrier(scripted.api(), carrier, time.Now().Add(time.Second))
		if conn != nil || err == nil {
			t.Fatalf("bridge = (%v, %v), want a defensive allocation error", conn, err)
		}
		if len(*closeCalls) != 1 || (*closeCalls)[0] != carrier {
			t.Fatalf("raw closes = %v, want exactly the carrier %#x", *closeCalls, carrier)
		}
	})

	t.Run("newfd-error-with-fd-closes-fd-not-raw", func(t *testing.T) {
		sentinel := errors.New("injected newFD partial failure")
		scripted := newScriptedSocketAdoption()
		scripted.newFDErr = sentinel
		closeCalls := installCarrierCloseSeam(t)
		conn, err := bridgeOwnedCarrier(scripted.api(), carrier, time.Now().Add(time.Second))
		if conn != nil || !errors.Is(err, sentinel) {
			t.Fatalf("bridge = (%v, %v), want the newFD cause", conn, err)
		}
		if scripted.closeFDCalls != 1 || scripted.closeInputs[0] != scripted.token || scripted.initCalls != 0 {
			t.Fatalf("FD closes = %d init = %d, want exactly one FD close and no init", scripted.closeFDCalls, scripted.initCalls)
		}
		if len(*closeCalls) != 0 {
			t.Fatalf("raw closes = %v, want no raw close once an FD owns the carrier", *closeCalls)
		}
	})

	t.Run("ambiguous-raw-close-keeps-known-carrier-charge", func(t *testing.T) {
		sentinel := errors.New("injected address observation failure")
		scripted := newScriptedSocketAdoption()
		scripted.addressesErr = sentinel
		closeCalls := installCarrierCloseSeam(t, ambiguous)
		conn, err := bridgeOwnedCarrier(scripted.api(), carrier, time.Now().Add(time.Second))
		if conn != nil || !errors.Is(err, sentinel) || !errors.Is(err, ambiguous) {
			t.Fatalf("bridge = (%v, %v), want both the cause and the close failure", conn, err)
		}
		var unresolved *unresolvedSocketRetirement
		if !errors.As(err, &unresolved) || unresolved.handle != carrier {
			t.Fatalf("error = %v, want the known-carrier unresolved obligation %#x", err, carrier)
		}
		if !hasUnresolvedRetirement(err) {
			t.Fatalf("error = %v, want the retirement charge retained", err)
		}
		if len(*closeCalls) != 1 {
			t.Fatalf("raw closes = %v, want exactly one attempt with no blind retry", *closeCalls)
		}
	})
}

// TestWA1DirectBridgeInitFailure pins DA-INIT: an init failure observes exactly
// one FD.Close, never a raw carrier close and never a second init; a nil close
// result proves the cleanup, a nonnil one (including would-block) keeps the
// known-carrier unresolved obligation with both error identities joined.
func TestWA1DirectBridgeInitFailure(t *testing.T) {
	carrier := windows.Handle(0x99)
	initSentinel := errors.New("injected netFD init failure")
	closeSentinel := errors.New("injected FD close failure")

	t.Run("good-close-proves-cleanup", func(t *testing.T) {
		scripted := newScriptedSocketAdoption()
		scripted.initErr = initSentinel
		closeCalls := installCarrierCloseSeam(t)
		conn, err := bridgeOwnedCarrier(scripted.api(), carrier, time.Now().Add(time.Second))
		if conn != nil || !errors.Is(err, initSentinel) {
			t.Fatalf("bridge = (%v, %v), want the init cause", conn, err)
		}
		if scripted.initCalls != 1 || scripted.closeFDCalls != 1 || scripted.closeInputs[0] != scripted.token {
			t.Fatalf("init=%d FD closes=%d, want exactly one init and one FD close", scripted.initCalls, scripted.closeFDCalls)
		}
		if scripted.setAddrCalls != 0 || scripted.tcpCalls != 0 || len(*closeCalls) != 0 {
			t.Fatalf("setAddr=%d tcp=%d raw closes=%v, want no publication and no raw close", scripted.setAddrCalls, scripted.tcpCalls, *closeCalls)
		}
		var unresolved *unresolvedSocketRetirement
		if errors.As(err, &unresolved) {
			t.Fatalf("error = %v, want no unresolved obligation after a proven FD cleanup", err)
		}
	})

	t.Run("bad-close-keeps-both-identities", func(t *testing.T) {
		scripted := newScriptedSocketAdoption()
		scripted.initErr = initSentinel
		scripted.closeFDErrors = []error{closeSentinel}
		closeCalls := installCarrierCloseSeam(t)
		conn, err := bridgeOwnedCarrier(scripted.api(), carrier, time.Now().Add(time.Second))
		if conn != nil || !errors.Is(err, initSentinel) || !errors.Is(err, closeSentinel) {
			t.Fatalf("bridge = (%v, %v), want both the init and close identities", conn, err)
		}
		var unresolved *unresolvedSocketRetirement
		if !errors.As(err, &unresolved) || unresolved.handle != carrier {
			t.Fatalf("error = %v, want the known-carrier unresolved obligation %#x", err, carrier)
		}
		if scripted.initCalls != 1 || scripted.closeFDCalls != 1 {
			t.Fatalf("init=%d FD closes=%d, want exactly one of each with no retry", scripted.initCalls, scripted.closeFDCalls)
		}
		if len(*closeCalls) != 0 {
			t.Fatalf("raw closes = %v, want no raw close after the FD owned the carrier", *closeCalls)
		}
		if scripted.tcpCalls != 0 {
			t.Fatalf("TCPConn constructions = %d, want none after init failure", scripted.tcpCalls)
		}
	})

	t.Run("wouldblock-close-keeps-obligation", func(t *testing.T) {
		scripted := newScriptedSocketAdoption()
		scripted.initErr = initSentinel
		scripted.closeFDErrors = []error{windows.WSAEWOULDBLOCK}
		conn, err := bridgeOwnedCarrier(scripted.api(), carrier, time.Now().Add(time.Second))
		if conn != nil || !errors.Is(err, windows.WSAEWOULDBLOCK) || !errors.Is(err, initSentinel) {
			t.Fatalf("bridge = (%v, %v), want both identities", conn, err)
		}
		if !hasUnresolvedRetirement(err) {
			t.Fatalf("error = %v, want the unresolved cleanup obligation", err)
		}
	})
}

// TestWA1DirectBridgeLateSuccess pins DA-LATE: a connection created after the
// shared budget is rolled back once and never published; a failed rollback
// Close keeps the existing opaque adopted-rollback marker, while a proven one
// releases the boundary. No extra acquisition or constructor runs.
func TestWA1DirectBridgeLateSuccess(t *testing.T) {
	carrier := windows.Handle(0x99)
	rollbackSentinel := errors.New("injected adopted rollback failure")

	t.Run("good-rollback", func(t *testing.T) {
		client, peer := net.Pipe()
		t.Cleanup(func() { _ = peer.Close() })
		rolledBack := &failingCloseConn{Conn: client}
		scripted := newScriptedSocketAdoption()
		scripted.conn = rolledBack
		closeCalls := installCarrierCloseSeam(t)
		start := time.Now()
		installAdoptionClock(t, start, start.Add(adoptContextBudget))
		conn, err := bridgeOwnedCarrier(scripted.api(), carrier, start.Add(adoptContextBudget))
		if conn != nil || err == nil || !strings.Contains(err.Error(), "adoption completed after the adoption budget expired") {
			t.Fatalf("bridge = (%v, %v), want the late-success cause", conn, err)
		}
		if rolledBack.closes != 1 {
			t.Fatalf("adopted Close calls = %d, want exactly one rollback", rolledBack.closes)
		}
		if scripted.newFDCalls != 1 || scripted.initCalls != 1 || scripted.tcpCalls != 1 {
			t.Fatalf("newFD=%d init=%d tcp=%d, want exactly one construction sequence", scripted.newFDCalls, scripted.initCalls, scripted.tcpCalls)
		}
		if scripted.closeFDCalls != 0 || len(*closeCalls) != 0 {
			t.Fatalf("FD closes = %d raw closes = %v, want only the connection rollback", scripted.closeFDCalls, *closeCalls)
		}
		assertNoOpaqueAdoptionRetirement(t, err)
	})

	t.Run("bad-rollback-keeps-marker", func(t *testing.T) {
		client, peer := net.Pipe()
		t.Cleanup(func() { _ = peer.Close() })
		rolledBack := &failingCloseConn{Conn: client, closeErr: rollbackSentinel}
		scripted := newScriptedSocketAdoption()
		scripted.conn = rolledBack
		start := time.Now()
		installAdoptionClock(t, start, start.Add(adoptContextBudget))
		conn, err := bridgeOwnedCarrier(scripted.api(), carrier, start.Add(adoptContextBudget))
		if conn != nil || !errors.Is(err, rollbackSentinel) {
			t.Fatalf("bridge = (%v, %v), want the rollback failure visible", conn, err)
		}
		if rolledBack.closes != 1 {
			t.Fatalf("adopted Close calls = %d, want exactly one rollback", rolledBack.closes)
		}
		assertOpaqueAdoptionRetirement(t, err, adoptionRetirementStageAdoptedRollback, rollbackSentinel)
	})
}

// TestWA1AdoptionBridgeRejectsInvalidCarrierSentinel pins the production seam
// validation: an invalid handle is refused before the bridge and is not closed.
func TestWA1AdoptionBridgeRejectsInvalidCarrierSentinel(t *testing.T) {
	for _, handle := range []windows.Handle{0, windows.InvalidHandle} {
		if _, err := newOwnedSocketConn(handle, time.Now().Add(time.Second)); err == nil {
			t.Fatalf("newOwnedSocketConn(%#x) = nil error, want a rejection", handle)
		}
	}
}

// TestSec328AdoptionCarrierOwnership pins the ownership split of the single
// direct adoption: the bridge must receive a dedicated readiness carrier, the
// original handle must never reach it, success publishes the adopter's
// connection without any separate carrier close, and an adoption error
// publishes nothing.
func TestSec328AdoptionCarrierOwnership(t *testing.T) {
	original := windows.Handle(0x42)
	carrier := windows.Handle(0x99)

	t.Run("success", func(t *testing.T) {
		seams := installAdoptionSeams(t, carrier, nil)
		conn, err := adoptConnectedSocket(original)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(seams.dupInputs) != 1 || seams.dupInputs[0] != original {
			t.Fatalf("duplication inputs = %v, want exactly one call with the original handle", seams.dupInputs)
		}
		if seams.adopter.calls != 1 || len(seams.adopter.inputs) != 1 || seams.adopter.inputs[0] != carrier {
			t.Fatalf("adopter inputs = %v, want exactly the carrier duplicate %#x, never the original %#x", seams.adopter.inputs, carrier, original)
		}
		if len(seams.closeInputs) != 0 {
			t.Fatalf("extra closesocket calls = %v, want none after a successful transfer", seams.closeInputs)
		}
		if conn != seams.conn {
			t.Fatalf("returned connection = %v, want the adopted connection", conn)
		}
		_ = conn.Close()
	})

	t.Run("adoption-failure-consumes-carrier", func(t *testing.T) {
		adoptErr := errors.New("injected bridge failure")
		seams := installAdoptionSeams(t, carrier, adoptErr)
		conn, err := adoptConnectedSocket(original)
		if conn != nil {
			t.Fatal("a failed adoption must not publish a connection")
		}
		if !errors.Is(err, adoptErr) {
			t.Fatalf("error = %v, want the bridge error", err)
		}
		if seams.adopter.calls != 1 || len(seams.adopter.inputs) != 1 || seams.adopter.inputs[0] != carrier {
			t.Fatalf("adopter inputs = %v, want the carrier consumed once", seams.adopter.inputs)
		}
		if len(seams.closeInputs) != 0 {
			t.Fatalf("extra closesocket calls = %v: the adopter owns cleanup on entry", seams.closeInputs)
		}
	})

	t.Run("duplication-failure-acquires-nothing", func(t *testing.T) {
		seams := installAdoptionSeams(t, carrier, nil)
		dupErr := errors.New("injected carrier duplication failure")
		duplicateForAdoption = func(handle windows.Handle) (windows.Handle, error) {
			seams.dupInputs = append(seams.dupInputs, handle)
			return 0, dupErr
		}
		conn, err := adoptConnectedSocket(original)
		if conn != nil || !errors.Is(err, dupErr) {
			t.Fatalf("adoptConnectedSocket = (%v, %v), want the duplication error", conn, err)
		}
		if seams.adopter.calls != 0 {
			t.Fatalf("adopter calls = %d, want no adoption without a descriptor", seams.adopter.calls)
		}
		if len(seams.closeInputs) != 0 {
			t.Fatalf("closesocket inputs = %v, want no close of an unacquired result", seams.closeInputs)
		}
	})
}

// TestWA1AdoptedConnectionSurvivesGCPressure is the GC/handle-reuse control:
// after a successful transfer the carrier belongs exclusively to the adapter's
// connection, no additional close acts on it, and the connection stays usable
// across garbage collection.
func TestWA1AdoptedConnectionSurvivesGCPressure(t *testing.T) {
	original := windows.Handle(0x42)
	carrier := windows.Handle(0x99)
	seams := installAdoptionSeams(t, carrier, nil)
	conn, err := adoptConnectedSocket(original)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i := 0; i < 4; i++ {
		runtime.GC()
		time.Sleep(time.Millisecond)
	}
	if len(seams.closeInputs) != 0 {
		t.Fatalf("extra closesocket calls = %v, want none", seams.closeInputs)
	}
	received := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1)
		_, readErr := seams.peer.Read(buffer)
		if readErr == nil && buffer[0] != 'x' {
			readErr = errors.New("unexpected payload")
		}
		received <- readErr
	}()
	if _, writeErr := conn.Write([]byte("x")); writeErr != nil {
		_ = seams.peer.Close()
		<-received
		t.Fatalf("adopted connection unusable after GC: %v", writeErr)
	}
	if readErr := <-received; readErr != nil {
		t.Fatalf("adopted connection payload after GC: %v", readErr)
	}
	if err = conn.Close(); err != nil {
		t.Fatalf("close adopted connection: %v", err)
	}
	if len(seams.closeInputs) != 0 {
		t.Fatalf("closesocket calls = %v after the adopted close, want no second close", seams.closeInputs)
	}
}

// TestWA2CarrierWithInvisibleContextIsReplaced pins the readiness boundary: a
// carrier whose own duplicated context is not observable is retired exactly
// once through the production retirement helper and replaced, and only the
// replacement carrier reaches the adopter.
func TestWA2CarrierWithInvisibleContextIsReplaced(t *testing.T) {
	original := windows.Handle(0x42)
	retiredCarrier := windows.Handle(0x98)
	carrier := windows.Handle(0x99)

	seams := installAdoptionSeams(t, carrier, nil)
	contextMiss := errors.New("desync: duplicated socket has no local address: An invalid argument was supplied.")
	duplicateForAdoption = func(handle windows.Handle) (windows.Handle, error) {
		seams.dupInputs = append(seams.dupInputs, handle)
		if len(seams.dupInputs) == 1 {
			return 0, retireFailedDuplicate(retiredCarrier, &connectedContextNotVisible{cause: contextMiss})
		}
		return carrier, nil
	}

	conn, err := adoptConnectedSocket(original)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(seams.dupInputs) != 2 {
		t.Fatalf("duplication calls = %v, want one retired carrier and one replacement", seams.dupInputs)
	}
	if len(seams.closeInputs) != 1 || seams.closeInputs[0] != retiredCarrier {
		t.Fatalf("closesocket inputs = %v, want exactly the retired carrier %#x", seams.closeInputs, retiredCarrier)
	}
	if len(seams.adopter.inputs) != 1 || seams.adopter.inputs[0] != carrier {
		t.Fatalf("adopter inputs = %v, want only the verified carrier %#x", seams.adopter.inputs, carrier)
	}
	if conn != seams.conn {
		t.Fatalf("returned connection = %v, want the adopted connection", conn)
	}
	_ = conn.Close()
}

// TestWA2UnresolvedCarrierRetirementStopsReplacement pins the replacement rule:
// a carrier whose release cannot be proven stops the sequence with its
// unresolved token; no second carrier is created and no connection is
// published.
func TestWA2UnresolvedCarrierRetirementStopsReplacement(t *testing.T) {
	original := windows.Handle(0x42)
	retiredCarrier := windows.Handle(0x98)
	ambiguous := errors.New("injected ambiguous close failure")

	seams := installAdoptionSeams(t, windows.Handle(0x99), nil)
	seams.closeErrors = []error{ambiguous}
	duplicateForAdoption = func(handle windows.Handle) (windows.Handle, error) {
		seams.dupInputs = append(seams.dupInputs, handle)
		return 0, retireFailedDuplicate(retiredCarrier, &connectedContextNotVisible{cause: errors.New("injected missing connected context")})
	}

	conn, err := adoptConnectedSocket(original)
	if conn != nil {
		t.Fatal("an unresolved carrier retirement must not publish a connection")
	}
	var unresolved *unresolvedSocketRetirement
	if !errors.As(err, &unresolved) || unresolved.handle != retiredCarrier {
		t.Fatalf("error = %v, want an unresolved-retirement token for the carrier %#x", err, retiredCarrier)
	}
	if len(seams.dupInputs) != 1 {
		t.Fatalf("duplication calls = %v, want exactly one", seams.dupInputs)
	}
	if seams.adopter.calls != 0 {
		t.Fatalf("adopter calls = %d, want no adoption carrier", seams.adopter.calls)
	}
}

// TestWA2CarrierContextBudgetExhaustionFailsWithoutAdoption pins the other half
// of the boundary: when no carrier exposes the connected context inside the
// budget, the attempt ends with the last observation error and the single
// adoption is never attempted.
func TestWA2CarrierContextBudgetExhaustionFailsWithoutAdoption(t *testing.T) {
	original := windows.Handle(0x42)
	seams := installAdoptionSeams(t, windows.Handle(0x99), nil)
	contextMiss := &connectedContextNotVisible{cause: errors.New("desync: duplicated socket has no local address: An invalid argument was supplied.")}
	duplicateForAdoption = func(handle windows.Handle) (windows.Handle, error) {
		seams.dupInputs = append(seams.dupInputs, handle)
		return 0, contextMiss
	}

	conn, err := adoptConnectedSocket(original)
	if conn != nil {
		t.Fatal("an unverified carrier must not be adopted")
	}
	var notVisible *connectedContextNotVisible
	if !errors.As(err, &notVisible) {
		t.Fatalf("error = %v, want the last connected-context observation", err)
	}
	if len(seams.dupInputs) < 2 {
		t.Fatalf("duplication calls = %d, want the bounded acquisition to replace an unobserved carrier", len(seams.dupInputs))
	}
	if seams.adopter.calls != 0 {
		t.Fatalf("adopter calls = %d, want no adoption carrier", seams.adopter.calls)
	}
}

// installAdoptionClock scripts the bounded acquisition clock: each adoptNow
// call consumes the next scripted instant, the last instant repeats, and
// adoptSleep only records the requested pause. A test can therefore place an
// acquisition entry, a resumed pause or an already ready carrier on either side
// of the shared budget without depending on real time or scheduler delay.
func installAdoptionClock(t *testing.T, instants ...time.Time) *[]time.Duration {
	t.Helper()
	if len(instants) == 0 {
		t.Fatal("installAdoptionClock needs at least one scripted instant")
	}
	originalNow := adoptNow
	originalSleep := adoptSleep
	t.Cleanup(func() {
		adoptNow = originalNow
		adoptSleep = originalSleep
	})
	calls := 0
	adoptNow = func() time.Time {
		index := calls
		calls++
		if index >= len(instants) {
			return instants[len(instants)-1]
		}
		return instants[index]
	}
	var pauses []time.Duration
	adoptSleep = func(pause time.Duration) {
		pauses = append(pauses, pause)
	}
	return &pauses
}

// TestWA3CarrierAcquisitionDeadlineAdmission pins R1214-R1. The shared adoption
// budget is one absolute deadline that admits every acquisition entry and every
// ready carrier: an expired entry creates no descriptor, a pause resumed after
// the deadline starts no next acquisition, and a carrier that becomes ready
// late is retired exactly once instead of reaching the adopter.
func TestWA3CarrierAcquisitionDeadlineAdmission(t *testing.T) {
	original := windows.Handle(0x42)
	lateCarrier := windows.Handle(0xa1)
	retiredCarrier := windows.Handle(0x98)
	contextMiss := errors.New("desync: duplicated socket has no local address: An invalid argument was supplied.")
	const budgetMessage = "connected socket context not observable within the adoption budget"

	t.Run("expired-entry-creates-no-carrier", func(t *testing.T) {
		start := time.Now()
		seams := installAdoptionSeams(t, windows.Handle(0x99), nil)
		installAdoptionClock(t, start, start.Add(adoptContextBudget))
		duplicateForAdoption = func(handle windows.Handle) (windows.Handle, error) {
			seams.dupInputs = append(seams.dupInputs, handle)
			return windows.Handle(0x99), nil
		}

		conn, err := adoptConnectedSocket(original)
		if conn != nil {
			t.Fatal("an acquisition entered after the budget must not be adopted")
		}
		if err == nil || !strings.Contains(err.Error(), budgetMessage) {
			t.Fatalf("error = %v, want the adoption budget error", err)
		}
		var notVisible *connectedContextNotVisible
		if errors.As(err, &notVisible) {
			t.Fatalf("error = %v, want no connected-context observation on an expired entry", err)
		}
		if len(seams.dupInputs) != 0 {
			t.Fatalf("duplication calls = %v, want none after the budget expired", seams.dupInputs)
		}
		if seams.adopter.calls != 0 || seams.closeCalls != 0 {
			t.Fatalf("adopter calls = %d, closesocket calls = %d, want no carrier handling", seams.adopter.calls, seams.closeCalls)
		}
	})

	t.Run("pause-resumed-after-budget-starts-no-replacement", func(t *testing.T) {
		start := time.Now()
		seams := installAdoptionSeams(t, lateCarrier, nil)
		pauses := installAdoptionClock(t, start, start.Add(time.Millisecond), start.Add(2*time.Millisecond), start.Add(adoptContextBudget))
		duplicateForAdoption = func(handle windows.Handle) (windows.Handle, error) {
			seams.dupInputs = append(seams.dupInputs, handle)
			if len(seams.dupInputs) == 1 {
				return 0, retireFailedDuplicate(retiredCarrier, &connectedContextNotVisible{cause: contextMiss})
			}
			return lateCarrier, nil
		}

		conn, err := adoptConnectedSocket(original)
		if conn != nil {
			t.Fatal("a replacement acquired after the resumed pause must not be adopted")
		}
		if err == nil || !strings.Contains(err.Error(), budgetMessage) {
			t.Fatalf("error = %v, want the adoption budget error", err)
		}
		var notVisible *connectedContextNotVisible
		if !errors.As(err, &notVisible) {
			t.Fatalf("error = %v, want the last connected-context observation retained", err)
		}
		if len(seams.dupInputs) != 1 {
			t.Fatalf("duplication calls = %v, want exactly one: no replacement after the resumed pause", seams.dupInputs)
		}
		if len(*pauses) != 1 || (*pauses)[0] != adoptContextPause {
			t.Fatalf("pauses = %v, want one recorded acquisition pause", *pauses)
		}
		if len(seams.closeInputs) != 1 || seams.closeInputs[0] != retiredCarrier {
			t.Fatalf("closesocket inputs = %v, want exactly the retired invisible-context carrier %#x", seams.closeInputs, retiredCarrier)
		}
		if seams.adopter.calls != 0 {
			t.Fatalf("adopter calls = %d, want no adoption carrier", seams.adopter.calls)
		}
	})

	t.Run("late-ready-carrier-retired-once-without-adoption", func(t *testing.T) {
		start := time.Now()
		seams := installAdoptionSeams(t, lateCarrier, nil)
		installAdoptionClock(t, start, start.Add(time.Millisecond), start.Add(adoptContextBudget))
		duplicateForAdoption = func(handle windows.Handle) (windows.Handle, error) {
			seams.dupInputs = append(seams.dupInputs, handle)
			return lateCarrier, nil
		}

		conn, err := adoptConnectedSocket(original)
		if conn != nil {
			t.Fatal("a carrier that became ready after the budget must not be adopted")
		}
		if err == nil || !strings.Contains(err.Error(), budgetMessage) {
			t.Fatalf("error = %v, want the adoption budget error", err)
		}
		if len(seams.dupInputs) != 1 {
			t.Fatalf("duplication calls = %v, want exactly one", seams.dupInputs)
		}
		if len(seams.closeInputs) != 1 || seams.closeInputs[0] != lateCarrier {
			t.Fatalf("closesocket inputs = %v, want the late carrier %#x retired exactly once", seams.closeInputs, lateCarrier)
		}
		if seams.adopter.calls != 0 {
			t.Fatalf("adopter calls = %d, want no adoption", seams.adopter.calls)
		}
	})

	t.Run("late-ready-carrier-close-failure-keeps-unresolved-token", func(t *testing.T) {
		ambiguous := errors.New("injected ambiguous late carrier close failure")
		start := time.Now()
		seams := installAdoptionSeams(t, lateCarrier, nil)
		seams.closeErrors = []error{ambiguous}
		installAdoptionClock(t, start, start.Add(time.Millisecond), start.Add(adoptContextBudget))
		duplicateForAdoption = func(handle windows.Handle) (windows.Handle, error) {
			seams.dupInputs = append(seams.dupInputs, handle)
			return lateCarrier, nil
		}

		conn, err := adoptConnectedSocket(original)
		if conn != nil {
			t.Fatal("an unresolved late carrier must not be published")
		}
		var unresolved *unresolvedSocketRetirement
		if !errors.As(err, &unresolved) || unresolved.handle != lateCarrier {
			t.Fatalf("error = %v, want an unresolved-retirement token for the late carrier %#x", err, lateCarrier)
		}
		if !hasUnresolvedRetirement(err) {
			t.Fatalf("error = %v, want the retirement obligation that keeps the attempt charge", err)
		}
		if !strings.Contains(err.Error(), budgetMessage) {
			t.Fatalf("error = %v, want the budget cause retained next to the token", err)
		}
		if len(seams.closeInputs) != 1 || seams.closeInputs[0] != lateCarrier {
			t.Fatalf("closesocket inputs = %v, want exactly one attempt for the late carrier", seams.closeInputs)
		}
		if seams.adopter.calls != 0 {
			t.Fatalf("adopter calls = %d, want no adoption", seams.adopter.calls)
		}
	})

	t.Run("timely-ready-carrier-is-adopted", func(t *testing.T) {
		start := time.Now()
		seams := installAdoptionSeams(t, lateCarrier, nil)
		installAdoptionClock(t, start, start, start.Add(time.Millisecond))
		duplicateForAdoption = func(handle windows.Handle) (windows.Handle, error) {
			seams.dupInputs = append(seams.dupInputs, handle)
			return lateCarrier, nil
		}

		conn, err := adoptConnectedSocket(original)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if conn != seams.conn {
			t.Fatalf("returned connection = %v, want the adopted connection", conn)
		}
		if len(seams.dupInputs) != 1 || len(seams.adopter.inputs) != 1 || seams.adopter.inputs[0] != lateCarrier {
			t.Fatalf("duplication calls = %v, adopter inputs = %v, want one carrier adopted inside the budget", seams.dupInputs, seams.adopter.inputs)
		}
		if len(seams.closeInputs) != 0 {
			t.Fatalf("closesocket calls = %v, want no carrier close after a transfer", seams.closeInputs)
		}
		_ = conn.Close()
	})
}

// installOriginalCloseSeam replaces the original-socket disposal seam for one
// subtest and records every closesocket it received.
func installOriginalCloseSeam(t *testing.T, errs ...error) *[]windows.Handle {
	t.Helper()
	original := closeOriginalSocket
	t.Cleanup(func() { closeOriginalSocket = original })
	var calls []windows.Handle
	closeOriginalSocket = func(handle windows.Handle) error {
		calls = append(calls, handle)
		if len(calls) <= len(errs) {
			return errs[len(calls)-1]
		}
		return nil
	}
	return &calls
}

// TestWA1OriginalSocketRetirementContract pins the disposal contract of the
// original native socket: exactly one owner and one socket API, a documented
// WSAEWOULDBLOCK outcome retried by that owner, an ambiguous outcome reported
// as an unresolved descriptor instead of a blind numeric retry, and a close
// failure that stays visible.
func TestWA1OriginalSocketRetirementContract(t *testing.T) {
	handle := windows.Handle(0x42)
	ambiguous := errors.New("injected ambiguous original close failure")

	t.Run("proven-release", func(t *testing.T) {
		calls := installOriginalCloseSeam(t)
		if err := retireOriginalSocket(handle); err != nil {
			t.Fatalf("error = %v, want a proven release", err)
		}
		if len(*calls) != 1 || (*calls)[0] != handle {
			t.Fatalf("closesocket calls = %v, want exactly one with %#x", *calls, handle)
		}
	})

	t.Run("wouldblock-retried-then-proven", func(t *testing.T) {
		calls := installOriginalCloseSeam(t, windows.WSAEWOULDBLOCK, nil)
		err := retireOriginalSocket(handle)
		if err == nil {
			t.Fatal("a close that reported WSAEWOULDBLOCK must stay visible")
		}
		var unresolved *unresolvedSocketRetirement
		if errors.As(err, &unresolved) {
			t.Fatalf("error = %v, want no unresolved token after a successful retry", err)
		}
		if len(*calls) != 2 {
			t.Fatalf("closesocket calls = %d, want the original attempt plus one retry", len(*calls))
		}
	})

	t.Run("ambiguous-no-retry", func(t *testing.T) {
		calls := installOriginalCloseSeam(t, ambiguous)
		err := retireOriginalSocket(handle)
		var unresolved *unresolvedSocketRetirement
		if !errors.As(err, &unresolved) || unresolved.handle != handle || !errors.Is(err, ambiguous) {
			t.Fatalf("error = %v, want an unresolved token for %#x carrying the close error", err, handle)
		}
		if len(*calls) != 1 {
			t.Fatalf("closesocket calls = %v, want no blind numeric retry", *calls)
		}
	})

	t.Run("wouldblock-retry-failure-retains-token", func(t *testing.T) {
		calls := installOriginalCloseSeam(t, windows.WSAEWOULDBLOCK, ambiguous)
		err := retireOriginalSocket(handle)
		var unresolved *unresolvedSocketRetirement
		if !errors.As(err, &unresolved) || !errors.Is(err, ambiguous) {
			t.Fatalf("error = %v, want an unresolved token carrying the retry error", err)
		}
		if len(*calls) != 2 {
			t.Fatalf("closesocket calls = %d, want one retry before the ambiguous error stops it", len(*calls))
		}
	})
}

// TestWA1AttemptRetirementRollsBackAndKeepsCharge pins what the deferred
// retirement does with the rest of the attempt: an adopted connection is never
// published while the original socket is unretired, an unproven release keeps
// the admission charge instead of faking a released descriptor, and a proven
// release leaves the atomically recorded charge to its existing owner.
func TestWA1AttemptRetirementRollsBackAndKeepsCharge(t *testing.T) {
	handle := windows.Handle(0x42)
	attemptErr := errors.New("injected attempt error")
	ambiguous := errors.New("injected ambiguous original close failure")

	t.Run("unproven-release-rolls-back-and-keeps-charge", func(t *testing.T) {
		client, server := net.Pipe()
		t.Cleanup(func() { _ = server.Close() })
		installOriginalCloseSeam(t, ambiguous)
		state := attemptRetirement{handle: handle, conn: client, holdOwned: true, err: attemptErr}
		state.retire()
		if state.conn != nil {
			t.Fatal("the adopted connection must be rolled back")
		}
		if _, err := client.Write([]byte("x")); err == nil {
			t.Fatal("the rolled-back connection is still usable")
		}
		if state.holdOwned {
			t.Fatal("an unproven release must keep the attempt's admission charge")
		}
		if !errors.Is(state.err, attemptErr) {
			t.Fatalf("error = %v, want the attempt error preserved", state.err)
		}
		var unresolved *unresolvedSocketRetirement
		if !errors.As(state.err, &unresolved) || !errors.Is(state.err, ambiguous) {
			t.Fatalf("error = %v, want the retirement error joined with the attempt error", state.err)
		}
	})

	t.Run("proven-release-keeps-published-connection", func(t *testing.T) {
		client, server := net.Pipe()
		t.Cleanup(func() {
			_ = client.Close()
			_ = server.Close()
		})
		calls := installOriginalCloseSeam(t)
		state := attemptRetirement{handle: handle, conn: client, holdOwned: true}
		state.retire()
		if state.conn != client || state.err != nil || !state.holdOwned {
			t.Fatalf("state = %+v, want the connection kept and the charge discharged", state)
		}
		if len(*calls) != 1 {
			t.Fatalf("closesocket calls = %d, want exactly one", len(*calls))
		}
	})

	t.Run("wouldblock-retried-then-proven-rolls-back", func(t *testing.T) {
		client, server := net.Pipe()
		t.Cleanup(func() { _ = server.Close() })
		installOriginalCloseSeam(t, windows.WSAEWOULDBLOCK, nil)
		state := attemptRetirement{handle: handle, conn: client, holdOwned: true, err: attemptErr}
		state.retire()
		var unresolved *unresolvedSocketRetirement
		if errors.As(state.err, &unresolved) {
			t.Fatalf("error = %v, want no unresolved token after a successful retry", state.err)
		}
		if state.conn != nil {
			t.Fatal("a close that reported an error still rolls the connection back")
		}
		if !errors.Is(state.err, attemptErr) || !strings.Contains(state.err.Error(), "desync: retire original socket") {
			t.Fatalf("error = %v, want the attempt and retirement errors visible", state.err)
		}
		if !state.holdOwned {
			t.Fatal("a proven release must discharge the charge through its existing owner")
		}
	})

	t.Run("clean-retirement-keeps-connection", func(t *testing.T) {
		client, server := net.Pipe()
		t.Cleanup(func() {
			_ = client.Close()
			_ = server.Close()
		})
		installOriginalCloseSeam(t)
		state := attemptRetirement{handle: handle, conn: client, holdOwned: true}
		state.retire()
		if state.conn == nil || state.err != nil || !state.holdOwned {
			t.Fatalf("state = %+v, want an untouched connection and a dischargeable charge", state)
		}
	})
}

// failingCloseConn makes only Close fail so a rollback error can be observed
// without any socket. The underlying conn is still closed once, and closes
// counts those one-shot Close calls.
type failingCloseConn struct {
	net.Conn
	closeErr error
	closes   int
}

func (c *failingCloseConn) Close() error {
	c.closes++
	_ = c.Conn.Close()
	return c.closeErr
}

// partialWriteConn accepts only a scripted prefix of each Write and then
// reports the injected error, so the remainder progress contract is observable
// without a real socket failure.
type partialWriteConn struct {
	net.Conn
	writes   int
	writeN   int
	writeErr error
	payloads [][]byte
	closes   int
}

func (c *partialWriteConn) Write(payload []byte) (int, error) {
	c.writes++
	c.payloads = append(c.payloads, append([]byte(nil), payload...))
	if c.writeN > 0 {
		return c.writeN, c.writeErr
	}
	return 0, c.writeErr
}

func (c *partialWriteConn) Close() error {
	c.closes++
	_ = c.Conn.Close()
	return nil
}

// assertOpaqueAdoptionRetirement checks the shared marker contract of the
// adoption boundary: the typed stage, the exact wrapped cause, the conservative
// unresolved-retirement classification and a diagnostic that renders without a
// panic.
func assertOpaqueAdoptionRetirement(t *testing.T, err error, stage string, cause error) {
	t.Helper()
	var opaque *opaqueUnprovenAdoptionRetirement
	if !errors.As(err, &opaque) {
		t.Fatalf("error = %v, want the opaque unproven-adoption-retirement marker", err)
	}
	if opaque.stage != stage {
		t.Fatalf("marker stage = %q, want %q", opaque.stage, stage)
	}
	if !errors.Is(err, cause) || !errors.Is(opaque, cause) {
		t.Fatalf("error = %v, marker = %v, want the marker cause %v preserved", err, opaque, cause)
	}
	if !hasUnresolvedRetirement(err) {
		t.Fatalf("error = %v, want the marker classified as an unresolved retirement", err)
	}
	rendered := captureStringPanic(t, "opaque adoption retirement marker", err.Error)
	if !strings.Contains(rendered, stage) || !strings.Contains(rendered, cause.Error()) {
		t.Fatalf("rendered error = %q, want the stage %q and the cause %q", rendered, stage, cause)
	}
}

// assertNoOpaqueAdoptionRetirement checks that a failure outside the one
// adoption-rollback boundary carries no opaque charge.
func assertNoOpaqueAdoptionRetirement(t *testing.T, err error) {
	t.Helper()
	var opaque *opaqueUnprovenAdoptionRetirement
	if errors.As(err, &opaque) {
		t.Fatalf("error = %v, want no opaque adoption-retirement marker", err)
	}
}

// TestWA4RemainderWriteProgress pins the adjacent remainder repair: exactly the
// suffix after the native accepted count is written, the actual written
// progress is preserved on error, the connection is rolled back exactly once,
// and a bad rollback Close keeps the existing opaque marker. No reconnect or
// replay exists at this boundary.
func TestWA4RemainderWriteProgress(t *testing.T) {
	rollbackSentinel := errors.New("injected remainder rollback failure")
	writeSentinel := errors.New("injected remainder write failure")
	payload := []byte("abcdef")

	t.Run("only-unwritten-suffix", func(t *testing.T) {
		client, peer := net.Pipe()
		t.Cleanup(func() {
			_ = client.Close()
			_ = peer.Close()
		})
		received := make(chan []byte, 1)
		go func() {
			buffer := make([]byte, len(payload))
			n, _ := peer.Read(buffer)
			received <- buffer[:n]
		}()
		written, err := writeAdoptedRemainder(client, payload, 2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if written != len(payload) {
			t.Fatalf("written = %d, want the full accepted progress %d", written, len(payload))
		}
		if got := <-received; string(got) != "cdef" {
			t.Fatalf("peer received %q, want only the unwritten suffix %q", got, "cdef")
		}
	})

	t.Run("write-error-keeps-progress-and-rolls-back-once", func(t *testing.T) {
		client, peer := net.Pipe()
		t.Cleanup(func() { _ = peer.Close() })
		partial := &partialWriteConn{Conn: client, writeN: 1, writeErr: writeSentinel}
		written, err := writeAdoptedRemainder(partial, payload, 2)
		if !errors.Is(err, writeSentinel) {
			t.Fatalf("error = %v, want the write failure", err)
		}
		if written != 3 {
			t.Fatalf("written = %d, want the actual accepted 2 + written remainder 1", written)
		}
		if partial.closes != 1 {
			t.Fatalf("adopted Close calls = %d, want exactly one rollback", partial.closes)
		}
		if partial.writes != 1 || string(partial.payloads[0]) != "cdef" {
			t.Fatalf("writes = %d payloads = %q, want exactly the suffix %q with no replay", partial.writes, partial.payloads, "cdef")
		}
		assertNoOpaqueAdoptionRetirement(t, err)
	})

	t.Run("bad-rollback-keeps-charge", func(t *testing.T) {
		client, peer := net.Pipe()
		t.Cleanup(func() { _ = peer.Close() })
		partial := &partialWriteConn{Conn: client, writeN: 0, writeErr: writeSentinel}
		badRollback := &failingCloseConn{Conn: partial, closeErr: rollbackSentinel}
		written, err := writeAdoptedRemainder(badRollback, payload, 2)
		if !errors.Is(err, writeSentinel) || !errors.Is(err, rollbackSentinel) {
			t.Fatalf("error = %v, want both the write and rollback identities", err)
		}
		if written != 2 {
			t.Fatalf("written = %d, want the accepted count preserved", written)
		}
		if badRollback.closes != 1 {
			t.Fatalf("adopted Close calls = %d, want exactly one rollback", badRollback.closes)
		}
		assertOpaqueAdoptionRetirement(t, err, adoptionRetirementStageAdoptedRollback, rollbackSentinel)
	})
}

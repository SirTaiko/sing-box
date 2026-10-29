//go:build windows

package desync

// W3 real-backend regressions: these drive the shipped Windows sender against
// real loopback TCP sockets and the real overlapped WSASend / completion-event /
// WSAGetOverlappedResult / CancelIoEx API. The seams are only *observed*
// (the wrapper delegates to the real functions and records their return), never
// substituted, so a PASS here means the native path ran for real. Complements
// the injected-seam lifecycle fixtures, which cannot prove kernel behaviour.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

type w3RealFlow struct {
	t      *testing.T
	client *net.TCPConn
	peer   *net.TCPConn
	holder *testAdmissionHolder
	sender streamSender
	native *windowsSender
}

func w3Pattern(size int, seed byte) []byte {
	buffer := make([]byte, size)
	for index := range buffer {
		buffer[index] = byte((index*7 + int(seed)*31) & 0xFF)
	}
	return buffer
}

// w3SmallBuffersControl pins the kernel socket buffers at connect time, before
// the TCP window scale is negotiated, so a large send really has to stay
// outstanding instead of completing synchronously into an autotuned buffer.
func w3SmallBuffersControl(receive int, send int) func(network, address string, conn syscall.RawConn) error {
	return func(network, address string, conn syscall.RawConn) error {
		var optionErr error
		if err := conn.Control(func(fd uintptr) {
			handle := windows.Handle(fd)
			if receive > 0 {
				if err := windows.SetsockoptInt(handle, windows.SOL_SOCKET, windows.SO_RCVBUF, receive); err != nil {
					optionErr = err
					return
				}
			}
			if send > 0 {
				if err := windows.SetsockoptInt(handle, windows.SOL_SOCKET, windows.SO_SNDBUF, send); err != nil {
					optionErr = err
					return
				}
			}
		}); err != nil {
			return err
		}
		return optionErr
	}
}

func w3OpenFlow(t *testing.T, deadline func() time.Time) *w3RealFlow {
	t.Helper()
	listenConfig := net.ListenConfig{Control: w3SmallBuffersControl(2048, 0)}
	listener, err := listenConfig.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback: %v", err)
	}
	defer listener.Close()
	type acceptOutcome struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptOutcome, 1)
	go func() {
		conn, acceptErr := listener.(*net.TCPListener).Accept()
		accepted <- acceptOutcome{conn: conn, err: acceptErr}
	}()
	dialer := net.Dialer{Timeout: 5 * time.Second, Control: w3SmallBuffersControl(0, 4096)}
	dialed, err := dialer.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial loopback: %v", err)
	}
	outcome := <-accepted
	if outcome.err != nil {
		dialed.Close()
		t.Fatalf("accept loopback: %v", outcome.err)
	}
	client := dialed.(*net.TCPConn)
	peer := outcome.conn.(*net.TCPConn)
	holder := newTestAdmissionHolder()
	wrapped := &testAdmissionConn{Conn: client, holder: holder, native: client}
	sender, err := newPlatformStreamNative().NewSender(wrapped, deadline)
	if err != nil {
		client.Close()
		peer.Close()
		t.Fatalf("NewSender on a real loopback socket: %v", err)
	}
	native, ok := sender.(*windowsSender)
	if !ok {
		client.Close()
		peer.Close()
		t.Fatalf("NewSender returned %T, want *windowsSender", sender)
	}
	flow := &w3RealFlow{t: t, client: client, peer: peer, holder: holder, sender: sender, native: native}
	t.Cleanup(func() {
		if canceler, ok := sender.(streamSenderCanceler); ok {
			canceler.CancelPending()
		}
		if releaser, ok := sender.(streamSenderReleaser); ok {
			releaser.Release()
		}
		client.Close()
		peer.Close()
	})
	return flow
}

// w3ObserveWSASend records the real WSASend return value of every submission.
func w3ObserveWSASend(t *testing.T) <-chan error {
	t.Helper()
	original := windowsWSASend
	observed := make(chan error, 64)
	windowsWSASend = func(handle windows.Handle, bufs *windows.WSABuf, count uint32, sent *uint32, flags uint32, overlapped *windows.Overlapped, routine *byte) error {
		err := original(handle, bufs, count, sent, flags, overlapped, routine)
		select {
		case observed <- err:
		default:
		}
		return err
	}
	t.Cleanup(func() { windowsWSASend = original })
	return observed
}

func w3WaitPendingSubmission(t *testing.T, observed <-chan error) {
	t.Helper()
	select {
	case err := <-observed:
		if !errors.Is(err, windows.ERROR_IO_PENDING) {
			t.Fatalf("WSASend returned %v, want the real ERROR_IO_PENDING: the pending-I/O path was not exercised", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no real WSASend submission observed")
	}
}

// w3PinSmallBuffers records the negotiated buffer sizes and bounds the peer's
// blocked reads, so the pending-I/O tests fail loudly if the small buffers were
// not applied before the handshake.
func w3PinSmallBuffers(t *testing.T, flow *w3RealFlow) {
	t.Helper()
	sendBuffer, err := windows.GetsockoptInt(flow.native.handle, windows.SOL_SOCKET, windows.SO_SNDBUF)
	if err != nil {
		t.Fatalf("SO_SNDBUF: %v", err)
	}
	peerRaw, err := flow.peer.SyscallConn()
	if err != nil {
		t.Fatalf("peer SyscallConn: %v", err)
	}
	var receiveBuffer int
	var optionErr error
	if err := peerRaw.Control(func(fd uintptr) {
		receiveBuffer, optionErr = windows.GetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_RCVBUF)
	}); err != nil {
		t.Fatalf("peer Control: %v", err)
	}
	if optionErr != nil {
		t.Fatalf("SO_RCVBUF: %v", optionErr)
	}
	t.Logf("socket buffers: SO_SNDBUF=%d SO_RCVBUF=%d", sendBuffer, receiveBuffer)
	if sendBuffer > 64*1024 || receiveBuffer > 64*1024 {
		t.Fatalf("small buffers were not applied before connect: SO_SNDBUF=%d SO_RCVBUF=%d", sendBuffer, receiveBuffer)
	}
	if err := flow.peer.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
		t.Fatalf("peer read deadline: %v", err)
	}
}

// w3PrimeBlockedSocket fills the loopback socket with one send that the kernel
// completes synchronously (observed natively: the first 1 MiB is accepted into
// AFD's queue even with a 4 KiB SO_SNDBUF). Every later send is then genuinely
// outstanding, which is what the pending-I/O regressions need.
func w3PrimeBlockedSocket(t *testing.T, flow *w3RealFlow) []byte {
	t.Helper()
	prime := w3Pattern(1024*1024, 23)
	count, err := flow.sender.Send(prime, sendOptions{})
	if err != nil || count != len(prime) {
		t.Fatalf("priming send: count=%d err=%v", count, err)
	}
	return prime
}

// w3SubmitPending starts one real Send and waits until the observed submission
// is the genuine ERROR_IO_PENDING. It returns the send outcome channel.
func w3SubmitPending(t *testing.T, flow *w3RealFlow, observed <-chan error, payload []byte) <-chan struct {
	count int
	err   error
} {
	t.Helper()
	outcome := make(chan struct {
		count int
		err   error
	}, 1)
	go func() {
		count, err := flow.sender.Send(payload, sendOptions{})
		outcome <- struct {
			count int
			err   error
		}{count: count, err: err}
	}()
	w3WaitPendingSubmission(t, observed)
	return outcome
}

func w3WaitRetired(t *testing.T, sender *windowsSender) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		buffer, closed, sending := v9SenderState(sender)
		if buffer == 0 && !sending && closed {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	buffer, closed, sending := v9SenderState(sender)
	t.Fatalf("sender never retired: retained=%d eventClosed=%v sending=%v", buffer, closed, sending)
}

func w3ReadExact(t *testing.T, conn net.Conn, size int) []byte {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buffer := make([]byte, size)
	if _, err := io.ReadFull(conn, buffer); err != nil {
		t.Fatalf("read %d bytes: %v", size, err)
	}
	return buffer
}

// TestW3RealSendDeliversExactBytesAndCount: a real overlapped WSASend on a real
// loopback socket returns the kernel-reported count and the peer receives
// exactly the submitted bytes.
func TestW3RealSendDeliversExactBytesAndCount(t *testing.T) {
	flow := w3OpenFlow(t, nil)
	payload := w3Pattern(48*1024, 3)
	received := make(chan []byte, 1)
	go func() { received <- w3ReadExact(t, flow.peer, len(payload)) }()
	written, err := flow.sender.Send(payload, sendOptions{})
	if err != nil {
		t.Fatalf("real Send: %v", err)
	}
	if written != len(payload) {
		t.Fatalf("Send counted %d of %d bytes", written, len(payload))
	}
	if got := <-received; !bytes.Equal(got, payload) {
		t.Fatalf("peer received %d bytes that differ from the submitted payload", len(got))
	}
}

// TestW3RealIndependentEventOverlappedAndSocket: each sender owns a distinct
// completion event, OVERLAPPED and socket handle, and the OVERLAPPED points at
// its own event. Real concurrent sends on both senders keep that identity.
func TestW3RealIndependentEventOverlappedAndSocket(t *testing.T) {
	first := w3OpenFlow(t, nil)
	second := w3OpenFlow(t, nil)
	if first.native.event == 0 || second.native.event == 0 {
		t.Fatalf("completion events not created: %v %v", first.native.event, second.native.event)
	}
	if first.native.event == second.native.event {
		t.Fatalf("two senders share one completion event: %v", first.native.event)
	}
	if &first.native.overlapped == &second.native.overlapped {
		t.Fatal("two senders share one OVERLAPPED")
	}
	if first.native.overlapped.HEvent != first.native.event || second.native.overlapped.HEvent != second.native.event {
		t.Fatal("OVERLAPPED.HEvent is not bound to its own sender's completion event")
	}
	if first.native.handle == second.native.handle {
		t.Fatalf("two senders share one socket handle: %v", first.native.handle)
	}
	for _, flow := range []*w3RealFlow{first, second} {
		raw, err := flow.client.SyscallConn()
		if err != nil {
			t.Fatalf("SyscallConn: %v", err)
		}
		var socketHandle windows.Handle
		if err := raw.Control(func(fd uintptr) { socketHandle = windows.Handle(fd) }); err != nil {
			t.Fatalf("Control: %v", err)
		}
		if socketHandle != flow.native.handle {
			t.Fatalf("sender handle %v is not its own socket %v", flow.native.handle, socketHandle)
		}
	}
	payloadFirst := w3Pattern(4096, 11)
	payloadSecond := w3Pattern(4096, 29)
	gotFirst := make(chan []byte, 1)
	gotSecond := make(chan []byte, 1)
	go func() { gotFirst <- w3ReadExact(t, first.peer, len(payloadFirst)) }()
	go func() { gotSecond <- w3ReadExact(t, second.peer, len(payloadSecond)) }()
	var wg sync.WaitGroup
	for index, item := range []struct {
		flow    *w3RealFlow
		payload []byte
	}{{first, payloadFirst}, {second, payloadSecond}} {
		wg.Add(1)
		go func(index int, flow *w3RealFlow, payload []byte) {
			defer wg.Done()
			if count, err := flow.sender.Send(payload, sendOptions{}); err != nil || count != len(payload) {
				t.Errorf("concurrent sender %d: count=%d err=%v", index, count, err)
			}
		}(index, item.flow, item.payload)
	}
	wg.Wait()
	if !bytes.Equal(<-gotFirst, payloadFirst) {
		t.Fatal("first flow received foreign bytes")
	}
	if !bytes.Equal(<-gotSecond, payloadSecond) {
		t.Fatal("second flow received foreign bytes")
	}
}

// TestW3RealOverlappingRecvWithPendingSend: a real overlapped WSASend stays
// pending on the socket while the application reads the return direction of the
// same handle; after the peer drains the socket both directions carry their
// exact bytes (no shared buffer/event corruption, no direction deadlock).
func TestW3RealOverlappingRecvWithPendingSend(t *testing.T) {
	flow := w3OpenFlow(t, nil)
	w3PinSmallBuffers(t, flow)
	downstream := w3Pattern(256*1024, 5)
	upstream := w3Pattern(512*1024, 7)
	prime := w3PrimeBlockedSocket(t, flow)
	observed := w3ObserveWSASend(t)
	peerWriteErr := make(chan error, 1)
	go func() {
		_, err := flow.peer.Write(downstream)
		peerWriteErr <- err
	}()
	type sendOutcome struct {
		count int
		err   error
	}
	sent := w3SubmitPending(t, flow, observed, upstream)
	// Overlap: read the return direction while the overlapped send is pending.
	receivedDownstream := w3ReadExact(t, flow.client, len(downstream))
	if err := <-peerWriteErr; err != nil {
		t.Fatalf("peer write: %v", err)
	}
	if !bytes.Equal(receivedDownstream, downstream) {
		t.Fatal("return direction corrupted while a send was pending")
	}
	expectedUpstream := append(append([]byte(nil), prime...), upstream...)
	receivedUpstream := make(chan []byte, 1)
	go func() { receivedUpstream <- w3ReadExact(t, flow.peer, len(expectedUpstream)) }()
	outcome := <-sent
	if outcome.err != nil {
		t.Fatalf("pending real send: %v", outcome.err)
	}
	if outcome.count != len(upstream) {
		t.Fatalf("pending real send counted %d of %d", outcome.count, len(upstream))
	}
	if !bytes.Equal(<-receivedUpstream, expectedUpstream) {
		t.Fatal("forward direction bytes differ after the overlapping read")
	}
}

// TestW3RealConcurrentFlowsNoCrossContamination: several flows send distinct
// byte streams concurrently over real sockets; every peer must receive exactly
// its own stream.
func TestW3RealConcurrentFlowsNoCrossContamination(t *testing.T) {
	const flows = 4
	const messages = 48
	const size = 1024
	opened := make([]*w3RealFlow, flows)
	for index := range opened {
		opened[index] = w3OpenFlow(t, nil)
	}
	var wg sync.WaitGroup
	errs := make(chan error, flows*2)
	for index, flow := range opened {
		wg.Add(2)
		go func(index int, flow *w3RealFlow) {
			defer wg.Done()
			for message := 0; message < messages; message++ {
				payload := w3Pattern(size, byte(index*17+message))
				count, err := flow.sender.Send(payload, sendOptions{})
				if err != nil {
					errs <- fmt.Errorf("flow %d message %d send: %w", index, message, err)
					return
				}
				if count != len(payload) {
					errs <- fmt.Errorf("flow %d message %d counted %d/%d", index, message, count, len(payload))
					return
				}
			}
		}(index, flow)
		go func(index int, flow *w3RealFlow) {
			defer wg.Done()
			if err := flow.peer.SetReadDeadline(time.Now().Add(40 * time.Second)); err != nil {
				errs <- err
				return
			}
			buffer := make([]byte, size)
			for message := 0; message < messages; message++ {
				if _, err := io.ReadFull(flow.peer, buffer); err != nil {
					errs <- fmt.Errorf("flow %d message %d read: %w", index, message, err)
					return
				}
				want := w3Pattern(size, byte(index*17+message))
				if !bytes.Equal(buffer, want) {
					errs <- fmt.Errorf("flow %d message %d: cross-flow contamination", index, message)
					return
				}
			}
		}(index, flow)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestW3RealCancelPendingSendRetiresOwnership: the production close sequence
// (CancelPending then Release) against a genuinely pending overlapped send must
// return promptly with an unknown-prefix close, and the retained OVERLAPPED,
// event, buffer and admission reference must retire through the real
// cancellation completion.
func TestW3RealCancelPendingSendRetiresOwnership(t *testing.T) {
	flow := w3OpenFlow(t, nil)
	w3PinSmallBuffers(t, flow)
	w3PrimeBlockedSocket(t, flow)
	observed := w3ObserveWSASend(t)
	payload := w3Pattern(512*1024, 13)
	outcome := w3SubmitPending(t, flow, observed, payload)
	flow.sender.(streamSenderCanceler).CancelPending()
	flow.sender.(streamSenderReleaser).Release()
	select {
	case result := <-outcome:
		if result.count != 0 {
			t.Fatalf("cancelled send counted %d bytes; the aborted status carries no authoritative count", result.count)
		}
		if !errors.Is(result.err, net.ErrClosed) {
			t.Fatalf("cancelled send error = %v, want net.ErrClosed", result.err)
		}
		if !streamCompletionUnproven(result.err) {
			t.Fatalf("cancelled send error = %v, want the unknown-prefix marker", result.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Send never returned after CancelPending/Release with real I/O pending")
	}
	w3WaitRetired(t, flow.native)
	if acquired, released := flow.holder.counts(); acquired != released {
		t.Fatalf("admission references leaked: acquired=%d released=%d", acquired, released)
	}
}

// TestW3RealReleaseDefersEventCloseToSendEnd: Release while a real send is
// pending must not close the completion event under the kernel; the send stays
// valid, completes once the peer drains it, and only then retires the event.
func TestW3RealReleaseDefersEventCloseToSendEnd(t *testing.T) {
	flow := w3OpenFlow(t, nil)
	w3PinSmallBuffers(t, flow)
	prime := w3PrimeBlockedSocket(t, flow)
	observed := w3ObserveWSASend(t)
	payload := w3Pattern(512*1024, 17)
	outcome := w3SubmitPending(t, flow, observed, payload)
	flow.sender.(streamSenderReleaser).Release()
	if _, closed, _ := v9SenderState(flow.native); closed {
		t.Fatal("Release closed the completion event while an overlapped send was still pending")
	}
	expectedBytes := append(append([]byte(nil), prime...), payload...)
	received := make(chan []byte, 1)
	go func() { received <- w3ReadExact(t, flow.peer, len(expectedBytes)) }()
	select {
	case result := <-outcome:
		if result.err != nil {
			t.Fatalf("deferred-release send: %v", result.err)
		}
		if result.count != len(payload) {
			t.Fatalf("deferred-release send counted %d/%d", result.count, len(payload))
		}
	case <-time.After(20 * time.Second):
		t.Fatal("send did not complete after the peer drained the socket")
	}
	if !bytes.Equal(<-received, expectedBytes) {
		t.Fatal("deferred-release send delivered altered bytes")
	}
	w3WaitRetired(t, flow.native)
}

// TestW3RealDeadlineAbortsPendingSend: a write deadline that expires while the
// real overlapped send is pending must abort exactly that operation, report the
// deadline with an unknown prefix and retire the ownership.
func TestW3RealDeadlineAbortsPendingSend(t *testing.T) {
	flow := w3OpenFlow(t, nil)
	w3PinSmallBuffers(t, flow)
	w3PrimeBlockedSocket(t, flow)
	observed := w3ObserveWSASend(t)
	payload := w3Pattern(512*1024, 19)
	outcome := w3SubmitPending(t, flow, observed, payload)
	flow.native.SetWriteDeadline(time.Now().Add(150 * time.Millisecond))
	select {
	case result := <-outcome:
		if !errors.Is(result.err, os.ErrDeadlineExceeded) {
			t.Fatalf("deadline abort error = %v, want os.ErrDeadlineExceeded", result.err)
		}
		if result.count != 0 {
			t.Fatalf("deadline abort counted %d bytes", result.count)
		}
		if !streamCompletionUnproven(result.err) {
			t.Fatalf("deadline abort error = %v, want the unknown-prefix marker", result.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Send never returned after the write deadline expired on a pending overlapped send")
	}
	flow.sender.(streamSenderReleaser).Release()
	w3WaitRetired(t, flow.native)
	if acquired, released := flow.holder.counts(); acquired != released {
		t.Fatalf("admission references leaked: acquired=%d released=%d", acquired, released)
	}
}

// TestW3RealPeerResetSurfacesNativeError: after the peer resets the connection,
// a real WSASend must surface a native error instead of reporting a successful
// count.
func TestW3RealPeerResetSurfacesNativeError(t *testing.T) {
	flow := w3OpenFlow(t, nil)
	if err := flow.peer.SetLinger(0); err != nil {
		t.Fatalf("SetLinger: %v", err)
	}
	if err := flow.peer.Close(); err != nil {
		t.Fatalf("close peer: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	var lastErr error
	for attempt := 0; attempt < 16; attempt++ {
		count, err := flow.sender.Send(w3Pattern(2048, byte(attempt)), sendOptions{})
		if err != nil {
			lastErr = err
			if count != 0 {
				t.Fatalf("failed send counted %d bytes", count)
			}
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if lastErr == nil {
		t.Fatal("sends kept succeeding after the peer reset the connection: no native error surfaced")
	}
	if !errors.Is(lastErr, windows.WSAECONNRESET) && !errors.Is(lastErr, windows.WSAECONNABORTED) && !errors.Is(lastErr, windows.ERROR_OPERATION_ABORTED) {
		t.Fatalf("peer reset surfaced %v, want a native connection error", lastErr)
	}
}

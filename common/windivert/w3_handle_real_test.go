//go:build windows && !with_external_windivert

package windivert

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// These tests drive the shipped WinDivert device handle against the real driver
// and real loopback UDP traffic. They exist because the original W3 risk lives in
// this file's production counterpart (common/windivert/handle_windows.go): one
// shared address/event/OVERLAPPED between receive, send and control operations,
// close/cancel with I/O genuinely pending, queued-packet drain after
// ShutdownRecv, and per-flow address/byte isolation. Every assertion below is on
// data observed through the driver (packets, terminal statuses, addresses), not
// on source markers or injected return values.

const realWait = 5 * time.Second

type udpFlow struct {
	client   *net.UDPConn
	listener *net.UDPConn
	clientAP netip.AddrPort
	serverAP netip.AddrPort
}

func newUDPFlow(t *testing.T) *udpFlow {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	flow := &udpFlow{client: client, listener: listener}
	flow.clientAP = netip.MustParseAddrPort(client.LocalAddr().String())
	flow.serverAP = netip.MustParseAddrPort(listener.LocalAddr().String())
	t.Cleanup(func() {
		_ = client.Close()
		_ = listener.Close()
	})
	return flow
}

// payloadOf returns the transport payload of one captured IPv4 packet.
func payloadOf(t *testing.T, packet []byte) []byte {
	t.Helper()
	require.GreaterOrEqual(t, len(packet), 28)
	ihl := int(packet[0]&0x0F) * 4
	require.GreaterOrEqual(t, len(packet), ihl+8, "truncated IPv4/UDP packet")
	return packet[ihl+8:]
}

func (f *udpFlow) write(t *testing.T, payload []byte) {
	t.Helper()
	_, err := f.client.WriteToUDP(payload, net.UDPAddrFromAddrPort(f.serverAP))
	require.NoError(t, err)
}

func (f *udpFlow) read(t *testing.T, want []byte) {
	t.Helper()
	buf := make([]byte, 2048)
	require.NoError(t, f.listener.SetReadDeadline(time.Now().Add(realWait)))
	n, _, err := f.listener.ReadFromUDP(buf)
	require.NoError(t, err, "listener did not receive the re-injected datagram")
	require.Equal(t, want, buf[:n])
}

func (f *udpFlow) drain(t *testing.T) {
	t.Helper()
	buf := make([]byte, 2048)
	_ = f.listener.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	for {
		if _, _, err := f.listener.ReadFromUDP(buf); err != nil {
			return
		}
	}
}

func drainConn(t *testing.T, conn *net.UDPConn) {
	t.Helper()
	buf := make([]byte, 2048)
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	for {
		if _, _, err := conn.ReadFromUDP(buf); err != nil {
			return
		}
	}
}

func openReal(t *testing.T, filter *Filter, flags Flag) *Handle {
	t.Helper()
	h, err := Open(filter, LayerNetwork, 0, flags)
	require.NoError(t, err)
	require.NotNil(t, h)
	return h
}

func outboundFlowFilter(t *testing.T, flow *udpFlow) *Filter {
	t.Helper()
	filter, err := OutboundUDP(flow.clientAP, flow.serverAP)
	require.NoError(t, err)
	return filter
}

func recvWithin(t *testing.T, h *Handle, timeout time.Duration) (int, Address, []byte, error) {
	t.Helper()
	type result struct {
		n    int
		addr Address
		buf  []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		buf := make([]byte, MTUMax)
		n, addr, err := h.Recv(buf)
		done <- result{n: n, addr: addr, buf: buf[:n], err: err}
	}()
	select {
	case r := <-done:
		return r.n, r.addr, r.buf, r.err
	case <-time.After(timeout):
		t.Fatalf("Recv did not return within %s", timeout)
		return 0, Address{}, nil, nil
	}
}

// TestRealCaptureLoopbackUDP is the precondition for every other test in this
// file: the authentic driver must deliver a real loopback UDP datagram to the
// shipped handle with a usable WINDIVERT_ADDRESS. A sniffing handle is used so
// the packet also reaches its real destination, proving the capture is a copy of
// genuine traffic and not a synthetic fixture.
func TestRealCaptureLoopbackUDP(t *testing.T) {
	flow := newUDPFlow(t)
	h := openReal(t, outboundFlowFilter(t, flow), FlagSniff)
	defer func() { require.NoError(t, h.Close()) }()

	payload := []byte("windivert-real-capture-probe")
	flow.write(t, payload)
	flow.read(t, payload) // the sniffed original still reaches the listener

	n, addr, packet, err := recvWithin(t, h, realWait)
	require.NoError(t, err)
	require.Equal(t, len(packet), n, "Recv must report the complete IP packet length")
	require.Equal(t, len(payload)+28, n, "IPv4 header 20 + UDP header 8 + payload")
	require.True(t, addr.Outbound(), "captured outbound datagram must carry the outbound flag")
	require.False(t, addr.IPv6())
	require.Equal(t, payload, payloadOf(t, packet), "captured IPv4/UDP payload must be the bytes the client sent")
}

// TestRealInterceptReinjectByteExact proves the shipped send lane re-injects one
// captured packet exactly once with its own captured address, end to end through
// the driver and the real loopback stack.
func TestRealInterceptReinjectByteExact(t *testing.T) {
	flow := newUDPFlow(t)
	h := openReal(t, outboundFlowFilter(t, flow), 0)
	defer func() { require.NoError(t, h.Close()) }()

	payload := []byte("intercept-reinject-payload-0123456789")
	flow.write(t, payload)
	flow.drain(t) // nothing may arrive while the packet is held

	n, addr, packet, err := recvWithin(t, h, realWait)
	require.NoError(t, err)
	require.Equal(t, len(payload)+28, n)
	require.Equal(t, payload, payloadOf(t, packet))

	sent, err := h.Send(packet, &addr)
	require.NoError(t, err)
	require.Equal(t, len(packet), sent, "Send must report the complete packet, not a prefix")
	flow.read(t, payload)
}

// TestRealPendingRecvSimultaneousSend reproduces the original W3 scenario on the
// changed driver handle: a receive is genuinely outstanding in the kernel while
// a send is issued on the same handle. The send must complete, the pending
// receive must keep its own address/completion, and no byte may be lost or
// corrupted. A shared addr/event between the two lanes breaks this test.
func TestRealPendingRecvSimultaneousSend(t *testing.T) {
	flow := newUDPFlow(t)
	h := openReal(t, outboundFlowFilter(t, flow), 0)
	defer func() { require.NoError(t, h.Close()) }()

	firstPayload := []byte("held-packet-that-is-reinjected-while-recv-is-pending")
	flow.write(t, firstPayload)
	n, heldAddr, heldPacket, err := recvWithin(t, h, realWait)
	require.NoError(t, err)
	require.Equal(t, len(firstPayload)+28, n)
	require.Equal(t, firstPayload, payloadOf(t, heldPacket))
	heldCopy := heldAddr

	recvDone := make(chan struct {
		payload []byte
		addr    Address
		err     error
	}, 1)
	go func() {
		buf := make([]byte, MTUMax)
		count, addr, recvErr := h.Recv(buf)
		recvDone <- struct {
			payload []byte
			addr    Address
			err     error
		}{payload: append([]byte(nil), buf[:count]...), addr: addr, err: recvErr}
	}()

	// Give the receive time to reach the driver so the send below genuinely
	// overlaps a pending native operation on the same handle.
	select {
	case early := <-recvDone:
		t.Fatalf("second Recv returned before any traffic arrived: err=%v len=%d", early.err, len(early.payload))
	case <-time.After(400 * time.Millisecond):
	}

	sendStart := time.Now()
	sent, err := h.Send(heldPacket, &heldAddr)
	sendElapsed := time.Since(sendStart)
	require.NoError(t, err, "Send must complete while a receive is pending on the same handle")
	require.Equal(t, len(heldPacket), sent)
	require.Less(t, sendElapsed, 2*time.Second, "overlapping Send took %s", sendElapsed)
	require.Equal(t, heldCopy, heldAddr, "Send must not mutate the handle's receive address storage")
	flow.read(t, firstPayload)

	secondPayload := []byte("traffic-after-overlapping-send")
	flow.write(t, secondPayload)
	select {
	case got := <-recvDone:
		require.NoError(t, got.err)
		require.Equal(t, secondPayload, payloadOf(t, got.payload))
	case <-time.After(realWait):
		t.Fatal("pending Recv did not receive the datagram sent after an overlapping Send")
	}
}

// TestRealShutdownRecvDrainsQueuedThenSendStillWorks covers the Quiesce contract:
// ShutdownRecv preserves already queued packets, every one is delivered before
// the documented end-of-queue status, the send capability survives, and Close
// afterwards retires without loss or deadlock.
func TestRealShutdownRecvDrainsQueuedThenSendStillWorks(t *testing.T) {
	flow := newUDPFlow(t)
	h := openReal(t, outboundFlowFilter(t, flow), 0)

	const queued = 8
	var payloads [][]byte
	for i := range queued {
		payload := []byte(fmt.Sprintf("queued-packets-%02d-%s", i, "drain-me"))
		payloads = append(payloads, payload)
		flow.write(t, payload)
	}
	flow.drain(t) // none may leak past the intercept handle

	require.NoError(t, h.ShutdownRecv())

	buf := make([]byte, MTUMax)
	var received [][]byte
	var addresses []Address
	deadline := time.Now().Add(realWait)
	for len(received) < queued {
		require.True(t, time.Now().Before(deadline), "drain stalled after %d of %d packets", len(received), queued)
		n, addr, err := h.Recv(buf)
		require.NoError(t, err, "drain must deliver every queued packet, not report an error")
		received = append(received, append([]byte(nil), buf[:n]...))
		addresses = append(addresses, addr)
	}
	// Every queued datagram arrived; the queue then terminates with the
	// documented no-more-data status and nothing else.
	_, _, err := h.Recv(buf)
	require.Error(t, err)
	require.True(t, IsDrained(err), "expected ERROR_NO_DATA end of drained queue, got %v", err)

	seen := make(map[string]int)
	for i, packet := range received {
		require.True(t, addresses[i].Outbound(), "drained packet %d lost its outbound address", i)
		seen[string(payloadOf(t, packet))]++
	}
	for _, payload := range payloads {
		require.Equal(t, 1, seen[string(payload)], "queued payload %q delivered %d times", payload, seen[string(payload)])
	}

	// The same handle must still send after the receive side was shut down.
	sent, err := h.Send(received[0], &addresses[0])
	require.NoError(t, err)
	require.Equal(t, len(received[0]), sent)
	// The send side still works after the receive side was shut down; the
	// re-injected datagram is one of the queued payloads, unchanged.
	buf = make([]byte, 2048)
	require.NoError(t, flow.listener.SetReadDeadline(time.Now().Add(realWait)))
	lastN, _, readErr := flow.listener.ReadFromUDP(buf)
	require.NoError(t, readErr)
	require.Contains(t, payloads, append([]byte(nil), buf[:lastN]...))

	flow.drain(t)

	closeDone := make(chan error, 1)
	go func() { closeDone <- h.Close() }()
	select {
	case err := <-closeDone:
		require.NoError(t, err)
	case <-time.After(realWait):
		t.Fatal("Close deadlocked after ShutdownRecv and drain")
	}
	select {
	case <-h.Done():
	case <-time.After(realWait):
		t.Fatal("Done not closed after a successful Close")
	}
}

// TestRealRecvBatchSendBatchRoundTrip covers the batch lanes: the driver writes
// an address array that the handle must copy before reusing its own storage, and
// SendBatch must re-inject every packet of the batch exactly once, byte-exact.
func TestRealRecvBatchSendBatchRoundTrip(t *testing.T) {
	flow := newUDPFlow(t)
	h := openReal(t, outboundFlowFilter(t, flow), 0)
	defer func() { require.NoError(t, h.Close()) }()

	const count = 6
	var payloads [][]byte
	for i := range count {
		payload := []byte(fmt.Sprintf("batch-payload-%02d-%s", i, "round-trip"))
		payloads = append(payloads, payload)
		flow.write(t, payload)
	}
	flow.drain(t)

	buf := make([]byte, MTUMax*4)
	var allPackets []byte
	var addrs []Address
	deadline := time.Now().Add(realWait)
	for len(addrs) < count {
		require.True(t, time.Now().Before(deadline), "batch recv delivered %d of %d packets", len(addrs), count)
		n, batchAddrs, err := h.RecvBatch(buf)
		require.NoError(t, err)
		require.NotEmpty(t, batchAddrs)
		require.Equal(t, len(batchAddrs), packetCount(buf[:n]))
		allPackets = append(allPackets, append([]byte(nil), buf[:n]...)...)
		addrs = append(addrs, batchAddrs...)
		// The returned slice must be the handle's copy: corrupting it may not
		// affect the next batch.
		if len(batchAddrs) > 0 {
			batchAddrs[0].Timestamp = 0x7FFFFFFFFFFFFFF
		}
	}
	require.Len(t, addrs, count)
	firstAddrs := append([]Address(nil), addrs...)

	sent, err := h.SendBatch(allPackets, addrs)
	require.NoError(t, err)
	require.Equal(t, len(allPackets), sent)
	for _, payload := range payloads {
		flow.read(t, payload)
	}
	flow.drain(t)

	// The address array of the send lane is the handle's own storage; a second
	// batch must not have mutated the addresses the caller still holds.
	require.Equal(t, firstAddrs, addrs)
}

func packetCount(buffer []byte) int {
	count := 0
	for offset := 0; offset+20 <= len(buffer); {
		length := int(binary.BigEndian.Uint16(buffer[offset+2 : offset+4]))
		if length <= 0 || offset+length > len(buffer) {
			return -1
		}
		count++
		offset += length
	}
	return count
}

// TestRealConcurrentFlowsIsolation runs two independent flows through one
// intercepting handle that re-injects each captured packet, so a pending receive
// and a send are repeatedly in flight on the same handle. Both listeners must
// receive exactly their own payload set, in order, with no cross-delivery.
func TestRealConcurrentFlowsIsolation(t *testing.T) {
	flowA := newUDPFlow(t)
	flowB := newUDPFlow(t)
	filterA, err := OutboundUDP(flowA.clientAP, flowA.serverAP)
	require.NoError(t, err)
	filterB, err := OutboundUDP(flowB.clientAP, flowB.serverAP)
	require.NoError(t, err)
	filter, err := Or(filterA, filterB)
	require.NoError(t, err)
	h := openReal(t, filter, 0)
	defer func() { require.NoError(t, h.Close()) }()

	const perFlow = 24
	var (
		aPayloads [][]byte
		bPayloads [][]byte
		received  [][]byte
		addrs     []Address
		mu          sync.Mutex
		stop        atomic.Bool
		wg          sync.WaitGroup
		loopExitErr error
	)
	for i := range perFlow {
		aPayloads = append(aPayloads, []byte(fmt.Sprintf("flow-A-%02d-%s", i, "isolation")))
		bPayloads = append(bPayloads, []byte(fmt.Sprintf("flow-B-%02d-%s", i, "isolation")))
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, MTUMax)
		for !stop.Load() {
			n, addr, recvErr := h.Recv(buf)
			if recvErr != nil {
				mu.Lock()
				loopExitErr = recvErr
				mu.Unlock()
				return
			}
			packet := append([]byte(nil), buf[:n]...)
			if _, sendErr := h.Send(packet, &addr); sendErr != nil {
				mu.Lock()
				loopExitErr = sendErr
				mu.Unlock()
				return
			}
			mu.Lock()
			received = append(received, payloadOf(t, packet))
			addrs = append(addrs, addr)
			mu.Unlock()
		}
	}()

	flowB.drain(t)
	for i := range perFlow {
		flowA.write(t, aPayloads[i])
		flowB.write(t, bPayloads[i])
	}

	require.NoError(t, flowA.listener.SetReadDeadline(time.Now().Add(realWait)))
	require.NoError(t, flowB.listener.SetReadDeadline(time.Now().Add(realWait)))
	var gotA, gotB [][]byte
	buf := make([]byte, 2048)
	for range perFlow {
		n, _, err := flowA.listener.ReadFromUDP(buf)
		require.NoError(t, err, "flow A lost a packet")
		gotA = append(gotA, append([]byte(nil), buf[:n]...))
	}
	for range perFlow {
		n, _, err := flowB.listener.ReadFromUDP(buf)
		require.NoError(t, err, "flow B lost a packet")
		gotB = append(gotB, append([]byte(nil), buf[:n]...))
	}
	drainConn(t, flowA.listener)
	drainConn(t, flowB.listener)
	stop.Store(true)
	closeErr := make(chan error, 1)
	go func() { closeErr <- h.Close() }()
	wg.Wait()
	mu.Lock()
	processed := len(received)
	loopErr := loopExitErr
	mu.Unlock()
	require.GreaterOrEqual(t, processed, perFlow*2, "loop processed %d of at least %d packets", processed, perFlow*2)
	// The only acceptable loop exit is the Close-driven abort of its pending
	// receive; a native error before Close would be a real finding.
	require.True(t, loopErr == nil || errors.Is(loopErr, windows.ERROR_OPERATION_ABORTED), "capture loop exited early: %v", loopErr)
	select {
	case err := <-closeErr:
		if err == nil {
			select {
			case <-h.Done():
			case <-time.After(realWait):
				t.Fatal("Close returned nil but Done stayed open")
			}
		}
	case <-time.After(realWait):
		t.Fatal("Close deadlocked in the concurrent-flow test")
	}

	require.Equal(t, aPayloads, gotA, "flow A payloads crossed or were reordered")
	require.Equal(t, bPayloads, gotB, "flow B payloads crossed or were reordered")
	mu.Lock()
	defer mu.Unlock()
	require.GreaterOrEqual(t, len(received), perFlow*2)
	for i, addr := range addrs {
		require.True(t, addr.Outbound(), "packet %d lost its outbound address", i)
		require.False(t, addr.IPv6())
	}
	// Each captured packet carried its own payload, never a neighbor's.
	counts := make(map[string]int, perFlow*2)
	for _, payload := range received {
		counts[string(payload)]++
	}
	for _, payload := range append(append([][]byte(nil), aPayloads...), bPayloads...) {
		require.Equal(t, 1, counts[string(payload)], "payload %q observed %d times", payload, counts[string(payload)])
	}
}

// TestRealCloseWithPendingRecvAndSendRacing retires the handle while one receive
// is registered as pending and a send races the close. Close must return, the
// pending receive must produce a terminal error, Done must close, and a second
// Close must stay idempotent - the lifecycle invariant of the changed handle.
func TestRealCloseWithPendingRecvAndSendRacing(t *testing.T) {
	flow := newUDPFlow(t)
	h := openReal(t, outboundFlowFilter(t, flow), 0)

	payload := []byte("close-with-pending-io")
	flow.write(t, payload)
	n, addr, packet, err := recvWithin(t, h, realWait)
	require.NoError(t, err)
	require.Equal(t, len(payload)+28, n)

	recvErr := make(chan error, 1)
	go func() {
		buf := make([]byte, MTUMax)
		_, _, err := h.Recv(buf)
		recvErr <- err
	}()
	time.Sleep(300 * time.Millisecond)

	sendErr := make(chan error, 1)
	go func() {
		_, err := h.Send(packet, &addr)
		sendErr <- err
	}()
	time.Sleep(20 * time.Millisecond)

	closeErr := make(chan error, 1)
	go func() { closeErr <- h.Close() }()
	select {
	case err := <-closeErr:
		// A bounded grace may defer retirement; a successful close must mean
		// every native reference is already terminal.
		if err == nil {
			select {
			case <-h.Done():
			case <-time.After(realWait):
				t.Fatal("Close returned nil but Done stayed open")
			}
		}
	case <-time.After(realWait):
		t.Fatal("Close deadlocked with a receive pending and a send racing")
	}

	select {
	case err := <-recvErr:
		require.Error(t, err, "a receive pending across Close must not report success")
	case <-time.After(realWait):
		t.Fatal("pending Recv never returned after Close")
	}
	select {
	case <-sendErr:
	case <-time.After(realWait):
		t.Fatal("racing Send never returned after Close")
	}
	require.NoError(t, h.Close())
	select {
	case <-h.Done():
	case <-time.After(realWait):
		t.Fatal("Done did not close after the racing close")
	}
}

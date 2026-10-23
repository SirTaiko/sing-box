package desync

import (
	"errors"
	"net"
	"testing"

	"github.com/sagernet/sing-box/option"
)

// admissionCapConn exposes the admission capability of one real attempt lease
// and nothing else. The platform sender factory consumes it structurally
// before it inspects or touches the native source.
type admissionCapConn struct {
	net.Conn
	lease *Lease
}

func (c *admissionCapConn) AcquireNativeHold() (func(), error) {
	return c.lease.AcquireNativeHold()
}

// fakeWrites snapshots the memory connection's recorded writes.
func fakeWrites(conn *fakeConn) [][]byte {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return append([][]byte(nil), conn.writes...)
}

// TestForwardUnsentAdmissionRefusalKeepsProvenPrefix covers the refusal
// accounting contract directly: a refusal never forwards the tail, keeps the
// block prefix and adds only the fragment progress the sender proved.
func TestForwardUnsentAdmissionRefusalKeepsProvenPrefix(t *testing.T) {
	refusal := admissionRefused(errLeaseClosed)
	tests := []struct {
		name   string
		offset int
		sent   int
		want   int
	}{
		{name: "zero progress", offset: 0, sent: 0, want: 0},
		{name: "zero progress with block prefix", offset: 2, sent: 0, want: 2},
		{name: "proven fragment", offset: 0, sent: 2, want: 2},
		{name: "proven fragment with block prefix", offset: 2, sent: 2, want: 4},
		{name: "fragment is clamped to the remaining block", offset: 0, sent: 7, want: 6},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			conn := newFakeConn()
			wrapper := &streamConn{Conn: conn}
			written, err := wrapper.forwardUnsent([]byte("abcdef"), testCase.offset, testCase.sent, refusal)
			if written != testCase.want {
				t.Fatalf("written = %d, want %d", written, testCase.want)
			}
			if !errors.Is(err, ErrAdmissionRefused) {
				t.Fatalf("error = %v, want admission refusal", err)
			}
			if writes := fakeWrites(conn); len(writes) != 0 {
				t.Fatalf("refusal wrote %d time(s) to the connection, want 0 fallback writes", len(writes))
			}
		})
	}
}

// TestFirstSendRefusalKeepsMeasuredPrefix runs the real deferred first-send
// path. The pending write delivers the first transformed fragment, then the
// established native sender factory is refused because the owning engine
// closed before it acquired its hold. The measured count of the successful
// first fragment must survive that refusal, and the refused tail must never be
// forwarded.
func TestFirstSendRefusalKeepsMeasuredPrefix(t *testing.T) {
	engine, err := NewStateEngine(&option.DirectDesyncOptions{}, nil)
	if err != nil {
		t.Fatalf("NewStateEngine: %v", err)
	}
	lease, err := engine.NewAttempt(Intent{Transport: TransportTCP})
	if err != nil {
		_ = engine.Close()
		t.Fatalf("NewAttempt: %v", err)
	}
	if err = engine.Close(); err != nil {
		t.Fatalf("Engine.Close: %v", err)
	}
	pendingRaw := newFakeConn()
	established := &admissionCapConn{Conn: newFakeConn(), lease: lease}
	facade := &retainedDeferredConn{Conn: pendingRaw, pending: true, established: established}
	wrapper := &streamConn{
		Conn:   facade,
		config: &StreamConfig{native: newPlatformStreamNative()},
		cancel: make(chan struct{}),
		rule:   &streamRule{split: &streamSplitSpec{}, fixSegSet: true},
	}
	sender, err := wrapper.newNativeSender()
	if err != nil {
		t.Fatalf("newNativeSender: %v", err)
	}
	wrapper.sender = sender
	written, err := wrapper.sendBlock([]byte("ABCDEF"), []int{2}, ProtocolUnknown)
	if !errors.Is(err, ErrAdmissionRefused) {
		t.Fatalf("sendBlock error = %v, want admission refusal", err)
	}
	if written != 2 {
		t.Fatalf("refusal lost the measured first fragment: written = %d, want 2", written)
	}
	writes := fakeWrites(pendingRaw)
	if len(writes) != 1 || len(writes[0]) != 2 {
		t.Fatalf("pending writes = %v, want exactly the proven 2-byte first fragment", writes)
	}
}

// TestFirstSendStableControlKeepsFullCount is the positive control of the same
// path: with a live owner the first fragment and the following native send are
// both accounted. The native sender backend is the only substituted seam.
func TestFirstSendStableControlKeepsFullCount(t *testing.T) {
	pendingRaw := newFakeConn()
	native := &retainedFakeNative{}
	established := &retainedCapConn{Conn: newFakeConn(), holder: &retainedHolder{}}
	facade := &retainedDeferredConn{Conn: pendingRaw, pending: true, established: established}
	wrapper := &streamConn{
		Conn:   facade,
		config: &StreamConfig{native: native},
		cancel: make(chan struct{}),
		// skip_no_delay keeps the substituted plain sender applicable: the
		// control measures accounting, not corking.
		rule: &streamRule{split: &streamSplitSpec{}, fixSegSet: true, skipNoDelay: true},
	}
	sender, err := wrapper.newNativeSender()
	if err != nil {
		t.Fatalf("newNativeSender: %v", err)
	}
	wrapper.sender = sender
	written, err := wrapper.sendBlock([]byte("ABCDEF"), []int{2}, ProtocolUnknown)
	if err != nil {
		t.Fatalf("sendBlock: %v", err)
	}
	if written != 6 {
		t.Fatalf("written = %d, want the complete block 6", written)
	}
	writes := fakeWrites(pendingRaw)
	if len(writes) != 1 || len(writes[0]) != 2 {
		t.Fatalf("pending writes = %v, want the 2-byte first fragment", writes)
	}
	if calls, _ := native.state(); calls != 1 {
		t.Fatalf("native sender factory calls = %d, want 1", calls)
	}
}

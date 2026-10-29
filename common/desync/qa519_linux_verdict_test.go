//go:build linux

package desync

// The held-packet seam makes the NFQUEUE verdict sender asynchronous: a held
// original's terminal disposition is delivered from the replay path instead of
// the receive loop. A netlink Send or message-build error there used to be
// discarded, so a lost native disposition was reported as a clean completion.
// These cases pin the existing diagnostic owner (Lease.ReportNativeFailure /
// Lease.Err) at that seam; no retry or new ownership is involved.

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
)

type qa519VerdictConn struct {
	sent    []netlink.Message
	sendErr error
}

func (c *qa519VerdictConn) Receive() ([]netlink.Message, error) { return nil, errors.New("no receive") }

func (c *qa519VerdictConn) Execute(netlink.Message) ([]netlink.Message, error) { return nil, nil }

func (c *qa519VerdictConn) Send(message netlink.Message) (netlink.Message, error) {
	if c.sendErr != nil {
		return netlink.Message{}, c.sendErr
	}
	c.sent = append(c.sent, message)
	return netlink.Message{}, nil
}

func (c *qa519VerdictConn) SetReadDeadline(time.Time) error { return nil }

func (c *qa519VerdictConn) pending() (bool, error) { return false, nil }

func (c *qa519VerdictConn) boundPort() uint32 { return 0x51a00010 }

func (c *qa519VerdictConn) Close() error { return nil }

func qa519VerdictLease(t *testing.T) *Lease {
	t.Helper()
	config := qa519CompileRule(t, qa519UDPRules(qa519FakeMarker("LB01"), 3, ""), "")
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { engine.Close() })
	lease, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportUDP,
		Source: netip.MustParseAddrPort("192.0.2.10:40000"), Destination: netip.MustParseAddrPort("198.51.100.7:443")})
	if err != nil {
		t.Fatal(err)
	}
	return lease
}

func TestQA519LinuxVerdictFailureIsPreserved(t *testing.T) {
	lease := qa519VerdictLease(t)
	conn := &qa519VerdictConn{}
	capture := &linuxCapture{nl: conn, lease: lease}

	capture.sendVerdict(1, []byte{0, 0, 0, 1}, VerdictPass, "", nil)
	if len(conn.sent) != 1 {
		t.Fatalf("successful verdicts sent = %d, want 1", len(conn.sent))
	}
	if err := lease.Err(); err != nil {
		t.Fatalf("a delivered verdict must not be reported as a failure: %v", err)
	}

	conn.sendErr = errors.New("netlink send failed")
	capture.sendVerdict(1, []byte{0, 0, 0, 2}, VerdictDrop, "", nil)
	err := lease.Err()
	if err == nil {
		t.Fatal("a failed native verdict must be preserved in the lease diagnostic")
	}
	if !strings.Contains(err.Error(), "send NFQUEUE verdict") {
		t.Fatalf("diagnostic = %q, want the native verdict send context", err)
	}

	// The original is not retried: the next verdict is a new record's own
	// disposition, and the recorded failure survives it.
	conn.sendErr = nil
	capture.sendVerdict(1, []byte{0, 0, 0, 3}, VerdictPass, "", nil)
	if len(conn.sent) != 2 {
		t.Fatalf("successful verdicts sent = %d, want 2", len(conn.sent))
	}
	if err = lease.Err(); err == nil {
		t.Fatal("the recorded native failure must stay visible")
	}
}

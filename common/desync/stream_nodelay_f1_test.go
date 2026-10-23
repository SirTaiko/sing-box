package desync

// F1 regression: Go's net package re-enables TCP_NODELAY after a successful
// dial, so the preconnect `skip_nodelay` value must be re-asserted on the
// connected socket for every attached Go TCP entrypoint. These are behavioural
// tests over the wrapper seam (the production entrypoint is verified by the
// compile-time assertion that *net.TCPConn implements streamNoDelayConn in
// stream_native.go); no socket, network or privilege is involved.

import (
	"errors"
	"net"
	"testing"

	"github.com/sagernet/sing-box/option"
)

type noDelayConn struct {
	*fakeConn
	calls []bool
	err   error
}

func (c *noDelayConn) SetNoDelay(enabled bool) error {
	c.calls = append(c.calls, enabled)
	return c.err
}

func skipNoDelayRule() option.DirectDesyncStreamRule {
	return option.DirectDesyncStreamRule{SkipNoDelay: true}
}

func TestSkipNoDelayReassertedAfterConnect(t *testing.T) {
	config := mustCompileStream(t, skipNoDelayRule())
	conn := &noDelayConn{fakeConn: newFakeConn()}
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	if wrapped == nil {
		t.Fatal("skip_nodelay wrapper was not created")
	}
	if len(conn.calls) != 1 || conn.calls[0] {
		t.Fatalf("SetNoDelay calls = %v, want exactly [false]", conn.calls)
	}
	if conn.closed {
		t.Fatal("the connection must stay open after a successful re-assert")
	}
}

func TestSkipNoDelayAbsentLeavesSocketOptionAlone(t *testing.T) {
	rule := option.DirectDesyncStreamRule{
		Name:     "split-only",
		Methods:  []string{"split"},
		Split:    &option.DirectDesyncStreamSplit{SplitPos: []string{"2"}},
		Cutoff:   "",
		Start:    "",
		Disabled: false,
	}
	config := mustCompileStream(t, rule)
	conn := &noDelayConn{fakeConn: newFakeConn()}
	if wrapped := wrapStream(t, config, conn, MatchFacts{}); wrapped == nil {
		t.Fatal("wrapper was not created")
	}
	if len(conn.calls) != 0 {
		t.Fatalf("SetNoDelay calls = %v, want none when skip_nodelay is absent", conn.calls)
	}
}

func TestSkipNoDelayFailureIsTerminal(t *testing.T) {
	config := mustCompileStream(t, skipNoDelayRule())
	conn := &noDelayConn{fakeConn: newFakeConn(), err: errors.New("setsockopt failed")}
	wrapped, err := config.WrapConn(t.Context(), conn, MatchFacts{})
	if err == nil {
		t.Fatal("a failed TCP_NODELAY re-assert must fail the attach")
	}
	if wrapped != nil {
		t.Fatal("no connection may be returned when skip_nodelay cannot be applied")
	}
	if !conn.closed {
		t.Fatal("the failed connection must be closed exactly once")
	}
}

func TestSkipNoDelayUnsupportedConnectionFails(t *testing.T) {
	config := mustCompileStream(t, skipNoDelayRule())
	conn := newFakeConn()
	wrapped, err := config.WrapConn(t.Context(), conn, MatchFacts{})
	if err == nil {
		t.Fatal("skip_nodelay on a connection without TCP_NODELAY must be an error")
	}
	if wrapped != nil {
		t.Fatal("no connection may be returned")
	}
	if !conn.closed {
		t.Fatal("the rejected connection must be closed")
	}
}

// The production Go dialer returns *net.TCPConn for every attached TCP entry
// point; the assertion above (streamNoDelayConn) is only meaningful if that
// type really provides the method.
func TestGoTCPConnProvidesNoDelaySetter(t *testing.T) {
	var conn net.Conn = &net.TCPConn{}
	if _, ok := conn.(streamNoDelayConn); !ok {
		t.Fatal("*net.TCPConn must implement streamNoDelayConn")
	}
}
